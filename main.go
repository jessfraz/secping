package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/oauth2"

	"github.com/genuinetools/pkg/cli"
	"github.com/google/go-github/github"
	"github.com/jessfraz/secping/version"
	"github.com/sirupsen/logrus"
)

type multiString struct {
	set   bool
	parts []string
}

func (ms *multiString) Set(s string) error {
	if !ms.set {
		ms.set = true
		ms.parts = nil
	}
	ms.parts = append(ms.parts, s)
	return nil
}

func (ms *multiString) String() string {
	return strings.Join(ms.parts, ", ")
}

const defaultBranch = "master"

var (
	token string

	debug   bool
	confirm bool

	skipEmails    bool
	skipOpen      bool
	skipClose     bool
	assignDays    int
	assignees     int
	bump          int
	skipAssignees = multiString{
		parts: []string{"k8s-ci-robot", "k8s-merge-robot", "k8s-bot"},
	}
	skipRepos = multiString{
		parts: []string{
			"kubernetes/kubernetes-template-project",
		},
	}

	// This list of organizations comes from:
	// https://git.k8s.io/community/github-management#actively-used-github-organizations
	orgs = multiString{
		// TODO: Drop unused orgs
		parts: []string{
			"kubernetes",
			"kubernetes-client",
			"kubernetes-csi",
			"kubernetes-incubator",
			//"kubernetes-retired", // maybe just ignore this one
			"kubernetes-sig-testing",
			"kubernetes-sigs",
		},
	}

	issueTitle = "Create a SECURITY_CONTACTS file."
	issueBody  = `As per the email sent to kubernetes-dev[1], please create a SECURITY_CONTACTS
file.

The template for the file can be found in the kubernetes-template repository[2].
A description for the file is in the steering-committee docs[3], you might need
to search that page for "Security Contacts".

Please feel free to ping me on the PR when you make it, otherwise I will see when
you close this issue. :)

Thanks so much, let me know if you have any questions.

(This issue was generated from a tool, apologies for any weirdness.)

[1] https://groups.google.com/forum/#!topic/kubernetes-dev/codeiIoQ6QE
[2] https://git.k8s.io/kubernetes-template-project/SECURITY_CONTACTS
[3] https://github.com/kubernetes/community/blob/c9b921c9f3281c48749a49b02085444f5450dad0/committee-steering/governance/sig-governance-template-short.md
`
)

func main() {
	// Create a new cli program.
	p := cli.NewProgram()
	p.Name = "secping"
	p.Description = "A tool for reading the SECURITY_CONTACTS file in a kubernetes repository"

	// Set the GitCommit and Version.
	p.GitCommit = version.GITCOMMIT
	p.Version = version.VERSION

	// Setup the global flags.
	p.FlagSet = flag.NewFlagSet("global", flag.ExitOnError)
	var tokenPath string
	p.FlagSet.StringVar(&tokenPath, "token-path", "", "/path/to/github-token")
	p.FlagSet.StringVar(&token, "token", os.Getenv("GITHUB_TOKEN"), "Value of github token ($GITHUB_TOKEN by default)")

	p.FlagSet.BoolVar(&confirm, "confirm", false, "Actually create/edit/etc issues when set.")
	p.FlagSet.BoolVar(&debug, "d", false, "enable debug logging")
	p.FlagSet.BoolVar(&skipEmails, "skip-emails", false, "do not log contact emails for each repo when set")
	p.FlagSet.BoolVar(&skipOpen, "skip-open", false, "do not open new issues when set")
	p.FlagSet.BoolVar(&skipClose, "skip-close", false, "do not attempt to close issues when set")
	p.FlagSet.IntVar(&assignDays, "assign-days", 10, "assign issues more than this many days old (0 to disable)")
	p.FlagSet.IntVar(&assignees, "assignees", 5, "ensure at least this many people are assigned (will attempt to assign twice as many if unmet).")
	p.FlagSet.IntVar(&bump, "bump", 7, "bump the issue with a new comment if it hasn't been updated in this many days (0 to disable)")
	p.FlagSet.Var(&skipAssignees, "skip-assignee", "Do not assign this person (repeatable)")
	p.FlagSet.Var(&skipRepos, "skip-repo", "Do not check this repo when listing org repos (repeatable)")
	p.FlagSet.Var(&orgs, "org", "Check all repos in this org (repeatable) (skipped if repos are passed in)")

	// Set the before function.
	p.Before = func(ctx context.Context) error {
		// Set the log level.
		if debug {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if tokenPath == "" && token == "" {
			return errors.New("must set --token or --token-path")
		}
		if tokenPath != "" {
			buf, err := ioutil.ReadFile(tokenPath)
			if err != nil {
				return fmt.Errorf("failed to read --token-path=%q: %v", tokenPath, err)
			}
			token = string(buf)
		}
		token = strings.TrimSpace(token)

		return nil
	}

	// Set the main program action.
	p.Action = func(ctx context.Context, repos []string) error {
		// On ^C, or SIGTERM handle exit.
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		signal.Notify(c, syscall.SIGTERM)
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		go func() {
			for sig := range c {
				logrus.Infof("Received %s, exiting.", sig.String())
				cancel()
				os.Exit(0)
			}
		}()

		// Create the http client.
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{
				AccessToken: token,
				TokenType:   "token",
			},
		)
		tc := oauth2.NewClient(ctx, ts)

		// Create the github client.
		client := github.NewClient(tc)

		user, _, err := client.Users.Get(ctx, "") // authenticated user
		if err != nil {
			logrus.WithError(err).Fatal("could not get authenticated user")
		}
		logrus.Info("Acting as ", *user.Login)

		// If the user passed a repo or repos, just get the contacts for those.
		for _, repo := range repos {
			// Parse git repo for username and repo name.
			r := strings.SplitN(repo, "/", 2)
			if len(r) < 2 {
				logrus.WithFields(logrus.Fields{
					"repo": repo,
				}).Fatal("Repository name could not be parsed. Try something like: kubernetes/kubernetes")
			}

			repoCtx := repoContext{
				ctx:    ctx,
				client: client,
				owner:  r[0],
				repo:   r[1],
			}
			// Get the security contacts for the repository.
			if err := repoCtx.getSecurityContactsForRepo(); err != nil {
				logrus.WithFields(logrus.Fields{
					"repo": repo,
				}).Fatal(err)
			}
		}

		if len(repos) > 0 {
			// Return early if the user specified specific repositories,
			// as we don't want to also return all of them.
			return nil
		}

		// The user did not pass a specific repo so get all.
		for _, org := range orgs.parts {
			page := 1
			perPage := 100
			if err := getRepositories(ctx, client, page, perPage, org); err != nil {
				logrus.WithFields(logrus.Fields{
					"org": org,
				}).Fatal(err)
			}
		}
		return nil
	}

	// Run our program.
	p.Run()
}

func getRepositories(ctx context.Context, client *github.Client, page, perPage int, org string) error {
	opt := &github.RepositoryListByOrgOptions{
		Type: "sources",
		ListOptions: github.ListOptions{
			Page:    page,
			PerPage: perPage,
		},
	}

	logrus.WithFields(logrus.Fields{
		"org": org,
	}).Info("Listing repos...")
	repos, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
	if err != nil {
		return fmt.Errorf("listing repositories by org failed: %v", err)
	}

	for _, repo := range repos {
		// Skip kubernetes/kubernetes-template-project as it is the template.
		fn := repo.GetFullName()
		var found bool
		for _, sr := range skipRepos.parts {
			if fn == sr {
				found = true
				break
			}
		}
		if found {
			continue
		}

		if repo.Archived != nil && *repo.Archived {
			continue
		}

		r := repoContext{
			ctx:    ctx,
			client: client,
			owner:  repo.GetOwner().GetLogin(),
			repo:   repo.GetName(),
		}
		if err := r.getSecurityContactsForRepo(); err != nil {
			logrus.WithFields(logrus.Fields{
				"repo": repo.GetFullName(),
			}).Error(err)
		}
	}

	// Return early if we are on the last page.
	if page == resp.LastPage || resp.NextPage == 0 {
		return nil
	}

	page = resp.NextPage
	return getRepositories(ctx, client, page, perPage, org)
}

func (r repoContext) createIssue(title, body string) (*github.Issue, error) {
	if !confirm {
		logrus.WithFields(logrus.Fields{
			"repo":  r.owner + "/" + r.repo,
			"title": title,
		}).Info("Pretending to create issue...")
		fakeNum := 1
		open := "open"
		now := time.Now()
		return &github.Issue{
			Number:    &fakeNum,
			CreatedAt: &now,
			UpdatedAt: &now,
			State:     &open,
			HTMLURL:   &open,
		}, nil
	}
	issue, _, err := r.client.Issues.Create(r.ctx, r.owner, r.repo, &github.IssueRequest{
		Title: &title,
		Body:  &body,
	})
	return issue, err
}

type repoContext struct {
	ctx    context.Context
	client *github.Client
	owner  string
	repo   string
}

func (r repoContext) linkNewIssue(issue *github.Issue, prev int) error {
	if prev == 0 {
		return nil
	}
	logrus.WithFields(logrus.Fields{
		"previous": prev,
		"issue":    issue.GetHTMLURL(),
	}).Info("Linking new issue to previous...")
	msg := fmt.Sprintf("Required SECURITY_CONTACTS file still does not exist in the repo. See #%d for more info.", *issue.Number)
	return r.createComment(prev, msg)
}

func (r repoContext) ensureOpen(issue *github.Issue) (int, *github.Issue, error) {
	var prev int

	log := logrus.WithFields(logrus.Fields{
		"repo": r.owner + "/" + r.repo,
	})
	if issue != nil && issue.GetState() != "open" { // there's a closed issue
		log.WithFields(logrus.Fields{
			"old":   issue.GetHTMLURL(),
			"state": issue.GetState(),
		}).Info("not open, creating new issue")
		prev = *issue.Number // note for later
		issue = nil          // create a new one
	}

	if !skipOpen && issue == nil {
		// The issue does not already exist. Create the issue in the
		// repository that they need to add a SECURITY_CONTACTS file.
		log.Info("Creating new issue...")
		var err error
		if issue, err = r.createIssue(issueTitle, issueBody); err != nil {
			return 0, nil, fmt.Errorf("creating issue failed: %v", err)
		}
	}
	return prev, issue, nil
}

func (r repoContext) bumpIssue(issue *github.Issue) error {
	if bump <= 0 {
		return nil
	}
	if issue.UpdatedAt.Add(time.Duration(bump) * 24 * time.Hour).After(time.Now()) {
		return nil
	}

	logrus.WithFields(logrus.Fields{
		"updated": *issue.UpdatedAt,
		"repo":    fmt.Sprintf("%s/%s", r.owner, r.repo),
	}).Info("Bumping stale issue...")
	msg := "Required SECURITY_CONTACTS file still does not exist. Please resolve as soon as possible."
	return r.createComment(*issue.Number, msg)
}

func (r repoContext) getSecurityContactsForRepo() error {
	// Get the issue on the repository stating that they need to add a
	// SECURITY_CONTACTS file. This will be checked regardless of if the file
	// exists or not. If the file does not exist, we need this to know if we need
	// to open a new issue. If it does exist, we need this to make sure the
	// issue was closed and cleaned up.
	log := logrus.WithFields(logrus.Fields{
		"repo": fmt.Sprintf("%s/%s", r.owner, r.repo),
	})
	log.Debug("Checking...")
	issue, err := r.getIssue()
	if err != nil {
		return fmt.Errorf("getting issue failed: %v", err)
	}

	// Get the file contents for SECURITY_CONTACTS.
	content, _, _, err := r.client.Repositories.GetContents(r.ctx, r.owner, r.repo, "SECURITY_CONTACTS", &github.RepositoryContentGetOptions{Ref: defaultBranch})
	if err != nil && !strings.Contains(err.Error(), "404") {
		// Return the error early here if it is not a "Not Found" error.
		return fmt.Errorf("getting SECURITY_CONTACTS file failed: %v", err)
	}
	if err != nil {
		// The file was not found. We need to check if we already have an existing
		// issue on the repository opened, and if not create a new issue.
		prev, issue, err := r.ensureOpen(issue)
		if err != nil {
			return fmt.Errorf("ensureOpen error: %v", err)
		}

		if issue != nil {
			log = log.WithFields(logrus.Fields{
				"issue":   issue.GetHTMLURL(),
				"updated": *issue.UpdatedAt,
			})

			if err = r.linkNewIssue(issue, prev); err != nil {
				return fmt.Errorf("create reopen comment: %v", err)
			}

			if err = r.bumpIssue(issue); err != nil {
				return fmt.Errorf("bump issue: %v", err)
			}

			if err = r.assignIssue(issue); err != nil {
				return fmt.Errorf("assign issue: %v", err)
			}
		}

		log.Warn("SECURITY_CONTACTS missing")
		return nil
	}

	// Get the file contents.
	file, err := content.GetContent()
	if err != nil {
		return fmt.Errorf("getting SECURITY_CONTACTS content failed: %v", err)
	}

	// Clearly we have a SECURITY_CONTACTS file, let's make sure the original
	// issue we opened on the repository is now closed.
	if !skipClose && issue != nil && issue.GetState() == "open" {
		// The issue is still open we should close it.
		log := log.WithFields(logrus.Fields{
			"issue": issue.GetHTMLURL(),
			"state": issue.GetState(),
		})
		log.Warn("Need to close issue")
		msg := "Thank you for creating a SECURITY_CONTACTS file. Please `/close` the issue.\n/close"
		comment, err := r.getComment(*issue.Number, msg)
		if err != nil {
			return fmt.Errorf("checking for close comment: %v", err)
		}
		if comment == nil {
			log.Info("Attempting to close...")

			if err = r.createComment(*issue.Number, msg); err != nil {
				return fmt.Errorf("create close comment: %v", err)
			}
		}
	}

	if skipEmails {
		return nil
	}
	// Iterate over each line.
	scanner := bufio.NewScanner(strings.NewReader(file))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Ignore the comment or empty lines.
		if strings.HasPrefix(line, "#") || len(line) <= 0 {
			continue
		}

		email, err := r.getUserEmail(line)
		if err != nil {
			return fmt.Errorf("getting user %s's email failed: %v", line, err)
		}

		logrus.WithFields(logrus.Fields{
			"repo": fmt.Sprintf("%s/%s", r.owner, r.repo),
		}).Infof("@%s, %s", line, email)
	}

	return nil
}

func (r repoContext) assignIssue(issue *github.Issue) error {
	if assignDays == 0 {
		return nil
	}
	if issue.CreatedAt.Add(time.Duration(assignDays) * 24 * time.Hour).After(time.Now()) {
		return nil
	}
	if len(issue.Assignees) > 0 || assignees == 0 {
		return nil
	}
	logrus.WithFields(logrus.Fields{
		"repo":      fmt.Sprintf("%s/%s", r.owner, r.repo),
		"created":   *issue.CreatedAt,
		"assignees": len(issue.Assignees),
		"issue":     issue.GetHTMLURL(),
	}).Info("Assigning people to issue...")
	var targets []string
	contribs, _, err := r.client.Repositories.ListContributors(r.ctx, r.owner, r.repo, nil)
	if err != nil {
		return fmt.Errorf("list collaborators: %v", err)
	}
	skip := map[string]bool{}
	for _, s := range skipAssignees.parts {
		skip[s] = true
	}
	for _, c := range contribs {
		who := *c.Login
		if who == "" || skip[who] {
			continue
		}
		targets = append(targets, "@"+who)
		if len(targets) >= assignees {
			break
		}
	}

	if len(targets) == 0 {
		return nil
	}

	msg := fmt.Sprintf("%s/%s still needs a SECURITY_CONTACTS file.\n/assign %s", r.owner, r.repo, strings.Join(targets, " "))
	if err = r.createComment(*issue.Number, msg); err != nil {
		return fmt.Errorf("create comment: %v", err)
	}
	return nil
}

func (r repoContext) createComment(num int, msg string) error {
	if !confirm {
		logrus.WithFields(logrus.Fields{
			"repo":    fmt.Sprintf("%s/%s", r.owner, r.repo),
			"number":  num,
			"message": msg,
		}).Info("Pretending to create comment...")
		return nil
	}
	_, _, err := r.client.Issues.CreateComment(r.ctx, r.owner, r.repo, num, &github.IssueComment{
		Body: &msg,
	})
	return err
}

func (r repoContext) getComment(num int, goal string) (*github.IssueComment, error) {
	comments, _, err := r.client.Issues.ListComments(r.ctx, r.owner, r.repo, num, &github.IssueListCommentsOptions{
		Direction: "desc",
	})
	if err != nil {
		return nil, err
	}
	for _, c := range comments {
		if strings.Contains(*c.Body, goal) {
			return c, nil
		}
	}
	return nil, nil
}

// getUserEmail tries to get an email from a github username one of two ways:
// - their public email on github
// - their email used to make commits
func (r repoContext) getUserEmail(user string) (string, error) {
	// First, check if they have a public email on github.
	u, _, err := r.client.Users.Get(r.ctx, user)
	if err != nil {
		return "", fmt.Errorf("getting user %s failed: %v", user, err)
	}

	email := u.GetEmail()
	if len(email) > 0 {
		// Return early because we found an email address.
		return email, nil
	}

	// We did not find a public email so get one of their commits in the
	// repository and find the email through that.
	commits, _, err := r.client.Repositories.ListCommits(r.ctx, r.owner, r.repo, &github.CommitsListOptions{
		Author: user,
	})
	if err != nil {
		return "", fmt.Errorf("getting user %s commits in %s/%s failed: %v", user, r.owner, r.repo, err)
	}
	for _, commit := range commits {
		email = commit.GetCommit().GetAuthor().GetEmail()
		if len(email) > 0 {
			return email, nil
		}
	}

	return email, nil
}

func (r repoContext) getIssue() (*github.Issue, error) {
	for {
		result, resp, err := r.client.Search.Issues(r.ctx, fmt.Sprintf("in:title is:issue repo:%s/%s %q", r.owner, r.repo, issueTitle), &github.SearchOptions{Sort: "updated"})
		if _, ok := err.(*github.RateLimitError); ok {
			wait := time.Until(resp.Rate.Reset.Time) + 1*time.Second
			logrus.Infof("Sleeping for %s...", wait)
			time.Sleep(wait)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("searching issues in %s/%s failed: %v", r.owner, r.repo, err)
		}

		var best *github.Issue

		// Try to match the title to the issue.
		for _, issue := range result.Issues {
			if issue.GetTitle() != issueTitle {
				continue
			}
			if s := issue.State; s != nil && *s == "open" { // try to find an open one
				return &issue, nil
			}
			if best == nil { // otherwise anything matching
				best = &issue
			}
		}

		return best, nil
	}
}
