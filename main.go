package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/oauth2"

	"github.com/genuinetools/pkg/cli"
	"github.com/google/go-github/github"
	"github.com/jessfraz/secping/version"
	"github.com/sirupsen/logrus"
)

const (
	// BANNER is what is printed for help/info output.
	BANNER = `secping [OPTIONS] [REPO] [REPO...]

 .
 Version: %s
 Build: %s

`
)

var (
	token string

	debug bool

	// This list of organizations comes from:
	// https://github.com/kubernetes/community/blob/master/org-owners-guide.md#current-organizations-in-use
	orgs = []string{
		"kubernetes",
		"kubernetes-client",
		"kubernetes-csi",
		"kubernetes-incubator",
		//"kubernetes-retired", // maybe just ignore this one
		"kubernetes-sig-testing",
		"kubernetes-sigs",
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
[2] https://github.com/kubernetes/kubernetes-template-project/blob/master/SECURITY_CONTACTS
[3] https://github.com/kubernetes/community/blob/master/committee-steering/governance/sig-governance-template-short.md
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
	p.FlagSet.StringVar(&token, "token", os.Getenv("GITHUB_TOKEN"), "GitHub API token (or env var GITHUB_TOKEN)")

	p.FlagSet.BoolVar(&debug, "d", false, "enable debug logging")

	// Set the before function.
	p.Before = func(ctx context.Context) error {
		// Set the log level.
		if debug {
			logrus.SetLevel(logrus.DebugLevel)
		}

		if token == "" {
			return errors.New("GitHub token cannot be empty")
		}

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
			&oauth2.Token{AccessToken: token},
		)
		tc := oauth2.NewClient(ctx, ts)

		// Create the github client.
		client := github.NewClient(tc)

		// If the user passed a repo or repos, just get the contacts for those.
		for _, repo := range repos {
			// Parse git repo for username and repo name.
			r := strings.SplitN(repo, "/", 2)
			if len(r) < 2 {
				logrus.WithFields(logrus.Fields{
					"repo": repo,
				}).Fatal("Repository name could not be parsed. Try something like: kubernetes/kubernetes")
			}

			// Get the security contacts for the repository.
			if err := getSecurityContactsForRepo(ctx, client, r[0], r[1]); err != nil {
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
		for _, org := range orgs {
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

	repos, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
	if err != nil {
		return fmt.Errorf("listing repositories by org failed: %v", err)
	}

	for _, repo := range repos {
		// Skip kubernetes/kubernetes-template-project as it is the template.
		if repo.GetFullName() == "kubernetes/kubernetes-template-project" {
			continue
		}

		if err := getSecurityContactsForRepo(ctx, client, repo.GetOwner().GetLogin(), repo.GetName()); err != nil {
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

func getSecurityContactsForRepo(ctx context.Context, client *github.Client, owner, repo string) error {
	// Get the issue on the repository stating that they need to add a
	// SECURITY_CONTACTS file. This will be checked regardless of if the file
	// exists or not. If the file does not exist, we need this to know if we need
	// to open a new issue. If it does exist, we need this to make sure the
	// issue was closed and cleaned up.
	issue, err := getIssue(ctx, client, owner, repo)
	if err != nil {
		return fmt.Errorf("getting issue failed: %v", err)
	}

	// Get the file contents for SECURITY_CONTACTS.
	content, _, _, err := client.Repositories.GetContents(ctx, owner, repo, "SECURITY_CONTACTS", &github.RepositoryContentGetOptions{Ref: "master"})
	if err != nil {
		if !strings.Contains(err.Error(), "404") {
			// Return the error early here if it is not a "Not Found" error.
			return fmt.Errorf("getting SECURITY_CONTACTS file failed: %v", err)
		}

		// The file was not found. We need to check if we already have an existing
		// issue on the repository opened, and if not create a new issue.
		if issue != nil {
			// The issue exists. Make sure it is still open.
			if issue.GetState() != "open" {
				logrus.WithFields(logrus.Fields{
					"repo":  fmt.Sprintf("%s/%s", owner, repo),
					"issue": issue.GetHTMLURL(),
					"state": issue.GetState(),
				}).Warn("issue exists, but it's state should be open")
			}
		} else {
			// The issue does not already exist. Create the issue in the
			// repository that they need to add a SECURITY_CONTACTS file.
			issue, _, err = client.Issues.Create(ctx, owner, repo, &github.IssueRequest{
				Title: &issueTitle,
				Body:  &issueBody,
			})
			if err != nil {
				return fmt.Errorf("creating issue failed: %v", err)
			}
		}

		logrus.WithFields(logrus.Fields{
			"repo":  fmt.Sprintf("%s/%s", owner, repo),
			"issue": issue.GetHTMLURL(),
			"state": issue.GetState(),
		}).Warn("SECURITY_CONTACTS does not exist")

		return nil
	}

	// Get the file contents.
	file, err := content.GetContent()
	if err != nil {
		return fmt.Errorf("getting SECURITY_CONTACTS content failed: %v", err)
	}

	// Clearly we have a SECURITY_CONTACTS file, let's make sure the original
	// issue we opened on the repository is now closed.
	if issue != nil && issue.GetState() == "open" {
		// The issue is still open we should close it.
		logrus.WithFields(logrus.Fields{
			"repo":  fmt.Sprintf("%s/%s", owner, repo),
			"issue": issue.GetHTMLURL(),
			"state": issue.GetState(),
		}).Warn("issue state should be closed")
	}

	// Iterate over each line.
	scanner := bufio.NewScanner(strings.NewReader(file))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Ignore the comment or empty lines.
		if strings.HasPrefix(line, "#") || len(line) <= 0 {
			continue
		}

		email, err := getUserEmail(ctx, client, line, owner, repo)
		if err != nil {
			return fmt.Errorf("getting user %s's email failed: %v", line, err)
		}

		logrus.WithFields(logrus.Fields{
			"repo": fmt.Sprintf("%s/%s", owner, repo),
		}).Infof("@%s, %s", line, email)
	}

	return nil
}

// getUserEmail tries to get an email from a github username one of two ways:
// - their public email on github
// - their email used to make commits
func getUserEmail(ctx context.Context, client *github.Client, user, owner, repo string) (string, error) {
	// First, check if they have a public email on github.
	u, _, err := client.Users.Get(ctx, user)
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
	commits, _, err := client.Repositories.ListCommits(ctx, owner, repo, &github.CommitsListOptions{
		Author: user,
	})
	if err != nil {
		return "", fmt.Errorf("getting user %s commits in %s/%s failed: %v", user, owner, repo, err)
	}
	for _, commit := range commits {
		email = commit.GetCommit().GetAuthor().GetEmail()
		if len(email) > 0 {
			return email, nil
		}
	}

	return email, nil
}

func getIssue(ctx context.Context, client *github.Client, owner, repo string) (*github.Issue, error) {
	issues, _, err := client.Issues.ListByRepo(ctx, owner, repo, &github.IssueListByRepoOptions{
		Creator: "jessfraz",
	})
	if err != nil {
		return nil, fmt.Errorf("listing issues in %s/%s failed: %v", owner, repo, err)
	}

	// Try to match the title to the issue.
	for _, issue := range issues {
		if issue.GetTitle() == issueTitle {
			return issue, nil
		}
	}

	return nil, nil
}
