package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/oauth2"

	"github.com/genuinetools/pepper/version"
	"github.com/google/go-github/github"
	"github.com/sirupsen/logrus"
)

const (
	// BANNER is what is printed for help/info output.
	BANNER = `secping

 A tool for reading the SECURITY_CONTACTS file in a kubernetes repository.
 Version: %s
 Build: %s

`
)

var (
	token string
	repo  string

	debug bool
	vrsn  bool

	// This list of organizations comes from:
	// https://github.com/kubernetes/community/blob/master/org-owners-guide.md#current-organizations-in-use
	orgs = []string{
		"kubernetes",
		"kubernetes-client",
		"kubernetes-csi",
		"kubernetes-incubator",
		"kubernetes-retired", // maybe just ignore this one
		"kubernetes-sig-testing",
		"kubernetes-sigs",
	}
)

func init() {
	// parse flags
	flag.StringVar(&token, "token", os.Getenv("GITHUB_TOKEN"), "GitHub API token (or env var GITHUB_TOKEN)")

	flag.BoolVar(&vrsn, "version", false, "print version and exit")
	flag.BoolVar(&vrsn, "v", false, "print version and exit (shorthand)")
	flag.BoolVar(&debug, "d", false, "run in debug mode")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, fmt.Sprintf(BANNER, version.VERSION, version.GITCOMMIT))
		flag.PrintDefaults()
	}

	flag.Parse()

	if vrsn {
		fmt.Printf("pepper version %s, build %s", version.VERSION, version.GITCOMMIT)
		os.Exit(0)
	}

	// set log level
	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	if token == "" {
		usageAndExit("GitHub token cannot be empty.", 1)
	}

	if flag.NArg() > 0 {
		repo = flag.Arg(0)
	}

}

func main() {
	// On ^C, or SIGTERM handle exit.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		for sig := range c {
			logrus.Infof("Received %s, exiting.", sig.String())
			os.Exit(0)
		}
	}()

	ctx := context.Background()

	// Create the http client.
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	// Create the github client.
	client := github.NewClient(tc)

	// If the user passed a repo, just get the contacts for that repo.
	if len(repo) > 0 {
		// Parse git repo for username and repo name.
		r := strings.SplitN(repo, "/", 2)
		if len(r) < 2 {
			logrus.Fatalf("Repository name %q could not be parsed. Try something like: kubernetes/kubernetes", repo)
		}
		logrus.Infof("Getting SECURITY_CONTACTS for %s/%s...", r[0], r[1])
		getSecurityContactsForRepo(ctx, client, r[0], r[1])
		return
	}

	// The user did not pass a specific repo so get all.
	for _, org := range orgs {
		page := 1
		perPage := 100
		if err := getRepositories(ctx, client, page, perPage, org); err != nil {
			logrus.Fatal(err)
		}
	}
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
		return err
	}

	for _, repo := range repos {
		// Skip kubernetes/kubernetes-template-project as it is the template.
		if repo.GetFullName() == "kubernetes/kubernetes-template-project" {
			continue
		}

		getSecurityContactsForRepo(ctx, client, repo.GetOwner().GetLogin(), repo.GetName())
	}

	// Return early if we are on the last page.
	if page == resp.LastPage || resp.NextPage == 0 {
		return nil
	}

	page = resp.NextPage
	return getRepositories(ctx, client, page, perPage, org)
}

func getSecurityContactsForRepo(ctx context.Context, client *github.Client, owner, repo string) {
	// Get the file contents for SECURITY_CONTACTS.
	content, _, _, err := client.Repositories.GetContents(ctx, owner, repo, "SECURITY_CONTACTS", &github.RepositoryContentGetOptions{Ref: "master"})
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			logrus.WithFields(logrus.Fields{
				"repo": fmt.Sprintf("%s/%s", owner, repo),
			}).Warn("SECURITY_CONTACTS does not exist")

			createIssue(ctx, client, owner, repo)
			return
		}

		logrus.WithFields(logrus.Fields{
			"repo": fmt.Sprintf("%s/%s", owner, repo),
		}).Errorf("getting SECURITY_CONTACTS file failed: %v", err)
		return
	}

	// Get the file contents.
	file, err := content.GetContent()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"repo": fmt.Sprintf("%s/%s", owner, repo),
		}).Errorf("getting SECURITY_CONTACTS content failed: %v", err)
		return
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
			logrus.WithFields(logrus.Fields{
				"repo":    fmt.Sprintf("%s/%s", owner, repo),
				"contact": line,
			}).Warn(err)
		}
		logrus.WithFields(logrus.Fields{
			"repo": fmt.Sprintf("%s/%s", owner, repo),
		}).Infof("@%s, %s", line, email)
	}
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

func createIssue(ctx context.Context, client *github.Client, owner, repo string) error {
	title := "Create a SECURITY_CONTACTS file."
	body := `As per the email sent to kubernetes-dev[1], please create a SECURITY_CONTACTS
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

	// First make sure an open issue doesn't already exist.
	issues, _, err := client.Issues.ListByRepo(ctx, owner, repo, &github.IssueListByRepoOptions{
		Creator: "jessfraz",
	})
	if err != nil {
		return fmt.Errorf("listing issues in %s/%s failed: %v", owner, repo, err)
	}

	// Try to match the title to the issue.
	for _, issue := range issues {
		if issue.GetTitle() == title {
			logrus.WithFields(logrus.Fields{
				"repo": fmt.Sprintf("%s/%s", owner, repo),
			}).Infof("open issue exists: %s", issue.GetHTMLURL())

			return nil
		}
	}

	// Create an issue in the repository that they need to add a SECURITY_CONTACTS file.
	issue, _, err := client.Issues.Create(ctx, owner, repo, &github.IssueRequest{
		Title: &title,
		Body:  &body,
	})
	if err != nil {
		return fmt.Errorf("creating issue in %s/%s failed: %v", owner, repo, err)
	}

	logrus.WithFields(logrus.Fields{
		"repo": fmt.Sprintf("%s/%s", owner, repo),
	}).Infof("opened issue: %s", issue.GetHTMLURL())

	return nil
}

func usageAndExit(message string, exitCode int) {
	if message != "" {
		fmt.Fprintf(os.Stderr, message)
		fmt.Fprintf(os.Stderr, "\n\n")
	}
	flag.Usage()
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(exitCode)
}
