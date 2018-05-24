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
			return
		}

		logrus.WithFields(logrus.Fields{
			"repo": fmt.Sprintf("%s/%s", owner, repo),
		}).Infof("contact: @%s", line)
	}
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
