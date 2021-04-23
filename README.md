# secping

[![Travis CI](https://img.shields.io/travis/jessfraz/secping.svg?style=for-the-badge)](https://travis-ci.org/jessfraz/secping)
[![GoDoc](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=for-the-badge)](https://godoc.org/github.com/jessfraz/secping)
[![Github All Releases](https://img.shields.io/github/downloads/jessfraz/secping/total.svg?style=for-the-badge)](https://github.com/jessfraz/secping/releases)

A tool for reading the SECURITY_CONTACTS file in a kubernetes repository.

**Table of Contents**

<!-- toc -->

- [Installation](#installation)
    + [Binaries](#binaries)
    + [Via Go](#via-go)
- [Usage](#usage)

<!-- tocstop -->

## Installation

#### Binaries

For installation instructions from binaries please visit the [Releases Page](https://github.com/jessfraz/secping/releases).

#### Via Go

```console
$ go get github.com/jessfraz/secping
```

## Usage

```console
$ secping -h
secping -  A tool for reading `security_contacts` in an OWNERS file in a kubernetes repository.

Usage: secping <command>

Flags:

  --assign-days    assign issues more than this many days old (0 to disable) (default: 10)
  --assignees      ensure at least this many people are assigned (will attempt to assign twice as many if unmet). (default: 5)
  --bump           bump the issue with a new comment if it hasn't been updated in this many days (0 to disable) (default: 7)
  --confirm        Actually create/edit/etc issues when set. (default: false)
  -d               enable debug logging (default: false)
  --org            Check all repos in this org (repeatable) (skipped if repos are passed in) (default: kubernetes, kubernetes-client, kubernetes-csi, kubernetes-incubator, kubernetes-sig-testing, kubernetes-sigs)
  --skip-assignee  Do not assign this person (repeatable) (default: k8s-ci-robot, k8s-merge-robot, k8s-bot)
  --skip-close     do not attempt to close issues when set (default: false)
  --skip-emails    do not log contact emails for each repo when set (default: false)
  --skip-open      do not open new issues when set (default: false)
  --skip-repo      Do not check this repo when listing org repos (repeatable) (default: kubernetes/kubernetes-template-project)
  --token          Value of github token ($GITHUB_TOKEN by default) (default: <none>)
  --token-path     /path/to/github-token (default: <none>)

Commands:

  version  Show the version information.
```
