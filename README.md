# secping

[![Travis CI](https://img.shields.io/travis/jessfraz/secping.svg?style=for-the-badge)](https://travis-ci.org/jessfraz/secping)
[![GoDoc](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=for-the-badge)](https://godoc.org/github.com/jessfraz/secping)
[![Github All Releases](https://img.shields.io/github/downloads/jessfraz/secping/total.svg?style=for-the-badge)](https://github.com/jessfraz/secping/releases)

A tool for reading the SECURITY_CONTACTS file in a kubernetes repository.

**Table of Contents**

<!-- toc -->

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
secping -  A tool for reading the SECURITY_CONTACTS file in a kubernetes repository.

Usage: secping <command>

Flags:

  -d       enable debug logging (default: false)
  --token  GitHub API token (or env var GITHUB_TOKEN) (default: <none>)

Commands:

  version  Show the version information.``
```
