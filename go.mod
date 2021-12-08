module github.com/jessfraz/secping

go 1.12

require (
	github.com/genuinetools/pkg v0.0.0-20181022210355-2fcf164d37cb
	github.com/google/go-github v17.0.0+incompatible
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
)

replace github.com/google/go-github => github.com/fejta/go-github v17.0.0+incompatible
