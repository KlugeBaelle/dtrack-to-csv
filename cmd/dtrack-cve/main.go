// Command dtrack-cve reports whether CVEs affect and are patched in Dependency-Track.
package main

import (
	"os"

	"github.com/sirupsen/logrus"

	"github.com/KlugeBaelle/dtrack-to-csv/internal/cli"
)

func main() {
	err := cli.NewRootCommand().Execute()
	if err != nil {
		logrus.Error(err)
		os.Exit(1)
	}
}
