package cmd

import "fmt"

type Version struct {
	BuildCommit string
	BuildDate   string
}

func (cmd *Version) Name() string {
	return "version"
}

func (cmd *Version) Desc() string {
	return "Print camo version"
}

func (cmd *Version) Usage() {
	fmt.Printf("Usage: camo version\n")
}

func (cmd *Version) Run(args ...string) {
	if cmd.BuildCommit != "" || cmd.BuildDate != "" {
		fmt.Printf("Build Commit: %s\nBuild Date: %s\n", cmd.BuildCommit, cmd.BuildDate)
	}
}
