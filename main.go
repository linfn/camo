package main // import "github.com/linfn/camo"

import (
	"fmt"
	"os"

	"github.com/linfn/camo/pkg/cmd"
)

var (
	buildCommit string
	buildDate   string
)

var help cmd.Help

var commands = []cmd.Command{
	&cmd.Client{},
	&cmd.Server{},
	&cmd.Version{
		BuildCommit: buildCommit,
		BuildDate:   buildDate,
	},
	&help,
}

func getCommand(name string) (cmd.Command, bool) {
	for _, c := range commands {
		if c.Name() == name {
			return c, true
		}
	}
	return nil, false
}

func init() {
	help.Commands = commands
}

func main() {
	if len(os.Args) < 2 {
		help, _ := getCommand("help")
		help.Run()
		return
	}

	cmd, ok := getCommand(os.Args[1])
	if !ok {
		fmt.Fprintln(os.Stderr, "unknow command")
		os.Exit(1)
	}

	cmd.Run(os.Args[2:]...)
}
