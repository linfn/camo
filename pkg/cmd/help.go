package cmd

import (
	"fmt"
)

type Help struct {
	Commands []Command
}

func (cmd *Help) Name() string {
	return "help"
}

func (cmd *Help) Desc() string {
	return "Help about any command"
}

func (cmd *Help) Usage() {
	fmt.Printf("Usage: camo help <command>\n")
}

func (cmd *Help) Run(args ...string) {
	if len(args) == 2 {
		for _, c := range cmd.Commands {
			if c.Name() == args[1] {
				c.Usage()
				return
			}
		}
	}
	cmd.printAllCommands()
}

func (cmd *Help) printAllCommands() {
	fmt.Printf("Camo is a VPN using HTTP/2 over TLS.\n\n")
	fmt.Printf("Usage: camo <command> [arguments]\n\n")
	fmt.Printf("The commands are:\n\n")
	for _, cmd := range cmd.Commands {
		fmt.Printf("\t%s\t%s\n", cmd.Name(), cmd.Desc())
	}
	fmt.Printf("\nUse \"camo help <command>\" for more information about a command.\n\n")
}
