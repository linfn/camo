package camo

import (
	"fmt"
	"os/exec"
)

func runCmd(name string, arg ...string) error {
	err := exec.Command(name, arg...).Run()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok && len(e.Stderr) > 0 {
			return fmt.Errorf("%v: %s", e, string(e.Stderr))
		}
	}
	return err
}

func runCmdOutput(name string, arg ...string) ([]byte, error) {
	out, err := exec.Command(name, arg...).Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok && len(e.Stderr) > 0 {
			return out, fmt.Errorf("%v: %s", e, string(e.Stderr))
		}
	}
	return out, err
}
