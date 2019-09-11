package envflag

import (
	"flag"
	"os"
	"strconv"
)

// String ...
func String(flagName string, envName string, value string, usage string) *string {
	v := flag.String(flagName, value, usage)
	env := os.Getenv(envName)
	if env != "" {
		*v = env
	}
	return v
}

// Bool ...
func Bool(flagName string, envName string, value bool, usage string) *bool {
	v := flag.Bool(flagName, value, usage)
	env := os.Getenv(envName)
	if env == "true" || env == "1" {
		*v = true
	} else if env == "false" || env == "0" {
		*v = false
	}
	return v
}

// Int ...
func Int(flagName string, envName string, value int, usage string) *int {
	v := flag.Int(flagName, value, usage)
	env := os.Getenv(envName)
	if env != "" {
		i, err := strconv.Atoi(env)
		if err == nil {
			*v = i
		}
	}
	return v
}
