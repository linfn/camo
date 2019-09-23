package env

import (
	"os"
	"strconv"
)

// String ...
func String(name string, value string) string {
	env := os.Getenv(name)
	if env != "" {
		return env
	}
	return value
}

// Bool ...
func Bool(name string, value bool) bool {
	env := os.Getenv(name)
	if env == "true" || env == "1" {
		return true
	} else if env == "false" || env == "0" {
		return false
	}
	return value
}

// Int ...
func Int(name string, value int) int {
	env := os.Getenv(name)
	if env != "" {
		if i, err := strconv.Atoi(env); err == nil {
			return i
		}
	}
	return value
}
