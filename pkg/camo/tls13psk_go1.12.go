// +build go1.12

package camo

import "os"

func init() {
	// force enable tls 1.3 for golang 1.12
	goDebug := os.Getenv("GODEBUG")
	if goDebug == "" {
		goDebug = "tls13=1"
	} else {
		goDebug += ",tls13=1"
	}
	os.Setenv("GODEBUG", goDebug)
}
