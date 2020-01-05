package cmd

import (
	"log"
	"os"
	"path"
	"strings"

	"github.com/linfn/camo/pkg/camo"
)

type Command interface {
	Name() string
	Desc() string
	Usage()
	Run(args ...string)
}

var camoDir = getCamoDir()

func getCamoDir() string {
	dir, err := os.UserCacheDir()
	if err == nil {
		return path.Join(dir, "camo")
	}
	return ".camo"
}

var defaultCertDir = path.Join(camoDir, "certs")

func newLogger(logLevel string) camo.Logger {
	level, ok := camo.LogLevelValues[strings.ToUpper(logLevel)]
	if !ok {
		log.Fatal("invalid log level")
	}
	return camo.NewLogger(log.New(os.Stderr, "", log.LstdFlags|log.Lshortfile), level)
}

// hidden the password to expvar and pprof package
func hiddenPasswordArg() {
	for i, a := range os.Args {
		if a == "-password" || a == "--password" {
			if len(os.Args) > i+1 {
				os.Args[i+1] = "*"
			}
		} else {
			if strings.HasPrefix(a, "-password=") {
				os.Args[i] = "-password=*"
			} else if strings.HasPrefix(a, "--password=") {
				os.Args[i] = "--password=*"
			}
		}
	}
}
