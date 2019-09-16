package envflag

import (
	"flag"
	"os"
	"testing"
)

func TestEnvFlag(t *testing.T) {
	oriCmdline := flag.CommandLine
	defer func() { flag.CommandLine = oriCmdline }()

	os.Setenv("TEST_ENV_STRING", "test2")
	defer os.Setenv("TEST_ENV_STRING", "")
	os.Setenv("TEST_ENV_BOOL", "true")
	defer os.Setenv("TEST_ENV_BOOL", "")
	os.Setenv("TEST_ENV_INT", "2")
	defer os.Setenv("TEST_ENV_INT", "")

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.PanicOnError)

	s := String("string", "TEST_ENV_STRING", "test", "string")
	b := Bool("bool", "TEST_ENV_BOOL", false, "bool")
	i := Int("int", "TEST_ENV_INT", 1, "int")

	err := flag.CommandLine.Parse([]string{})
	if err != nil {
		t.Fatal(err)
	}

	if *s != "test2" {
		t.Error()
	}
	if *b != true {
		t.Error()
	}
	if *i != 2 {
		t.Error()
	}

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.PanicOnError)

	// flag override env

	s = String("string", "TEST_ENV_STRING", "test", "string")
	b = Bool("bool", "TEST_ENV_BOOL", false, "bool")
	i = Int("int", "TEST_ENV_INT", 1, "int")

	err = flag.CommandLine.Parse([]string{"-string", "test3", "-bool=false", "-int", "3"})
	if err != nil {
		t.Fatal(err)
	}

	if *s != "test3" {
		t.Error()
	}
	if *b != false {
		t.Error()
	}
	if *i != 3 {
		t.Error()
	}
}
