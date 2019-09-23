package env

import (
	"os"
	"testing"
)

func TestEnv(t *testing.T) {
	if v := String("TEST_ENV_STRING", "test1"); v != "test1" {
		t.Errorf("get %s, want %s", v, "test1")
	}
	if v := Bool("TEST_ENV_BOOL", true); v != true {
		t.Errorf("get %v, want %v", v, true)
	}
	if v := Int("TEST_ENV_INT", 1); v != 1 {
		t.Errorf("get %d, want %d", v, 1)
	}

	os.Setenv("TEST_ENV_STRING", "test2")
	defer os.Setenv("TEST_ENV_STRING", "")
	os.Setenv("TEST_ENV_BOOL", "true")
	defer os.Setenv("TEST_ENV_BOOL", "")
	os.Setenv("TEST_ENV_INT", "2")
	defer os.Setenv("TEST_ENV_INT", "")

	if v := String("TEST_ENV_STRING", "test1"); v != "test2" {
		t.Errorf("get %s, want %s", v, "test1")
	}
	if v := Bool("TEST_ENV_BOOL", false); v != true {
		t.Errorf("get %v, want %v", v, true)
	}
	if v := Int("TEST_ENV_INT", 1); v != 2 {
		t.Errorf("get %d, want %d", v, 2)
	}
}
