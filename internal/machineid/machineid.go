package machineid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/denisbrodbeck/machineid"
)

// MachineID ...
func MachineID(fallbackStoreDir string) (string, error) {
	id, err := machineid.ID()
	if err == nil {
		return id, nil
	}

	err = os.MkdirAll(fallbackStoreDir, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("machineid: failed to mkdir: %v", err)
	}

	machineIDFile := path.Join(fallbackStoreDir, "machine-id")

	b, err := ioutil.ReadFile(machineIDFile)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("machineid: failed to read machineid from file: %s, error: %v", machineIDFile, err)
	}
	if len(b) == 0 {
		b = make([]byte, 32)
		if _, err = rand.Read(b); err != nil {
			return "", fmt.Errorf("machineid: failed to generate rand: %v", err)
		}
		b = []byte(hex.EncodeToString(b))
		err = ioutil.WriteFile(machineIDFile, b, os.ModePerm)
		if err != nil {
			return "", fmt.Errorf("machineid: failed to save machineid file: %s, error: %v", machineIDFile, err)
		}
	}
	return string(b), nil
}
