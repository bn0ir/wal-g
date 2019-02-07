package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"github.com/wal-g/wal-g/internal/tracelog"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

type GpgKeyExportError struct {
	error
}

func NewGpgKeyExportError(text string) GpgKeyExportError {
	return GpgKeyExportError{errors.Errorf("Got error while exporting gpg key: '%s'", text)}
}

func (err GpgKeyExportError) Error() string {
	return fmt.Sprintf(tracelog.GetErrorFormatter(), err.error)
}

// GetKeyRingId extracts name of a key to use from env variable
func GetKeyRingId() string {
	return getSettingValue("WALE_GPG_KEY_ID")
}

// GetGpgBinPath searching for gpg or gpg2 utils and returning binary location
func GetGpgBinPath() string {
	gpgBinPath := getSettingValue("GPG_BIN_PATH")
	if gpgBinPath != "" {
		return gpgBinPath
	}

	shellPaths := strings.Split(getSettingValue("PATH"), ":")
	for _, binPath := range shellPaths {
		gpgPathList := []string{"gpg", "gpg2"}
		for _, gpgPath := range gpgPathList {
			if _, err := os.Stat(strings.TrimRight(binPath, "/") + "/" + gpgPath); !os.IsNotExist(err) {
				gpgBinPath = strings.TrimRight(binPath, "/") + "/" + gpgPath
				break
			}
		}
	}

	if gpgBinPath == "" {
		tracelog.ErrorLogger.Printf(tracelog.GetErrorFormatter(), "Trying to use encryption, but GPG binary not found")
	}

	return gpgBinPath
}

// GetGpgBinVersion get version of given gpg binary
func GetGpgBinVersion(gpgBin string) string {
	out, err := exec.Command(gpgBin, "--version").Output()
	if err != nil {
		tracelog.ErrorLogger.Printf(tracelog.GetErrorFormatter(), "Can't get GPG version")
		tracelog.ErrorLogger.Printf(tracelog.GetErrorFormatter(), err)
		return ""
	}

	gpgBinVersion := ""
	gpgText := strings.Split(string(out), "\n")
	for _, gpgLine := range gpgText {
		if len(gpgLine) > 12 && gpgLine[:12] == "gpg (GnuPG) " {
			gpgBinVersion = gpgLine[12:]
			break
		}
	}

	if gpgBinVersion == "" {
		tracelog.ErrorLogger.Printf(tracelog.GetErrorFormatter(), "Can't get GPG version")
		tracelog.ErrorLogger.Printf(tracelog.GetErrorFormatter(), out)
	}

	return gpgBinVersion
}

var GpgBin = GetGpgBinPath()
var GpgBinVersion = GetGpgBinVersion(GpgBin)

// CachedKey is the data transfer object describing format of key ring cache
type CachedKey struct {
	KeyId string `json:"keyId"`
	Body  []byte `json:"body"`
}

// TODO : unit tests
// Here we read armoured version of Key by calling GPG process
func getPubRingArmour(keyId string) ([]byte, error) {
	var cache CachedKey
	var cacheFilename string

	usr, err := user.Current()
	if err == nil {
		cacheFilename = filepath.Join(usr.HomeDir, ".walg_key_cache")
		file, err := ioutil.ReadFile(cacheFilename)
		// here we ignore whatever error can occur
		if err == nil {
			json.Unmarshal(file, &cache)
			if cache.KeyId == keyId && len(cache.Body) > 0 { // don't return an empty cached value
				return cache.Body, nil
			}
		}
	}

	tracelog.InfoLogger.Printf("GPG: %v", GpgBin)
	tracelog.InfoLogger.Printf("GPG version: %v", GpgBinVersion)
	cmd := exec.Command(GpgBin, "-a", "--export", keyId)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if stderr.Len() > 0 { // gpg -a --export <key-id> reports error on stderr and exits == 0 if the key isn't found
		return nil, NewGpgKeyExportError(strings.TrimSpace(stderr.String()))
	}

	cache.KeyId = keyId
	cache.Body = out
	marshal, err := json.Marshal(&cache)
	if err == nil && len(cacheFilename) > 0 {
		ioutil.WriteFile(cacheFilename, marshal, 0644)
	}

	return out, nil
}

func getSecretRingArmour(keyId string) ([]byte, error) {
	out, err := exec.Command(GpgBin, "-a", "--export-secret-key", keyId).Output()
	if err != nil {
		return nil, err
	}
	return out, nil
}
