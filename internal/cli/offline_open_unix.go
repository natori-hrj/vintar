//go:build linux || darwin

package cli

import (
	"errors"
	"os"
	"syscall"
)

func openOfflineInput(path string) (*os.File, error) {
	return openDiscoveryInput(path)
}

func ordinaryOfflineDirectory(info os.FileInfo) bool { return info.IsDir() }

func offlineNameTooLong(err error) bool { return errors.Is(err, syscall.ENAMETOOLONG) }
