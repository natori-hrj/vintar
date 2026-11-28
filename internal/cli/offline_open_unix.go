//go:build linux || darwin

package cli

import "os"

func openOfflineInput(path string) (*os.File, error) {
	return openDiscoveryInput(path)
}

func ordinaryOfflineDirectory(info os.FileInfo) bool { return info.IsDir() }
