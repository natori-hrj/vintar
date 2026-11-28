//go:build !linux && !darwin && !windows

package cli

import "os"

func openOfflineInput(string) (*os.File, error) {
	return nil, errOfflineInput
}

func ordinaryOfflineDirectory(os.FileInfo) bool { return false }
