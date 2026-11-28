//go:build !linux && !darwin

package cli

import "os"

func openDiscoveryInput(path string) (*os.File, error) {
	return os.Open(path)
}

func openExistingDraft(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
