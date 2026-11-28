//go:build linux || darwin

package cli

import (
	"os"
	"syscall"
)

func openDiscoveryInput(path string) (*os.File, error) {
	// A file replaced with a FIFO after Stat must not block the CLI.
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func openExistingDraft(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
