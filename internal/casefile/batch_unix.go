//go:build linux || darwin

package casefile

import (
	"os"
	"syscall"
)

// A file replaced by a FIFO between Lstat and open must not block.
const caseOpenFlags = os.O_RDONLY | syscall.O_NONBLOCK

func supportedCaseEntry(info os.FileInfo) bool {
	return info.IsDir() || info.Mode().IsRegular()
}
