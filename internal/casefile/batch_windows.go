package casefile

import (
	"os"
	"syscall"
)

const caseOpenFlags = os.O_RDONLY | syscall.FILE_FLAG_OPEN_REPARSE_POINT

func supportedCaseEntry(info os.FileInfo) bool {
	attrs, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && attrs.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT == 0 &&
		(info.IsDir() || info.Mode().IsRegular())
}

// os.FileInfo exposes LastWriteTime on Windows, which sameInfo checks.
func sameChangeTime(os.FileInfo, os.FileInfo) bool { return true }
