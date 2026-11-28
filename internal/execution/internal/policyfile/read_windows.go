package policyfile

import (
	"errors"
	"os"
	"syscall"
)

func Read(path string, limit int64) ([]byte, error) {
	// Open the final reparse point itself, then check the same handle that
	// will supply the bytes. A path-based stat cannot enforce this rule.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errors.New("policy file could not be opened safely")
	}
	defer file.Close()
	handle := syscall.Handle(file.Fd())
	kind, err := syscall.GetFileType(handle)
	if err != nil || kind != syscall.FILE_TYPE_DISK {
		return nil, errors.New("policy file is not a bounded regular file")
	}
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil ||
		info.FileAttributes&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		uint64(info.FileSizeHigh)<<32|uint64(info.FileSizeLow) > uint64(limit) {
		return nil, errors.New("policy file is not a bounded regular file")
	}
	return readBounded(file, limit)
}
