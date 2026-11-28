package cli

import (
	"errors"
	"os"
	"syscall"
)

func openOfflineInput(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	handle := syscall.Handle(file.Fd())
	kind, err := syscall.GetFileType(handle)
	var info syscall.ByHandleFileInformation
	if err != nil || kind != syscall.FILE_TYPE_DISK || syscall.GetFileInformationByHandle(handle, &info) != nil ||
		info.FileAttributes&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		file.Close()
		return nil, errOfflineInput
	}
	return file, nil
}

func ordinaryOfflineDirectory(info os.FileInfo) bool {
	attrs, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && info.IsDir() && attrs.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

func offlineNameTooLong(err error) bool {
	const errorFilenameExcedRange = syscall.Errno(206) // ERROR_FILENAME_EXCED_RANGE
	return errors.Is(err, errorFilenameExcedRange) || errors.Is(err, syscall.ENAMETOOLONG)
}
