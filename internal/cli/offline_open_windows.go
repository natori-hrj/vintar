package cli

import (
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
