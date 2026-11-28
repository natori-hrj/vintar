package cli

import (
	"os"
	"syscall"
	"unsafe"
)

func windowsCompletionShell() string {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(snapshot)
	entries := make(map[uint32]syscall.ProcessEntry32)
	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err := syscall.Process32First(snapshot, &entry); err == nil; err = syscall.Process32Next(snapshot, &entry) {
		entries[entry.ProcessID] = entry
	}
	pid := uint32(os.Getpid())
	for depth := 0; pid != 0 && depth < 10; depth++ {
		entry := entries[pid]
		if name := shellName(syscall.UTF16ToString(entry.ExeFile[:])); name != "" {
			return name
		}
		pid = entry.ParentProcessID
	}
	return ""
}
