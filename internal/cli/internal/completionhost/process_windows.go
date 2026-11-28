package completionhost

import (
	"context"
	"reflect"
	"syscall"
)

func processLookup(ctx context.Context) func(int) process {
	parents := make(map[int]process)
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err == nil {
		defer syscall.CloseHandle(snapshot)
		var entry syscall.ProcessEntry32
		entry.Size = uint32(reflect.TypeFor[syscall.ProcessEntry32]().Size())
		for err := syscall.Process32First(snapshot, &entry); err == nil && ctx.Err() == nil; err = syscall.Process32Next(snapshot, &entry) {
			parents[int(entry.ProcessID)] = process{syscall.UTF16ToString(entry.ExeFile[:]), int(entry.ParentProcessID)}
		}
	}
	return func(pid int) process { return parents[pid] }
}
