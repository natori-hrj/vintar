//go:build linux || darwin

// Package policyfile reads trusted policy input without following a final link.
package policyfile

import (
	"errors"
	"io"
	"os"
	"syscall"
)

func Read(path string, limit int64) ([]byte, error) {
	// Nonblocking avoids hanging on a FIFO before checking file type.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("policy file could not be opened safely")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("policy file is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("policy file could not be read within its limit")
	}
	return data, nil
}
