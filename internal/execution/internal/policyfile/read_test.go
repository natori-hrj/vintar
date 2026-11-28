//go:build linux || darwin || windows

package policyfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestReadBoundedRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := Read(path, 2); err != nil || string(data) != "{}" {
		t.Fatalf("reading a regular file at the limit: %q, %v", data, err)
	}
	for _, invalid := range []string{path, dir, filepath.Join(dir, "missing.json")} {
		if data, err := Read(invalid, 1); err == nil || data != nil {
			t.Fatal("returned data from an oversized or non-regular input")
		}
	}
}

func TestReadRejectsFinalSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		const errorPrivilegeNotHeld = syscall.Errno(1314)
		if runtime.GOOS == "windows" && errors.Is(err, errorPrivilegeNotHeld) {
			t.Skip("Windows runner lacks the privilege to create a symlink")
		}
		t.Fatal(err)
	}
	if data, err := Read(link, 2); err == nil || data != nil {
		t.Fatal("followed final policy symlink")
	}
}
