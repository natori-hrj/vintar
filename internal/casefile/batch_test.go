//go:build linux || darwin || windows

package casefile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBatchInput(t *testing.T, dir, name, data string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadBatchOrderAndBudget(t *testing.T) {
	dir := t.TempDir()
	last := writeBatchInput(t, dir, "z.toml", v1)
	writeBatchInput(t, dir, "a.toml", strings.Replace(v1, `id = "example"`, `id = "first"`, 1))
	writeBatchInput(t, dir, "ignored.txt", "not TOML")
	nested := filepath.Join(dir, "subdir")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	writeBatchInput(t, nested, "ignored.toml", "not TOML")
	cases, err := LoadBatch(dir+string(os.PathSeparator), 12)
	if err != nil || len(cases) != 2 || cases[0].ID != "first" || cases[1].ID != "example" {
		t.Fatalf("ordered selection: got %d cases; %v", len(cases), err)
	}
	if cases, err := LoadBatch(last, 6); err != nil || len(cases) != 1 || cases[0].ID != "example" {
		t.Fatalf("single-file selection: got %d cases; %v", len(cases), err)
	}
	if cases, err := LoadBatch(dir, 11); err == nil || cases != nil {
		t.Fatal("insufficient aggregate budget admitted cases")
	}
}

func TestLoadBatchRejectsWholeSelection(t *testing.T) {
	otherV2 := strings.Replace(v2Get, `id = "get-query-boolean"`, `id = "another"`, 1)
	for _, tc := range []struct {
		name, first, second, want string
	}{
		{"duplicate", v1, v1, "duplicate regression case identifier"},
		{"mixed versions", v1, v2Get, "mixed case schema versions"},
		{"mixed identities", v2Get, strings.Replace(otherV2, "billing-reader", "other-user", 1), "multiple v2 identities in one batch"},
		{"oversized", v1, strings.Repeat("x", MaxCaseBytes+1), errCaseSource.Error()},
		{"malformed", v1, "sensitive-invalid-TOML!", "invalid case TOML"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeBatchInput(t, dir, "a.toml", tc.first)
			writeBatchInput(t, dir, "b.toml", tc.second)
			if cases, err := LoadBatch(dir, 12); cases != nil || err == nil || err.Error() != tc.want {
				t.Fatalf("got %d cases and error %v; want no cases and %q", len(cases), err, tc.want)
			}
		})
	}
}

func TestLoadBatchRejectsInvalidEntriesAndSize(t *testing.T) {
	dir := t.TempDir()
	if cases, err := LoadBatch(dir, 1); cases != nil || err == nil {
		t.Fatal("empty selection admitted")
	}
	if err := os.Mkdir(filepath.Join(dir, "dir.toml"), 0700); err != nil {
		t.Fatal(err)
	}
	if cases, err := LoadBatch(dir, 6); cases != nil || err == nil {
		t.Fatal("directory entry admitted as a case")
	}
	large := t.TempDir()
	for i := range maxBatchCases + 1 {
		name := fmt.Sprintf("%03d.toml", i)
		writeBatchInput(t, large, name, strings.Replace(v1, `"example"`, fmt.Sprintf(`"case-%d"`, i), 1))
		if i == maxBatchCases-1 {
			if cases, err := LoadBatch(large, 6*maxBatchCases); err != nil || len(cases) != maxBatchCases {
				t.Fatalf("selection at limit: got %d cases; %v", len(cases), err)
			}
		}
	}
	if cases, err := LoadBatch(large, 6*(maxBatchCases+1)); cases != nil || err == nil || err.Error() != "too many regression cases" {
		t.Fatalf("oversized selection: got %d cases; %v", len(cases), err)
	}
}

func TestLoadBatchRejectsSourceAndEntrySymlinks(t *testing.T) {
	dir := t.TempDir()
	file := writeBatchInput(t, dir, "real.toml", v1)
	link := filepath.Join(dir, "link.toml")
	if err := os.Symlink(file, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for _, path := range []string{dir, link} {
		if cases, err := LoadBatch(path, 12); cases != nil || err == nil {
			t.Fatal("link admitted as a case")
		}
	}
	dirLink := filepath.Join(t.TempDir(), "directory-link")
	if err := os.Symlink(dir, dirLink); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", string(os.PathSeparator), string(os.PathSeparator) + "."} {
		if cases, err := LoadBatch(dirLink+suffix, 12); cases != nil || err == nil {
			t.Fatal("linked directory admitted as a case source")
		}
	}
}

func TestReadCaseRejectsReplacementAfterSelection(t *testing.T) {
	dir := t.TempDir()
	file := writeBatchInput(t, dir, "selected.toml", v1)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	inputs, err := caseInputs(root)
	if err != nil || len(inputs) != 1 {
		t.Fatalf("selection: got %d cases; %v", len(inputs), err)
	}
	if err := os.Rename(file, filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	writeBatchInput(t, dir, "selected.toml", v1)
	if data, err := readCase(root, inputs[0]); data != nil || err == nil {
		t.Fatal("replacement file admitted")
	}
}
