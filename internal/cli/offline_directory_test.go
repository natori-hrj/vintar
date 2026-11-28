package cli

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestDiscoverDraftOutputDirectory(t *testing.T) {
	const inputID = "input-24a9c3cf0c3d01709121ac0d09079903"
	const draftName = "case-24a9c3cf0c3d01709121ac0d09079903.draft.toml"
	const spec = `{"openapi":"3.1.0","paths":{"/a":{"get":{"parameters":[{"name":"q","in":"query","schema":{"type":"string"}}]}}}}`
	const emptySummary = "{\"drafts\": [], \"report_type\": \"discovery_draft_summary\", \"schema_version\": 1}\n"
	for _, tc := range []struct {
		name, raw, destination string // empty destination means rejection
		linkTarget             string
	}{
		{name: "existing symlink before parent", raw: "linked/../drafts", linkTarget: "real/target"},
		{name: "dangling symlink before parent", raw: "linked/../drafts", linkTarget: "absent"},
		{name: "file before parent", raw: "block/../drafts"},
		{name: "symlink after missing", raw: "missing/../linked", linkTarget: "real/target"},
		{name: "symlink after nested missing", raw: "missing/child/../../linked/../drafts", linkTarget: "real/target"},
		{name: "file after missing", raw: "missing/../block/../drafts"},
		{name: "ordinary parent and repeated separators", raw: "real//target/.././drafts", destination: "real/drafts"},
		{name: "missing nested destination", raw: "missing/nested", destination: "missing/nested"},
		{name: "existing destination after missing", raw: "missing/child/../../real//target", destination: "real/target"},
	} {
		for _, mode := range []struct {
			name, approved string
		}{
			{"empty", "[]"},
			{"approved", `["` + inputID + `"]`},
		} {
			t.Run(tc.name+"/"+mode.name, func(t *testing.T) {
				dir, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				t.Chdir(dir)
				if err := os.MkdirAll("real/target", 0700); err != nil {
					t.Fatal(err)
				}
				if tc.linkTarget != "" {
					if err := os.Symlink(tc.linkTarget, "linked"); err != nil {
						if runtime.GOOS == "windows" {
							t.Skipf("cannot create symlink: %v", err)
						}
						t.Fatal(err)
					}
				}
				for path, content := range map[string]string{
					"block":          "not a directory",
					"openapi.json":   spec,
					"selection.toml": "version = 1\napproved = " + mode.approved + "\n",
				} {
					if err := os.WriteFile(path, []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
				}
				before := offlineDirectoryPaths(t)

				var out, errOut bytes.Buffer
				code := Run(t.Context(), []string{"discover", "--spec", "openapi.json", "--selection", "selection.toml", "--drafts-dir", tc.raw}, &out, &errOut)
				switch {
				case tc.destination == "":
					if code != 2 || out.Len() != 0 || errOut.String() != "Error: "+errOfflineOutputDirectory.Error()+"\n" {
						t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, &out, &errOut)
					}
				case mode.name == "empty":
					if code != 0 || out.String() != emptySummary || errOut.Len() != 0 {
						t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, &out, &errOut)
					}
				default:
					if code != 0 || errOut.Len() != 0 || !bytes.Contains(out.Bytes(), []byte(draftName)) {
						t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, &out, &errOut)
					}
					if data, err := os.ReadFile(filepath.Join(tc.destination, draftName)); err != nil || len(data) == 0 {
						t.Fatalf("read published draft: bytes = %d, error = %v", len(data), err)
					}
					if tc.destination == "real/target" {
						if _, err := os.Lstat("missing"); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("discarded directory was materialized: %v", err)
						}
					}
					return
				}
				if after := offlineDirectoryPaths(t); !slices.Equal(after, before) {
					t.Fatalf("output must not change the tree: before = %v, after = %v", before, after)
				}
			})
		}
	}
}

func TestOfflineReviewOutputDirectory(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	initial := []byte("existing")
	if err := os.WriteFile("block", initial, 0600); err != nil {
		t.Fatal(err)
	}
	before := offlineDirectoryPaths(t)
	err = publishOfflineReview(t.Context(), "missing/../block/../report.json", []byte("new"), nil)
	if !errors.Is(err, errOfflineOutputDirectory) {
		t.Fatalf("expected directory rejection, got %v", err)
	}
	if after := offlineDirectoryPaths(t); !slices.Equal(after, before) {
		t.Fatalf("rejection changed the tree: before = %v, after = %v", before, after)
	}

	output := "missing/../reports/report.json"
	if err := publishOfflineReview(t.Context(), output, initial, nil); err != nil {
		t.Fatal(err)
	}
	if err := publishOfflineReview(t.Context(), output, []byte("replacement"), nil); err == nil {
		t.Fatal("expected refusal to overwrite existing review")
	}
	if data, err := os.ReadFile("reports/report.json"); err != nil || !bytes.Equal(data, initial) {
		t.Fatalf("existing review = %q, read error = %v", data, err)
	}
}

func offlineDirectoryPaths(t *testing.T) []string {
	t.Helper()
	var paths []string
	if err := filepath.WalkDir(".", func(path string, _ fs.DirEntry, err error) error {
		if err == nil {
			paths = append(paths, path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return paths
}
