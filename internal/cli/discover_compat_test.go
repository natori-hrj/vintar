package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/natori-hrj/vintar/internal/discovery"
)

func TestDiscoverDraftSpecCWDPrecedesInputReads(t *testing.T) {
	parent := t.TempDir()
	cwd := filepath.Join(parent, "work")
	if err := os.Mkdir(cwd, 0755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)

	bad := filepath.Join(parent, "private-malformed.json")
	if err := os.WriteFile(bad, []byte(`{`), 0600); err != nil {
		t.Fatal(err)
	}
	valid := filepath.Join(parent, "valid.json")
	if err := os.WriteFile(valid, []byte(`{"openapi":"3.1.0","paths":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(cwd, "link.json")
	if err := os.Symlink(bad, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(cwd, "dangling.json")
	if err := os.Symlink(filepath.Join(parent, "absent-subdir", "absent.json"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, spec, want string
	}{
		{"outside malformed", bad, "Error: Spec is outside the current working directory. Run from a directory that contains the spec.\n"},
		{"outside valid and missing selection", valid, "Error: Spec is outside the current working directory. Run from a directory that contains the spec.\n"},
		{"outside absent", "../private-absent/other.json", "Error: Spec is outside the current working directory. Run from a directory that contains the spec.\n"},
		{"outside via symlink", link, "Error: Spec is outside the current working directory. Run from a directory that contains the spec.\n"},
		{"outside via dangling symlink", dangling, "Error: Spec is outside the current working directory. Run from a directory that contains the spec.\n"},
		{"inside absent", "private-absent.json", "Error: invalid OpenAPI spec. Check the local file format, declarations, references, and limits.\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(context.Background(), []string{"discover", "--spec", tc.spec, "--selection", "private-selection.toml", "--drafts-dir", "drafts"}, &out, &errOut)
			if code != 2 || out.Len() != 0 || errOut.String() != tc.want {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, &out, &errOut)
			}
			if _, err := os.Stat("drafts"); !os.IsNotExist(err) {
				t.Fatalf("drafts should not exist, stat error = %v", err)
			}
		})
	}
}

func TestDiscoverSelectionParseDiagnostic(t *testing.T) {
	dir := t.TempDir()
	spec, selection, output := filepath.Join(dir, "openapi.json"), filepath.Join(dir, "selection.toml"), filepath.Join(dir, "report.json")
	if err := os.WriteFile(spec, []byte(`{"openapi":"3.1.0","paths":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, selection, want string
	}{
		{"malformed", `private_key = ["private-value"`, "Error: Invalid selection TOML. Use version = 1 and an approved list of inventory input IDs.\n"},
		{"non UTF-8", "\xff", "Error: Invalid selection TOML. Use version = 1 and an approved list of inventory input IDs.\n"},
		{"extra key", "version = 1\napproved = []\nprivate_key = true", "Error: Invalid selection keys. Use only version and approved.\n"},
		{"two wrong keys", "version = 1\nprivate_key = []", "Error: Invalid selection keys. Use only version and approved.\n"},
		{"wrong schema", "version = true\napproved = []", "Error: Invalid selection schema. Set version = 1 and approved to an array of input IDs.\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(selection, []byte(tc.selection), 0600); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := Run(context.Background(), []string{"discover", "--spec", spec, "--selection", selection, "--output", output}, &out, &errOut)
			if code != 2 || out.Len() != 0 || errOut.String() != tc.want {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, &out, &errOut)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("report should not exist, stat error = %v", err)
			}
		})
	}
}

func TestDiscoverRepeatedSeparatorsStayInsideCWD(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("sub", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("sub/openapi.json", []byte(`{"openapi":"3.1.0","paths":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("selection.toml", []byte("version = 1\napproved = []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run(t.Context(), []string{"discover", "--spec", "sub//openapi.json", "--selection", "selection.toml", "--drafts-dir", "drafts"}, &out, &errOut)
	if code != 0 || out.Len() == 0 || errOut.Len() != 0 {
		t.Fatalf("cwd-relative discovery failed: exit=%d, stdout=%s, stderr=%s", code, &out, &errOut)
	}
}
func TestDiscoverDraftCanBeReviewedOffline(t *testing.T) {
	const inputID = "input-24a9c3cf0c3d01709121ac0d09079903"
	const name = "one\u2028two.json"
	const spec = `{"openapi":"3.1.0","paths":{"/a":{"get":{"parameters":[{"name":"q","in":"query","schema":{"type":"string"}}]}}}}`
	const answers = `{"version":1,"expected_verdict":"not_detected","parameters":{"q":{"value":"private-baseline-marker"}}}`
	dir := t.TempDir()
	t.Chdir(dir)
	filename := filepath.Join(dir, name)
	if err := os.WriteFile(filename, []byte(spec), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("selection.toml", []byte("version = 1\napproved = [\""+inputID+"\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"discover", "--spec", filename, "--selection", "selection.toml", "--drafts-dir", "drafts"}, &out, &errOut)
	if code != 0 || errOut.Len() != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, &errOut)
	}
	draft, err := os.ReadFile(filepath.Join("drafts", "case-24a9c3cf0c3d01709121ac0d09079903.draft.toml"))
	if err != nil {
		t.Fatal(err)
	}
	report, id, err := discovery.BuildDraftReview([]byte(spec), name, draft, []byte(answers))
	if err != nil || id != inputID || bytes.Contains(report, []byte("private-baseline-marker")) {
		t.Fatalf("report = %q, id = %q, err = %v", report, id, err)
	}
}
