package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func checkProductDiscovery(t *testing.T, root, binary string) {
	t.Helper()
	cwd := t.TempDir()
	write := func(name, text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(cwd, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("openapi.json", string(readFixture(t, root, "tests/fixtures/discovery/openapi30.json")))
	write("openapi.yaml", string(readFixture(t, root, "tests/fixtures/discovery/openapi30.yaml")))
	write("review.toml", "version = 1\napproved = [\"input-24a9c3cf0c3d01709121ac0d09079903\"]\n")
	var expected struct {
		Report json.RawMessage `json:"report_json"`
		Stdout json.RawMessage `json:"stdout_json"`
	}
	if err := json.Unmarshal(readFixture(t, root, "tests/golden/cli/discover/success.json"), &expected); err != nil {
		t.Fatal(err)
	}
	invocation := runProduct(t, binary, cwd, "discover", "--spec", "openapi.json", "--output", "report.json", "--selection", "review.toml")
	if invocation.code != 0 || invocation.stderr != "" {
		t.Fatalf("inventory: %+v", invocation)
	}
	equivalentJSON(t, []byte(invocation.stdout), expected.Stdout)
	equivalentJSON(t, readFixture(t, cwd, "report.json"), expected.Report)

	yaml := runProduct(t, binary, cwd, "discover", "--spec", "openapi.yaml", "--output", "yaml.json")
	if yaml.code != 0 || yaml.stderr != "" {
		t.Fatalf("YAML inventory: %+v", yaml)
	}

	var drafts struct {
		Stdout json.RawMessage   `json:"stdout_json"`
		Files  map[string]string `json:"draft_files"`
	}
	if err := json.Unmarshal(readFixture(t, root, "tests/golden/cli/discover/drafts.json"), &drafts); err != nil {
		t.Fatal(err)
	}
	draftArgs := []string{"discover", "--spec", "openapi.json", "--selection", "review.toml", "--drafts-dir", "drafts"}
	for i := 0; i < 2; i++ {
		got := runProduct(t, binary, cwd, draftArgs...)
		if got.code != 0 || got.stderr != "" {
			t.Fatalf("drafts: %+v", got)
		}
		equivalentJSON(t, []byte(got.stdout), drafts.Stdout)
		for name, want := range drafts.Files {
			if got := string(readFixture(t, cwd, filepath.Join("drafts", name))); got != want {
				t.Fatalf("draft differs from released bytes: %q", name)
			}
		}
	}
	for name := range drafts.Files {
		write(filepath.Join("drafts", name), "existing")
		got := runProduct(t, binary, cwd, draftArgs...)
		if got.code != 2 || got.stdout != "" || string(readFixture(t, cwd, filepath.Join("drafts", name))) != "existing" {
			t.Fatalf("different artifact was not safely refused: %+v", got)
		}
	}
	if err := os.Link(filepath.Join(cwd, "openapi.json"), filepath.Join(cwd, "alias.json")); err != nil {
		t.Fatal(err)
	}
	alias := runProduct(t, binary, cwd, "discover", "--spec", "openapi.json", "--output", "alias.json")
	if alias.code != 2 || alias.stdout != "" {
		t.Fatalf("input alias was not refused: %+v", alias)
	}
}

func equivalentJSON(t *testing.T, got, expected []byte) {
	t.Helper()
	var a, b any
	if json.Unmarshal(got, &a) != nil || json.Unmarshal(expected, &b) != nil || !reflect.DeepEqual(a, b) {
		t.Fatalf("JSON differs:\n got: %s\nwant: %s", got, expected)
	}
}
