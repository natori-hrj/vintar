package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("locate module at %s: %v", root, err)
	}
	return root
}

func readFixture(t *testing.T, root, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func goCommand(ctx context.Context, root, goos, goarch string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = root
	cmd.Env = append(cmd.Environ(), "GOTOOLCHAIN=local", "CGO_ENABLED=0",
		"GOOS="+goos, "GOARCH="+goarch)
	return cmd
}

func productBinary(t *testing.T, root string) string {
	t.Helper()
	if path, set := os.LookupEnv("VINTAR_TEST_BINARY"); set {
		if !filepath.IsAbs(path) {
			t.Fatal("VINTAR_TEST_BINARY must be an absolute path")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat VINTAR_TEST_BINARY: %v", err)
		}
		if !info.Mode().IsRegular() {
			t.Fatal("VINTAR_TEST_BINARY must point to a regular file")
		}
		return path
	}
	name := "vintar"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(t.TempDir(), name)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := goCommand(ctx, root, runtime.GOOS, runtime.GOARCH,
		"build", "-mod=readonly", "-trimpath", "-o", path, "./cmd/vintar")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build product binary: %v\n%s", err, output)
	}
	return path
}

type invocation struct {
	code           int
	stdout, stderr string
}

func runProduct(t *testing.T, binary, cwd string, args ...string) invocation {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = cwd
	for _, entry := range cmd.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		switch key {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "HOME", "USERPROFILE":
			continue
		}
		if !strings.HasPrefix(key, "VINTAR_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "HOME="+cwd, "USERPROFILE="+cwd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("%v: %v", args, ctx.Err())
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() < 0 {
			t.Fatalf("execute %v: %v; stdout=%q stderr=%q", args, err, &stdout, &stderr)
		}
		code = exit.ExitCode()
	}
	return invocation{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func TestProductBinary(t *testing.T) {
	root := repoRoot(t)
	binary := productBinary(t, root)
	t.Logf("product binary: %s (%s/%s, test toolchain %s)", binary, runtime.GOOS, runtime.GOARCH, runtime.Version())

	for _, tc := range []struct {
		name  string
		args  []string
		code  int
		words []string
	}{
		{"root-help", []string{"--help"}, 0, []string{
			"version", "verify", "http", "sqli", "discover", "inventory-post-json",
			"review-draft", "review-post-json", "materialize-case", "materialize-post-json-case",
			"--show-completion", "--install-completion",
		}},
		{"root-no-args", nil, 2, []string{"version", "verify", "discover"}},
		{"sqli-no-args", []string{"sqli"}, 2, []string{"verify"}},
		{"verify-help", []string{"verify", "--help"}, 0, []string{"--cases", "--authorized", "--pretty"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runProduct(t, binary, t.TempDir(), tc.args...)
			if got.code != tc.code || got.stderr != "" {
				t.Fatalf("want exit %d and empty stderr; got %+v", tc.code, got)
			}
			for _, word := range tc.words {
				if !strings.Contains(got.stdout, word) {
					t.Errorf("help stdout missing %q: %q", word, got.stdout)
				}
			}
		})
	}

	t.Run("version", func(t *testing.T) {
		got := runProduct(t, binary, t.TempDir(), "version")
		want := invocation{stdout: "Vintar v0.7.0\n"}
		if got != want {
			t.Fatalf("version: got %+v; want %+v", got, want)
		}
	})

	t.Run("http-method-uppercase", func(t *testing.T) {
		testHTTPMethodUppercase(t, root, binary)
	})

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"extra-arg", []string{"version", "extra"}},
		{"unknown-command", []string{"not-a-command"}},
		{"unknown-option", []string{"--not-an-option"}},
		{"verify-missing-cases", []string{"verify"}},
		{"http-no-args", []string{"http"}},
		{"http-missing-url", []string{"http", "send", "GET"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runProduct(t, binary, t.TempDir(), tc.args...)
			if got.code != 2 || got.stdout != "" || strings.TrimSpace(got.stderr) == "" ||
				strings.Contains(got.stderr, "not available") {
				t.Fatalf("want a parse diagnostic on stderr only and exit 2; got %+v", got)
			}
		})
	}

	// These release captures used parsed arguments without authorization. Do not
	// pass --authorized, real endpoints, or payloads that could change a query.
	for _, tc := range []struct {
		command string
		args    []string
	}{
		{"verify", []string{"verify", "--cases", "unread.toml"}},
		{"sqli-verify", []string{"sqli", "verify",
			"--url", "http://cli-fixture.invalid/", "--allow-origin", "http://cli-fixture.invalid",
			"--inject-param", "id", "--true-payload", "alpha", "--false-payload", "beta"}},
	} {
		t.Run(tc.command+"-authorization-required", func(t *testing.T) {
			var golden struct {
				Code   int             `json:"exit_code"`
				Stdout json.RawMessage `json:"stdout_json"`
				Stderr string          `json:"stderr"`
			}
			path := "tests/golden/cli/" + tc.command + "/authorization-required.json"
			if err := json.Unmarshal(readFixture(t, root, path), &golden); err != nil {
				t.Fatalf("decode %s: %v", path, err)
			}
			if golden.Code != 2 || string(golden.Stdout) != "null" || golden.Stderr == "" {
				t.Fatalf("not an authorization refusal golden: %s", path)
			}
			got := runProduct(t, binary, t.TempDir(), tc.args...)
			want := invocation{code: golden.Code, stderr: golden.Stderr}
			if got != want {
				t.Fatalf("%s: got %+v; want %+v", path, got, want)
			}
		})
	}

	// Exercise only offline stubs here; no test invokes an authorized route.
	spec := filepath.Join(root, "tests", "fixtures", "discovery", "openapi30.json")
	for _, args := range [][]string{
		{"discover", "--spec", spec, "--output", "out.json"},
		{"inventory-post-json", "--spec", spec, "--output", "out.json"},
		{"review-draft", "--spec", spec, "--draft", "draft.json", "--answers", "answers.json", "--output", "out.json"},
		{"review-post-json", "--spec", spec, "--inventory", "inventory.json", "--answers", "answers.json", "--output", "out.json"},
		{"materialize-case", "--spec", spec, "--draft", "draft.json", "--answers", "answers.json", "--review", "review.json", "--config", "config.json", "--output", "out.toml"},
		{"materialize-post-json-case", "--spec", spec, "--inventory", "inventory.json", "--answers", "answers.json", "--review", "review.json", "--config", "config.json", "--output", "out.toml"},
	} {
		t.Run(args[0]+"-unavailable", func(t *testing.T) {
			cwd := t.TempDir()
			got := runProduct(t, binary, cwd, args...)
			if got.code != 2 || got.stdout != "" || !strings.Contains(got.stderr, "not available") {
				t.Fatalf("want unavailable on stderr only and exit 2; got %+v", got)
			}
			entries, err := os.ReadDir(cwd)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("unavailable command wrote files: %v", entries)
			}
		})
	}
}

func testHTTPMethodUppercase(t *testing.T, root, binary string) {
	t.Helper()
	// The accepted set is exhaustive: enumerate all single-code-point
	// str.upper() results in Unicode 15.1, then compose the ones that
	// produce GET or POST. Both sets were checked against the v0.6.0 CLI.
	var fixture struct {
		Accepted []string `json:"accepted"`
		Rejected []string `json:"rejected"`
	}
	data := readFixture(t, root, "internal/acceptance/testdata/http-methods-v0.6.0.json")
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Accepted) != 40 || len(fixture.Rejected) == 0 {
		t.Fatal("incomplete uppercase oracle")
	}
	cwd := t.TempDir()
	for _, group := range []struct {
		methods []string
		stdout  string
	}{
		{fixture.Accepted, "Header name cannot be empty.\n"},
		{fixture.Rejected, "Only GET and POST are supported.\n"},
	} {
		for _, method := range group.methods {
			// The invalid header guarantees rejection before any send. Both
			// diagnostics exit 1 on stdout, so assert their text too.
			want := invocation{code: 1, stdout: group.stdout}
			if got := runProduct(t, binary, cwd, "http", "send", method, "unused", "-H", ":"); got != want {
				t.Errorf("method %q: got %+v; want %+v", method, got, want)
			}
		}
	}
}
