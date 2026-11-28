package cli

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestCompletionShowAndInstallIsolated(t *testing.T) {
	t.Setenv(explicitCompletionShell, "1")
	t.Setenv("_VINTAR_COMPLETE", "")
	for _, tc := range []struct{ shell, script, rc, registration string }{
		{"bash", ".bash_completions/vintar.sh", ".bashrc", "source "},
		{"zsh", ".zfunc/_vintar", ".zshrc", "fpath+=~/.zfunc"},
		{"fish", ".config/fish/completions/vintar.fish", "", ""},
	} {
		t.Run(tc.shell, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			const original = "# user settings\n\n"
			if tc.rc != "" {
				if err := os.WriteFile(filepath.Join(home, tc.rc), []byte(original), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			run := func(args ...string) int {
				stdout.Reset()
				stderr.Reset()
				return Run(t.Context(), args, &stdout, &stderr)
			}
			path := filepath.Join(home, tc.script)
			if code := run("--show-completion", tc.shell); code != 0 || !strings.Contains(stdout.String(), "vintar") || stderr.Len() != 0 {
				t.Fatalf("show: exit=%d stdout=%q stderr=%q", code, &stdout, &stderr)
			}
			want := stdout.String()
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("show wrote a file: %v", err)
			}
			for range 2 {
				if code := run("--install-completion", tc.shell); code != 0 || !strings.Contains(stdout.String(), path) || stderr.Len() != 0 {
					t.Fatalf("install: exit=%d stdout=%q stderr=%q", code, &stdout, &stderr)
				}
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != want {
				t.Fatalf("installed script mismatch: %v", err)
			}
			if tc.rc != "" {
				rc, err := os.ReadFile(filepath.Join(home, tc.rc))
				if err != nil || !strings.HasPrefix(string(rc), original) || strings.Count(string(rc), tc.registration) != 1 {
					t.Fatalf("startup settings changed or duplicated: %q, %v", rc, err)
				}
			}
			const custom = "# custom user completion"
			if err := os.WriteFile(path, []byte(custom), 0600); err != nil {
				t.Fatal(err)
			}
			if code := run("--install-completion", tc.shell); code == 0 {
				t.Fatal("install accepted an existing different script")
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != custom {
				t.Fatalf("existing completion was modified: %q, %v", got, err)
			}
		})
	}
}

func TestCompletionPreservesProfileEncodingAndEmptyPrefix(t *testing.T) {
	old := []byte{0xff, 0xfe}
	for _, u := range utf16.Encode([]rune("# user 設定\r\n")) {
		old = binary.LittleEndian.AppendUint16(old, u)
	}
	const text = "Register-ArgumentCompleter vintar"
	appended := completionAppendBytes(old, text)
	var want []byte
	for _, u := range utf16.Encode([]rune(text + "\n")) {
		want = binary.LittleEndian.AppendUint16(want, u)
	}
	if !bytes.Equal(appended, want) || completionAppendBytes(append(old, appended...), text) != nil {
		t.Fatal("UTF-16 profile append changed the encoding or was not idempotent")
	}
	t.Setenv("_VINTAR_COMPLETE", "complete_words")
	var out, errOut bytes.Buffer
	if n := Run(t.Context(), []string{"http", "word:"}, &out, &errOut); n != 0 || out.String() != "send\n" || errOut.Len() != 0 {
		t.Fatalf("empty completion word: %d %q %q", n, &out, &errOut)
	}
}

func TestCompletionPublicOptionsAndCandidates(t *testing.T) {
	t.Setenv(explicitCompletionShell, "1")
	t.Setenv("_VINTAR_COMPLETE", "")
	for _, shell := range []string{"powershell", "pwsh", "unknown"} {
		for _, action := range []string{"--show-completion", "--install-completion"} {
			if shell != "unknown" && action == "--install-completion" {
				continue // native installation is not invoked by this test
			}
			var out, errOut bytes.Buffer
			code := Run(t.Context(), []string{action, shell}, &out, &errOut)
			if shell == "unknown" {
				if code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), action) {
					t.Fatalf("unsupported shell: %d, %q, %q", code, &out, &errOut)
				}
			} else if code != 0 || !strings.Contains(out.String(), "Register-ArgumentCompleter") || errOut.Len() != 0 {
				t.Fatalf("powershell show: %d, %q, %q", code, &out, &errOut)
			}
		}
	}
	t.Setenv(explicitCompletionShell, "")
	t.Setenv("_VINTAR_COMPLETE", "complete_bash")
	t.Setenv("COMP_WORDS", `vintar http send --header 'X-Demo: with spaces' -t.1 --`)
	t.Setenv("COMP_CWORD", "6")
	var out, errOut bytes.Buffer
	if code := Run(t.Context(), nil, &out, &errOut); code != 0 || errOut.Len() != 0 ||
		!strings.Contains(out.String(), "--header\n") || strings.Contains(out.String(), "--timeout\n") {
		t.Fatalf("candidate repetition and scalar exclusion: %d, %q, %q", code, &out, &errOut)
	}
}
