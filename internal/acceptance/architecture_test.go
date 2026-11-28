package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

const modulePath = "github.com/natori-hrj/vintar"
const tomlModule = "github.com/pelletier/go-toml/v2"
const punycodePackage = "golang.org/x/net/idna"
const normalizationPackage = "golang.org/x/text/unicode/norm"

type listedPackage struct {
	ImportPath string
	Imports    []string
	Standard   bool
	Module     *struct{ Path string }
}

func TestProductArchitecture(t *testing.T) {
	root := repoRoot(t)
	for _, target := range []string{"linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			goos, goarch, _ := strings.Cut(target, "/")
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			// Include unlinked production packages too, and deliberately do not
			// include -test: jsonschema is a test dependency, not a product one.
			cmd := goCommand(ctx, root, goos, goarch, "list", "-mod=readonly", "-deps", "-json",
				"./cmd/vintar", "./internal/...")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list for %s: %v\n%s", target, err, &stderr)
			}
			decoder := json.NewDecoder(bytes.NewReader(output))
			foundEntry := false
			for {
				var pkg listedPackage
				err := decoder.Decode(&pkg)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("decode go list output: %v", err)
				}
				foundEntry = foundEntry || pkg.ImportPath == modulePath+"/cmd/vintar"
				checkProductPackage(t, pkg)
			}
			if !foundEntry {
				t.Fatal("missing product entry in go list output")
			}
		})
	}
}

func checkProductPackage(t *testing.T, pkg listedPackage) {
	t.Helper()
	path := pkg.ImportPath
	switch {
	case path == "net", strings.HasPrefix(path, "net/http"), path == "net/rpc", path == "net/smtp",
		path == "crypto/tls":
		t.Errorf("network dependency in foundation product graph: %s", path)
	case pkg.Standard:
		// unsafe/syscall may occur inside the Go standard library (e.g. os).
		// Direct imports by project code are rejected below.
	case path == punycodePackage, path == normalizationPackage,
		path == "golang.org/x/text/secure/bidirule",
		path == "golang.org/x/text/unicode/bidi", path == "golang.org/x/text/transform":
	case pkg.Module != nil && pkg.Module.Path == tomlModule:
		for _, dep := range pkg.Imports {
			if dep == "os/exec" || dep == "plugin" || dep == "C" {
				t.Errorf("unsafe dependency: %s imports %s", path, dep)
			}
		}
	case strings.HasPrefix(path, modulePath+"/"):
		checkProductImports(t, strings.TrimPrefix(path, modulePath+"/"), pkg.Imports)
	default:
		t.Errorf("unapproved product dependency %s (JSON Schema validation belongs in tests only)", path)
	}
}

func checkProductImports(t *testing.T, path string, imports []string) {
	t.Helper()
	// Edges allowed by the foundation layering, not edges that are required.
	allowed := map[string][]string{
		"cmd/vintar":          {"internal/cli"},
		"internal/cli":        {"internal/casefile", "internal/report", "internal/strictjson"},
		"internal/casefile":   {"internal/strictjson"},
		"internal/report":     {"internal/strictjson"},
		"internal/strictjson": nil,
		"internal/acceptance": nil, // Test-only; no product package may import it.
	}
	edges, ok := allowed[path]
	if !ok {
		t.Errorf("unapproved foundation package: %s", path)
	}
	for _, dep := range imports {
		switch {
		case dep == "C", dep == "unsafe", dep == "syscall", dep == "os/exec", dep == "plugin":
			t.Errorf("unsafe direct import: %s imports %s", path, dep)
		case dep == tomlModule || strings.HasPrefix(dep, tomlModule+"/"):
			if path != "internal/casefile" || dep != tomlModule {
				t.Errorf("TOML decoding must stay in casefile: %s imports %s", path, dep)
			}
		case strings.HasPrefix(dep, "golang.org/x/net/") || strings.HasPrefix(dep, "golang.org/x/text/"):
			if path != "internal/casefile" || dep != punycodePackage && dep != normalizationPackage {
				t.Errorf("only casefile may import the hostname codecs: %s imports %s", path, dep)
			}
		case strings.HasPrefix(dep, modulePath+"/"):
			permitted := false
			for _, edge := range edges {
				if dep == modulePath+"/"+edge {
					permitted = true
					break
				}
			}
			if !permitted {
				t.Errorf("forbidden product import direction: %s imports %s", path, dep)
			}
		}
	}
}
