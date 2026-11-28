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
const httpTransportPackage = "internal/execution/internal/httpio"
const policyReaderPackage = "internal/execution/internal/policyfile"
const yamlModule = "go.yaml.in/yaml/v3"

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
	case pkg.Standard:
		// unsafe/syscall may occur inside the Go standard library (e.g. os).
		// Direct imports by project code are rejected below.
	case path == punycodePackage, path == normalizationPackage,
		path == "golang.org/x/text/secure/bidirule",
		path == "golang.org/x/text/unicode/bidi", path == "golang.org/x/text/transform":
	case path == "golang.org/x/text/cases", path == "golang.org/x/text/language",
		path == "golang.org/x/text/internal", path == "golang.org/x/text/internal/tag",
		path == "golang.org/x/text/internal/language", path == "golang.org/x/text/internal/language/compact":
	case pkg.Module != nil && (pkg.Module.Path == tomlModule || pkg.Module.Path == yamlModule):
		for _, dep := range pkg.Imports {
			if dep == "os/exec" || dep == "plugin" || dep == "C" || dep == "net" || strings.HasPrefix(dep, "net/http") {
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
		"internal/cli":        {"internal/casefile", "internal/discovery", "internal/execution", "internal/report", "internal/strictjson"},
		"internal/casefile":   {"internal/strictjson"},
		"internal/discovery":  {"internal/strictjson"},
		"internal/execution":  {httpTransportPackage, policyReaderPackage, "internal/strictjson"},
		httpTransportPackage:  nil,
		policyReaderPackage:   nil,
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
		case dep == "syscall" && (path == policyReaderPackage || path == "internal/cli"):
			// File readers use no-follow flags and Windows checks the open handle.
		case dep == "C", dep == "unsafe", dep == "syscall", dep == "os/exec", dep == "plugin":
			t.Errorf("unsafe direct import: %s imports %s", path, dep)
		case dep == "net" || dep == "net/http" || dep == "crypto/tls":
			if path != httpTransportPackage {
				t.Errorf("transport dependency outside %s: %s imports %s", httpTransportPackage, path, dep)
			}
		case strings.HasPrefix(dep, "net/http/") || dep == "net/rpc" || dep == "net/smtp":
			t.Errorf("unapproved network dependency: %s imports %s", path, dep)
		case dep == tomlModule || strings.HasPrefix(dep, tomlModule+"/"):
			if (path != "internal/casefile" && path != "internal/cli") || dep != tomlModule {
				t.Errorf("TOML decoding must stay with case and selection inputs: %s imports %s", path, dep)
			}
		case dep == yamlModule || strings.HasPrefix(dep, yamlModule+"/"):
			if path != "internal/discovery" || dep != yamlModule {
				t.Errorf("YAML decoding must stay offline in discovery: %s imports %s", path, dep)
			}
		case strings.HasPrefix(dep, "golang.org/x/net/") || strings.HasPrefix(dep, "golang.org/x/text/"):
			casefileCodec := path == "internal/casefile" && (dep == punycodePackage || dep == normalizationPackage)
			publicHTTPCodec := path == httpTransportPackage && (dep == punycodePackage || dep == "golang.org/x/text/cases" || dep == "golang.org/x/text/language")
			if !casefileCodec && !publicHTTPCodec {
				t.Errorf("unapproved hostname codec: %s imports %s", path, dep)
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
