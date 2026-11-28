package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/natori-hrj/vintar/internal/casefile"
	"github.com/natori-hrj/vintar/internal/report"
	"github.com/pelletier/go-toml/v2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	schemaURL   = "https://github.com/natori-hrj/vintar/blob/main/schemas/"
	batchSchema = "regression-batch-report-v1.schema.json"
	caseSchema  = "regression-case-v2.schema.json"
	inventoryV1 = "openapi-post-json-inventory-v1.schema.json"
	inventoryV2 = "openapi-post-json-inventory-v2.schema.json"
	reviewV1    = "post-json-discovery-review-v1.schema.json"
	reviewV2    = "post-json-discovery-review-v2.schema.json"
)

type offlineLoader struct{}

func (offlineLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("schema resource is not registered locally: %s", url)
}

func decodeSchemaJSON(t *testing.T, label string, data []byte) any {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode %s: %v", label, err)
	}
	return value
}

func publishedSchemas(t *testing.T, root string) map[string]*jsonschema.Schema {
	t.Helper()
	names := []string{batchSchema, caseSchema, inventoryV1, inventoryV2, reviewV1, reviewV2}
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(offlineLoader{})
	for _, name := range names {
		path := "schemas/" + name
		doc := decodeSchemaJSON(t, path, readFixture(t, root, path))
		object, ok := doc.(map[string]any)
		if !ok || object["$id"] != schemaURL+name {
			t.Fatalf("unexpected published id in %s", path)
		}
		if err := compiler.AddResource(schemaURL+name, doc); err != nil {
			t.Fatalf("register %s: %v", path, err)
		}
	}
	compiled := make(map[string]*jsonschema.Schema, len(names))
	for _, name := range names {
		schema, err := compiler.Compile(schemaURL + name)
		if err != nil {
			t.Fatalf("compile %s from local resources: %v", name, err)
		}
		compiled[name] = schema
	}
	return compiled
}

func fixtureObject(t *testing.T, label string, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is not a JSON object", label)
	}
	return object
}

func TestPublishedSchemas(t *testing.T) {
	root := repoRoot(t)
	schemas := publishedSchemas(t, root)
	for _, tc := range []struct {
		name, path, member, schema string
	}{
		{"legacy-batch", "tests/fixtures/regression-batch-report-v1-legacy.json", "", batchSchema},
		{"inventory-v1", "tests/fixtures/post-json-inventory-v1.json", "", inventoryV1},
		{"inventory-v2-candidate", "tests/golden/cli/inventory-post-json/success.json", "report_json", inventoryV2},
		{"inventory-v2-empty", "tests/golden/cli/inventory-post-json/empty.json", "report_json", inventoryV2},
		{"review-v2", "tests/golden/cli/review-post-json/success.json", "review_json", reviewV2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := decodeSchemaJSON(t, tc.path, readFixture(t, root, tc.path))
			if tc.member != "" {
				value = fixtureObject(t, tc.path, value)[tc.member]
			}
			object := fixtureObject(t, tc.path, value)
			schema := schemas[tc.schema]
			if err := schema.Validate(object); err != nil {
				t.Fatalf("%s (%s): %v", tc.path, tc.schema, err)
			}
			if tc.name == "inventory-v2-candidate" {
				operations := object["operations"].([]any)
				if len(operations) != 1 {
					t.Fatalf("candidate golden has %d operations; want 1", len(operations))
				}
				candidates := operations[0].(map[string]any)["review_candidates"].([]any)
				if len(candidates) != 1 {
					t.Fatalf("candidate golden has %d review candidates; want 1", len(candidates))
				}
				candidates[0].(map[string]any)["approval"] = "approved"
				if err := schema.Validate(object); err == nil {
					t.Error("inventory v2 schema accepted an approved candidate")
				}
				return
			}
			// Mutate only the decoded copy. Every one of these schemas requires
			// the version field and its exact published value.
			object["schema_version"] = "invalid"
			if err := schema.Validate(object); err == nil {
				t.Errorf("%s accepted a deliberately invalid schema_version", tc.schema)
			}
		})
	}

	t.Run("verify-stdout", func(t *testing.T) {
		paths, err := filepath.Glob(filepath.Join(root, "tests", "golden", "cli", "verify", "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		validated := 0
		for _, path := range paths {
			name := filepath.Base(path)
			if name == "authorization-required.json" {
				continue // Intentionally no report; replayed by TestProductBinary.
			}
			validated++
			t.Run(name, func(t *testing.T) {
				rel := "tests/golden/cli/verify/" + name
				data := readFixture(t, root, rel)
				golden := fixtureObject(t, rel, decodeSchemaJSON(t, rel, data))
				stdout := fixtureObject(t, rel+" stdout_json", golden["stdout_json"])
				if err := schemas[batchSchema].Validate(stdout); err != nil {
					t.Fatal(err)
				}
				var capture struct {
					ExitCode int          `json:"exit_code"`
					Batch    report.Batch `json:"stdout_json"`
				}
				if err := json.Unmarshal(data, &capture); err != nil {
					t.Fatal(err)
				}
				if err := capture.Batch.ValidateSummary(capture.ExitCode); err != nil {
					t.Fatal(err)
				}
			})
		}
		if validated == 0 {
			t.Fatal("no released verify reports found")
		}
	})

	t.Run("case-v2", func(t *testing.T) {
		published := readFixture(t, root, "schemas/"+caseSchema)
		packaged := readFixture(t, root, "src/vintar/schemas/"+caseSchema)
		if !bytes.Equal(published, packaged) {
			t.Fatal("packaged and published v2 case schemas differ")
		}
		for _, name := range []string{"boolean", "time", "error"} {
			t.Run(name, func(t *testing.T) {
				path := "tests/golden/cases/post-json-" + name + "-v2.toml"
				fixture := readFixture(t, root, path)
				parsed, err := casefile.Parse(fixture)
				if err != nil {
					t.Fatalf("parse released case: %v", err)
				}
				if parsed.Version != casefile.Version2 || parsed.Request.Method != casefile.POST ||
					parsed.Check != casefile.Check("sqli."+name) {
					t.Fatal("parsed case has wrong version, method, or check type")
				}
				var doc map[string]any
				if err := toml.Unmarshal(fixture, &doc); err != nil {
					t.Fatalf("decode TOML %s: %v", path, err)
				}
				data, err := json.Marshal(doc)
				if err != nil {
					t.Fatalf("map case TOML to JSON: %v", err)
				}
				value := decodeSchemaJSON(t, path, data)
				if err := schemas[caseSchema].Validate(value); err != nil {
					t.Fatalf("validate %s: %v", path, err)
				}
				delete(fixtureObject(t, path, value), "request")
				if err := schemas[caseSchema].Validate(value); err == nil {
					t.Error("v2 case schema accepted a missing request table")
				}
			})
		}
	})
}
