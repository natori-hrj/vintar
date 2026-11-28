package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/natori-hrj/vintar/internal/strictjson"
)

func TestPostJSONArtifactWriterHasIndependentSizeLimit(t *testing.T) {
	// Inventory output can exceed the strict JSON input limit, as in the
	// released writer. It still must stop at the inventory-specific limit.
	row := map[string]any{"metadata": strings.Repeat("a", (1<<20)+1)}
	data, err := marshalPostArtifact(row, postMaxReport)
	if err != nil || len(data) <= 1<<20 || !json.Valid(data) {
		t.Fatalf("inventory writer applied the strict input limit: bytes=%d, err=%v", len(data), err)
	}
	row["metadata"] = strings.Repeat("a", postMaxReport)
	if data, err := marshalPostArtifact(row, postMaxReport); data != nil || !errors.Is(err, ErrPostArtifactSize) {
		t.Fatalf("oversized artifact was not consistently rejected: bytes=%d, err=%v", len(data), err)
	}
}

const postInventoryGoldenSpec = `{
  "openapi":"3.1.2","paths":{"/items":{"post":{
    "operationId":"createItem",
    "requestBody":{"content":{"application/json":{"schema":{
      "type":"object","required":["name"],"properties":{"name":{"type":"string"}}
    }}}}
  }}}
}`

func postGolden(t *testing.T, path string, key string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../tests/golden/cli/" + path)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	return fields[key]
}

func assertPostJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	a, err := strictjson.Canonicalize(got)
	if err != nil {
		t.Fatal(err)
	}
	b, err := strictjson.Canonicalize(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("artifact differs\n got: %s\nwant: %s", a, b)
	}
}

func TestPostJSONInventoryReleaseGolden(t *testing.T) {
	report, summary, err := BuildPostJSONInventory([]byte(postInventoryGoldenSpec), "fixtures/spec.json")
	if err != nil {
		t.Fatal(err)
	}
	const golden = "inventory-post-json/success.json"
	assertPostJSONEqual(t, report, postGolden(t, golden, "report_json"))
	var want string
	if err := json.Unmarshal(postGolden(t, golden, "stdout"), &want); err != nil || summary != want {
		t.Fatalf("summary = %q, want %q", summary, want)
	}
}

func TestPostJSONInventoryReferenceDiagnostics(t *testing.T) {
	const schema = `"schema":{
      "type":"object","required":["name"],"properties":{"name":{"type":"string"}}
    }`
	for _, tc := range []struct {
		golden     string
		newSchema  string
		components string
	}{
		{"external-ref", `"schema":{"$ref":"external.json#/Item"}`, ""},
		{"cyclic-ref", `"schema":{"$ref":"#/components/schemas/Node"}`,
			`"components":{"schemas":{"Node":{"type":"object","properties":{"child":{"$ref":"#/components/schemas/Node"}}}}},`},
	} {
		t.Run(tc.golden, func(t *testing.T) {
			spec := strings.Replace(postInventoryGoldenSpec, schema, tc.newSchema, 1)
			spec = strings.Replace(spec, `"openapi"`, tc.components+`"openapi"`, 1)
			got, _, err := BuildPostJSONInventory([]byte(spec), "spec.json")
			if err != nil {
				t.Fatal(err)
			}
			assertPostJSONEqual(t, got, postGolden(t, "inventory-post-json/"+tc.golden+".json", "report_json"))
		})
	}
}

func TestPostJSONInventoryMixedMediaReferencesAndAuth(t *testing.T) {
	const spec = `{
      "openapi":"3.1.0","security":[{"key":["PRIVATE-SCOPE"]},{},{"key":[]}],
      "paths":{"/body":{"$ref":"#/components/pathItems/Body"},"/other":{"post":{}}},
      "components":{
        "securitySchemes":{"key":{"type":"apiKey","name":"PRIVATE-HEADER"}},
        "pathItems":{"Body":{"post":{"requestBody":{"$ref":"#/components/requestBodies/Body"}}}},
        "requestBodies":{"Body":{"content":{" Application/JSON ;charset=utf-8":{
          "schema":{"properties":{"*":{"$ref":"#/components/schemas/Text","description":"PRIVATE-NOTE"}},
          "items":{"$ref":"#/components/schemas/Text"}}},
          "application/vnd.example+json":{"schema":{"type":"integer"}}
        }}},
        "schemas":{"Text":{"type":"string","default":"PRIVATE-DEFAULT"}}
      }
    }`
	report, _, err := BuildPostJSONInventory([]byte(spec), "spec.json")
	if err != nil {
		t.Fatal(err)
	}
	repeat, _, err := BuildPostJSONInventory([]byte(spec), "another.json")
	if err != nil || !bytes.Equal(report, repeat) || bytes.Contains(report, []byte("PRIVATE-")) {
		t.Fatal("report is nondeterministic or discloses non-metadata")
	}
	var out postInventory
	if err := json.Unmarshal(report, &out); err != nil {
		t.Fatal(err)
	}
	if out.Counts.WithoutJSON != 1 || len(out.Operations) != 1 {
		t.Fatal("incorrect operation counts")
	}
	op := out.Operations[0]
	if op.Path != "/body" || op.Operation != "/components/pathItems/Body/post" ||
		op.Body != "/components/requestBodies/Body/content/ Application~1JSON ;charset=utf-8" ||
		op.Auth.Source != "global" || !op.Auth.Public || len(op.Auth.Alternatives) != 2 ||
		len(op.Fields) != 2 || len(op.Candidates) != 2 ||
		op.Fields[0].Pointer != "/*" || op.Fields[1].Pointer != "/*" ||
		op.Fields[0].Definition != "/components/schemas/Text" || op.Fields[1].Definition != "/components/schemas/Text" ||
		len(op.Fields[0].Stars) != 0 || len(op.Fields[1].Stars) != 1 || op.Candidates[0].ID == op.Candidates[1].ID {
		t.Fatalf("unexpected inventory metadata: %s", report)
	}
}

func TestPostJSONInventoryRejectsMalformedReferences(t *testing.T) {
	spec := strings.Replace(postInventoryGoldenSpec, `{"type":"string"}`, `{"$ref":"#/missing/PRIVATE-POINTER"}`, 1)
	if report, summary, err := BuildPostJSONInventory([]byte(spec), "spec.json"); err == nil ||
		bytes.Contains([]byte(err.Error()), []byte("PRIVATE-POINTER")) || report != nil || summary != "" {
		t.Fatalf("expected redacted failure, got %v", err)
	}
}

func TestPostJSONInventoryOperationDigestBindsResolvedValues(t *testing.T) {
	const base = `{"openapi":"3.1.0","components":{"schemas":{"T":{"type":"string","default":1.0}}},
    "paths":{"/items":{"post":{"requestBody":{"content":{"application/json":{
      "schema":{"$ref":"#/components/schemas/T"}, "example":{"$ref":"opaque-identifier"}
    }}}}}}}`
	find := func(spec string) postCandidate {
		t.Helper()
		inventory, _, err := analyzePostJSON([]byte(spec))
		if err != nil {
			t.Fatal(err)
		}
		if len(inventory.Operations) != 1 || len(inventory.Operations[0].Candidates) != 1 {
			t.Fatal("expected one candidate")
		}
		return inventory.Operations[0].Candidates[0]
	}
	original := find(base)
	for _, changed := range []string{
		strings.Replace(base, `"default":1.0`, `"default":1`, 1),
		strings.Replace(base, "opaque-identifier", "updated-identifier", 1),
	} {
		next := find(changed)
		if next.ID != original.ID || next.Digest == original.Digest {
			t.Fatal("expected stable location ID and changed definition digest")
		}
	}
}
