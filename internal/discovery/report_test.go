package discovery

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInventoryValidatesWholeDocument(t *testing.T) {
	for name, data := range map[string]string{
		"lone surrogate":       `{"openapi":"3.0.0","paths":{},"x-note":"\ud800"}`,
		"lone surrogate key":   `{"openapi":"3.0.0","paths":{},"x-note":{"\ud800":true}}`,
		"invalid empty path":   `{"openapi":"3.0.0","paths":{"//notes":{}}}`,
		"unused node overflow": `{"openapi":"3.0.0","paths":{},"x-note":[` + strings.Repeat("0,", 8191) + `0]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if report, err := BuildInventory([]byte(data), "openapi.json"); err == nil || report.ReportType != "" {
				t.Fatal("invalid document produced an inventory")
			}
		})
	}
}

func TestInventoryAcceptsFiniteDecimals(t *testing.T) {
	for format, data := range map[string][]byte{
		"json": []byte(`{"openapi":"3.0.0","paths":{},"x-note":[0.5,-0.0,1e-2]}`),
		"yaml": []byte("openapi: '3.0.0'\npaths: {}\nx-note: [0.5, -0.0, 1e-2]\n"),
	} {
		t.Run(format, func(t *testing.T) {
			if format == "yaml" {
				decoded, err := DecodeYAML(data)
				if err != nil {
					t.Fatal(err)
				}
				data = decoded
			}
			report, err := BuildInventory(data, "spec."+format)
			if err != nil || report.ReportType == "" || len(report.Operations) != 0 {
				t.Fatalf("valid decimals did not produce an empty inventory: %v", err)
			}
		})
	}
}

func TestInventoryReferencedPathItemHoldsSiblings(t *testing.T) {
	raw := []byte(`{
		"openapi": "3.1.0",
		"paths": {"/a": {"$ref": "#/components/pathItems/café", "summary": "info", "parameters": []}},
		"components": {"pathItems": {"café": {
			"future": {},
			"get": {"parameters": [{"in": "query", "name": "q", "schema": {"type": "string"}}]}
		}}}
	}`)
	report, err := BuildInventory(raw, "spec.json")
	if err != nil || len(report.Operations) != 1 || len(report.Held) != 2 {
		t.Fatalf("unexpected inventory: %+v, %v", report, err)
	}
	item := report.Operations[0]
	if item.Source.Pointer != "/paths/~1a" || item.Definition.Pointer != "/components/pathItems/café/get" ||
		item.Compatible || item.CompatibilityStatus != "unverified" || item.CompatibilityBlocker == nil ||
		item.CompatibilityBlocker.Source.Pointer != "/paths/~1a/parameters" ||
		item.CompatibilityBlocker.Reason != referenceSiblingHold {
		t.Fatalf("operation lost provenance or compatibility blocker: %+v", item)
	}
	if report.Held[0].Source.Pointer != "/components/pathItems/café/future" ||
		report.Held[1].Source.Pointer != "/paths/~1a/parameters" {
		t.Fatalf("unexpected held declarations: %+v", report.Held)
	}
}

func TestInventoryValidatesPathItemsWithoutOperations(t *testing.T) {
	for _, raw := range []string{
		`{"openapi":"3.1.0","paths":{"/a":{"parameters":[{}]}}}`,
		`{"openapi":"3.1.0","paths":{"/a":{"$ref":"other.json#/paths/a"}}}`,
		`{"openapi":"3.1.0","paths":{"/a":{"$ref":"#/paths/~1a"}}}`,
	} {
		if report, err := BuildInventory([]byte(raw), "spec.json"); err == nil || report.ReportType != "" {
			t.Fatalf("invalid path item produced an inventory: %s", raw)
		}
	}
	for _, raw := range []string{`{"openapi":"3.1.0"}`, `{"openapi":"3.0.01","paths":{}}`} {
		if report, err := BuildInventory([]byte(raw), "spec.json"); err != nil || len(report.Operations) != 0 {
			t.Fatalf("valid empty inventory rejected: %s: %v", raw, err)
		}
	}
}

func TestInventoryHoldsReferencedBooleanParameterSchema(t *testing.T) {
	raw := []byte(`{
		"openapi": "3.1.0",
		"paths": {"/a": {"parameters": [{"$ref": "#/components/parameters/Q", "summary": "info"}], "get": {}}},
		"components": {
			"parameters": {"Q": {"in": "query", "name": "q", "required": true, "schema": {"$ref": "#/components/schemas/B"}}},
			"schemas": {"B": false}
		}
	}`)
	report, err := BuildInventory(raw, "spec.json")
	if err != nil || len(report.Operations) != 1 || len(report.Held) != 1 {
		t.Fatalf("unexpected inventory: %+v, %v", report, err)
	}
	held := report.Held[0]
	if held.Source.Pointer != "/components/parameters/Q/schema" || held.Definition == nil ||
		held.Definition.Pointer != "/components/schemas/B" || held.Reason != booleanSchemaHold {
		t.Fatalf("unexpected schema provenance: %+v", held)
	}
	item := report.Operations[0]
	if item.Compatible || item.CompatibilityBlocker == nil || *item.CompatibilityBlocker != held {
		t.Fatalf("required boolean schema did not block compatibility: %+v", item)
	}
}

func TestInventoryBooleanSchemaHold(t *testing.T) {
	raw := []byte(`{"openapi":"3.1.0","paths":{"/fixture":{"post":{"requestBody":{"content":{"application/json":{"schema":false}}}}}}}`)
	report, err := BuildInventory(raw, "spec.json")
	if err != nil {
		t.Fatal(err)
	}
	const pointer = "/paths/~1fixture/post/requestBody/content/application~1json/schema"
	for _, item := range report.Held {
		if item.Source.Pointer == pointer && item.Definition != nil && item.Definition.Pointer == pointer && item.Reason == booleanSchemaHold {
			return
		}
	}
	t.Fatal("missing released boolean-schema hold and its provenance")
}

func TestInventoryLongNamesRetainReleasedIDs(t *testing.T) {
	first, second := strings.Repeat("&", 190000), strings.Repeat("<", 190000)
	data := []byte(`{"openapi":"3.0.4","paths":{"/fixture":{"get":{"parameters":[` +
		`{"in":"query","name":"` + first + `","schema":{"type":"string"}},` +
		`{"in":"query","name":"` + second + `","schema":{"type":"string"}}]}}}}`)
	report, err := BuildInventory(data, "spec.json")
	if err != nil || len(report.Operations) != 1 || len(report.Operations[0].Inputs) != 2 {
		t.Fatalf("bounded document was not inventoried: %v", err)
	}
	inputs := report.Operations[0].Inputs
	want := []string{"input-e5058994c73b8fea0d03c601d41645b4", "input-9fdf1de02620fefcec67f13c899fbf51"}
	for i, input := range inputs {
		if input.ID != want[i] {
			t.Fatalf("input %d ID = %s, want %s", i, input.ID, want[i])
		}
	}
	if got := identityString("<&\x7f😀\u2028"); got != `"<&\u007f\ud83d\ude00\u2028"` || !json.Valid([]byte(got)) {
		t.Fatalf("incorrect ASCII JSON = %s", got)
	}
}
