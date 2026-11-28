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
