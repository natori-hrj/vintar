package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPostJSONDefinitionDigestUnicodeExpansion(t *testing.T) {
	const prefix = `{"openapi":"3.1.2","paths":{"/items":{"post":{"description":"`
	const suffix = `","requestBody":{"content":{"application/json":{"schema":{"type":"string"}}}}}}}}`
	const size = 540154
	spec := prefix + strings.Repeat("\u2028", 180000) + suffix
	spec += strings.Repeat(" ", size-len(spec))

	// Reviewer-supplied baseline tokens still use strict parsing, including
	// preservation of lone surrogates (unlike OpenAPI spec scalar values).
	baseline := json.RawMessage(`"PRIVATE-BODY-SENTINEL\ud800"`)
	inventory, answers := postReviewAnswers(t, spec, "", baseline)
	const released = "75f7b6c2492a6909cc1b1c5c85364941b0d6ead6076bf35c5898811bdd8cb031"
	if got := answers["operation_definition_sha256"]; got != released {
		t.Fatalf("inventory digest = %v, want %s", got, released)
	}
	answers["baseline"].(map[string]any)["body_sha256"] = fmt.Sprintf("%x", sha256.Sum256(baseline))
	report, _, err := BuildPostJSONReview([]byte(spec), "openapi.json", inventory, postTestMarshal(t, answers))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(report, []byte(released)) || bytes.Contains(report, []byte("PRIVATE-BODY-SENTINEL")) ||
		bytes.Contains(inventory, []byte(`\u2028`)) || bytes.Contains(report, []byte(`\u2028`)) {
		t.Fatal("review lost the released digest or an artifact leaked input text")
	}
}

func TestPostJSONDefinitionDigestAcceptsSharedLargeContent(t *testing.T) {
	spec := `{"openapi":"3.1.2","components":{"schemas":{"Shared":{"type":"string","description":"` +
		strings.Repeat("a", 550000) +
		`"}}},"paths":{"/items":{"post":{"requestBody":{"content":{"application/json":{"schema":` +
		`{"type":"object","properties":{"a":{"$ref":"#/components/schemas/Shared"},"b":{"$ref":"#/components/schemas/Shared"}}}` +
		`}}}}}}}`
	if report, _, err := BuildPostJSONInventory([]byte(spec), "openapi.json"); len(report) == 0 || err != nil {
		t.Fatalf("shared definition: report bytes=%d, err=%v", len(report), err)
	}
}

func TestPostJSONDefinitionDigestNumericExpansion(t *testing.T) {
	spec := `{"openapi":"3.1.2","paths":{"/items":{"post":{"description":"` +
		strings.Repeat("a", 1_047_000) + `","x-n":[` + strings.Repeat("1e15,", 127) + `1e15],` +
		`"requestBody":{"content":{"application/json":{"schema":{"type":"string"}}}}}}}}`
	const released = "1a79366dcf92d787788f31c71c6708468271f8872928ff2527ccd878f4cc2d79"
	body := json.RawMessage(`"offline"`)
	inventory, answers := postReviewAnswers(t, spec, "", body)
	if answers["operation_definition_sha256"] != released {
		t.Fatalf("got %v, want %s", answers["operation_definition_sha256"], released)
	}
	answers["baseline"].(map[string]any)["body_sha256"] = fmt.Sprintf("%x", sha256.Sum256(body))
	report, _, err := BuildPostJSONReview([]byte(spec), "openapi.json", inventory, postTestMarshal(t, answers))
	if err != nil || !bytes.Contains(report, []byte(released)) {
		t.Fatalf("review did not retain the released digest: %v", err)
	}
}

func TestPostJSONDigestAtYAMLSpecCeiling(t *testing.T) {
	prefix := "openapi: 3.1.2\npaths:\n  /items:\n    post:\n      description: \""
	suffix := "\"\n      requestBody:\n        content:\n          application/json:\n            schema: {type: string}\n"
	spec := []byte(prefix + strings.Repeat(`\L`, 180_000) + suffix)
	spec = append(spec, bytes.Repeat([]byte(" "), (1<<20)-len(spec))...)
	report, _, err := BuildPostJSONInventoryContext(t.Context(), spec, "openapi.yaml")
	const released = "75f7b6c2492a6909cc1b1c5c85364941b0d6ead6076bf35c5898811bdd8cb031"
	if err != nil || !bytes.Contains(report, []byte(released)) {
		t.Fatalf("typed YAML did not retain the released digest: %v", err)
	}
	if report, _, err := BuildPostJSONInventoryContext(t.Context(), append(spec, '\n'), "openapi.yaml"); report != nil || err == nil {
		t.Fatal("accepted oversized YAML")
	}
}

func TestPostJSONBaselineBodyByteLimit(t *testing.T) {
	value := strings.Repeat("\u2028", 174762) + "aa"
	if _, err := postBaselineDigest(t.Context(), value); err != nil {
		t.Fatal(err)
	}
	if digest, err := postBaselineDigest(t.Context(), value+"a"); digest != "" || !errors.Is(err, errPostBaseline) {
		t.Fatalf("over limit: digest=%q err=%v", digest, err)
	}
}

func TestPostJSONDefinitionCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	report, _, err := BuildPostJSONInventoryContext(ctx, []byte(`{}`), "openapi.json")
	if report != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("inventory on cancellation: report=%s err=%v", report, err)
	}
}

func postDefinitionFixture(levels, branches, operations int, description string) []byte {
	ref := func(i int) map[string]any { return map[string]any{"$ref": fmt.Sprintf("#/components/schemas/S%d", i)} }
	schemas := map[string]any{"S0": map[string]any{"type": "string", "description": description}}
	for i := 1; i <= levels; i++ {
		if branches == 1 {
			schemas[fmt.Sprintf("S%d", i)] = ref(i - 1)
			continue
		}
		refs := make([]any, branches)
		for j := range refs {
			refs[j] = ref(i - 1)
		}
		schemas[fmt.Sprintf("S%d", i)] = map[string]any{"allOf": refs}
	}
	paths := make(map[string]any)
	for i := range operations {
		path := fmt.Sprintf("/items-%03d", i)
		if operations == 1 {
			path = "/items"
		}
		paths[path] = map[string]any{"post": map[string]any{
			"requestBody": map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"type": "string"}}}},
			"responses": map[string]any{"200": map[string]any{
				"description": "ok", "content": map[string]any{"application/json": map[string]any{"schema": ref(levels)}},
			}},
		}}
	}
	data, err := json.Marshal(map[string]any{"openapi": "3.1.2", "paths": paths, "components": map[string]any{"schemas": schemas}})
	if err != nil {
		panic(err)
	}
	return data
}

func TestPostJSONDefinitionResourceEnvelope(t *testing.T) {
	fixture := postDefinitionFixture(12, 2, 1, strings.Repeat("\x7f", 256))
	report, _, err := BuildPostJSONInventory(fixture, "openapi.json")
	const released = "aed09506c088b1f1138bc0ad61f7c5ec7414a225b2fd1773c32c8b8b54f9c07d"
	if err != nil || !bytes.Contains(report, []byte(released)) {
		t.Fatalf("branching fixture lost released digest: %v", err)
	}
	for _, tc := range []struct {
		name                  string
		levels, branches, ops int
		description           string
		fail                  bool
	}{
		{"cumulative within", 8, 2, 3, strings.Repeat("a", 16<<10), false},
		{"cumulative over", 8, 2, 4, strings.Repeat("a", 16<<10), true},
		{"reference depth at", 127, 1, 1, "", false},
		{"reference depth above", 128, 1, 1, "", true},
		{"visit count below", 13, 2, 1, "", false},
		{"visit count above", 14, 2, 1, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := postDefinitionFixture(tc.levels, tc.branches, tc.ops, tc.description)
			report, _, err := BuildPostJSONInventory(spec, "openapi.json")
			if tc.fail {
				if report != nil || !errors.Is(err, ErrPostDefinitionLimit) {
					t.Fatalf("over limit: report bytes=%d err=%v", len(report), err)
				}
			} else if len(report) == 0 || err != nil {
				t.Fatalf("within limit: report bytes=%d err=%v", len(report), err)
			}
		})
	}
}

func TestPostJSONDefinitionExactLimits(t *testing.T) {
	spec := postDefinitionFixture(2, 2, 1, "offline")
	_, measured, err := analyzePostSpec(t.Context(), spec, "openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	refRoot := measured.root["paths"].(map[string]any)["/items"].(map[string]any)
	operation := refRoot["post"].(map[string]any)
	exact := postDefinitionBudget{
		ctx: t.Context(), references: postDefinitionReferences - measured.definitions.references,
		bytes: postDefinitionBytes - measured.definitions.bytes, work: postDefinitionWork - measured.definitions.work,
	}
	measured.definitions = exact
	digest, err := measured.operationDigest(operation, "/paths/~1items/post", refRoot, "/paths/~1items", nil)
	if err != nil || digest == "" || measured.definitions.bytes != 0 ||
		measured.definitions.references != 0 || measured.definitions.work != 0 {
		t.Fatalf("exact boundary: remaining=%+v err=%v", measured.definitions, err)
	}
	for _, bound := range []string{"bytes", "work", "references"} {
		budget := exact
		switch bound {
		case "bytes":
			budget.bytes--
		case "work":
			budget.work--
		case "references":
			budget.references--
		}
		measured.definitions = budget
		digest, err := measured.operationDigest(operation, "/paths/~1items/post", refRoot, "/paths/~1items", nil)
		if digest != "" || !errors.Is(err, ErrPostDefinitionLimit) {
			t.Errorf("%s over limit: digest=%q err=%v", bound, digest, err)
		}
	}
}

func BenchmarkPostJSONDefinition(b *testing.B) {
	for _, tc := range []struct {
		name                         string
		levels, branches, operations int
		description                  string
	}{
		{"short", 0, 1, 1, "offline"},
		{"unicode", 0, 1, 1, strings.Repeat("\u2028", 180000)},
		{"branching", 12, 2, 1, strings.Repeat("\x7f", 256)},
		{"many-references", 13, 2, 1, ""},
		{"cumulative", 8, 2, 3, strings.Repeat("a", 16<<10)},
		{"dense-values", 9, 2, 1, "dense-sentinel"},
		{"key-comparisons", 0, 1, 1, "sort-sentinel"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			spec := postDefinitionFixture(tc.levels, tc.branches, tc.operations, tc.description)
			switch tc.name {
			case "unicode":
				spec = bytes.ReplaceAll(spec, []byte(`\u2028`), []byte("\u2028"))
			case "dense-values":
				spec = bytes.Replace(spec, []byte(`"description":"dense-sentinel"`),
					[]byte(`"x-payload":[`+strings.Repeat(`"",`, 7000)+`""]`), 1)
			case "key-comparisons":
				fields := make(map[string]any)
				prefix := strings.Repeat("k", 380)
				for i := range 1000 {
					fields[fmt.Sprintf("%s%04d", prefix, i)] = ""
				}
				raw, err := json.Marshal(fields)
				if err != nil {
					b.Fatal(err)
				}
				spec = bytes.Replace(spec, []byte(`"description":"sort-sentinel"`),
					append([]byte(`"x-payload":`), raw...), 1)
			}
			_, d, err := analyzePostSpec(b.Context(), spec, "openapi.json")
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(postDefinitionBytes - d.definitions.bytes))
			for b.Loop() {
				if _, _, err := BuildPostJSONInventoryContext(b.Context(), spec, "openapi.json"); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(postDefinitionWork-d.definitions.work), "work/op")
			b.ReportMetric(float64(postDefinitionReferences-d.definitions.references), "refs/op")
		})
	}
}
func TestPostJSONDigestAtPublicSpecCeiling(t *testing.T) {
	const prefix = `{"openapi": "3.1.2", "paths": {"/items": {"post": {"description": "`
	const suffix = `", "requestBody": {"content": {"application/json": {"schema": {"type": "string"}}}}}}}}`
	const limit = 1 << 20
	const released = "b731f7d5810131506db4de12e10f38ea9f55528d2cd8b59ddd6042dfb87c5a9f"
	spec := prefix + strings.Repeat("a", limit-len(prefix)-len(suffix)) + suffix
	report, _, err := BuildPostJSONInventory([]byte(spec), "openapi.json")
	if err != nil || !bytes.Contains(report, []byte(released)) {
		t.Fatalf("the exact input boundary no longer yields the released digest: %v", err)
	}
	report, _, err = BuildPostJSONInventory([]byte(spec+"\n"), "openapi.json")
	if err == nil || report != nil {
		t.Fatal("serialized input above the public limit was accepted")
	}
}
