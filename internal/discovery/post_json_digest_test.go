package discovery

import (
	"bytes"
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

func TestPostJSONDefinitionDigestRejectsOverBudgetExpansion(t *testing.T) {
	spec := `{"openapi":"3.1.2","components":{"schemas":{"Shared":{"type":"string","description":"` +
		strings.Repeat("a", 550000) +
		`"}}},"paths":{"/items":{"post":{"requestBody":{"content":{"application/json":{"schema":` +
		`{"type":"object","properties":{"a":{"$ref":"#/components/schemas/Shared"},"b":{"$ref":"#/components/schemas/Shared"}}}` +
		`}}}}}}}`
	if report, _, err := BuildPostJSONInventory([]byte(spec), "openapi.json"); report != nil || !errors.Is(err, errPostWork) {
		t.Fatalf("over-budget expanded definition: report bytes=%d, err=%v", len(report), err)
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
