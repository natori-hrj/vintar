package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const postReviewGoldenSpec = `{"openapi":"3.1.2","paths":{"/items":{"post":{
  "requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{
    "orders":{"type":"array","items":{"type":"object","properties":{"sku":{"type":"string"}}}}
  }}}}}
}}}}`

func postTestMarshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func postReviewAnswers(t *testing.T, spec, pointer string, value json.RawMessage) ([]byte, map[string]any) {
	t.Helper()
	raw, _, err := BuildPostJSONInventory([]byte(spec), "openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory postInventory
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Operations) != 1 || len(inventory.Operations[0].Candidates) != 1 {
		t.Fatalf("expected one POST inventory candidate, got %s", raw)
	}
	op := inventory.Operations[0]
	candidate := op.Candidates[0]
	field := op.Fields[len(op.Fields)-1]
	return raw, map[string]any{
		"version": 1, "candidate_id": candidate.ID, "identity_id": "reviewed-user",
		"operation_definition_sha256": candidate.Digest,
		"schema_pointer":              field.Schema, "schema_definition_pointer": field.Definition,
		"baseline": map[string]any{"value": value,
			"body_sha256": "8b672bf71f217f9211c2b86ac9a0ca4049ebbac956e13ffd2af8200cf5e953b2"},
		"concrete_pointer": pointer, "operation_approved": true,
		"side_effect": map[string]any{"class": "no_side_effect", "confirmed": true},
		"environment": map[string]any{"class": "isolated_test", "confirmed": true},
	}
}

func TestPostJSONReviewReleaseGolden(t *testing.T) {
	value := json.RawMessage(`{"orders":[{"sku":"PRIVATE-BODY-SENTINEL-74d9"}]}`)
	inventory, answers := postReviewAnswers(t, postReviewGoldenSpec, "/orders/0/sku", value)
	report, id, err := BuildPostJSONReview([]byte(postReviewGoldenSpec), "openapi.json", inventory, postTestMarshal(t, answers))
	if err != nil {
		t.Fatal(err)
	}
	if id != "post-json-candidate-5e0e940b7970259d433021a5897ed4ea" ||
		bytes.Contains(report, []byte("PRIVATE-BODY-SENTINEL")) {
		t.Fatal("unexpected candidate ID or unredacted baseline")
	}
	assertPostJSONEqual(t, report, postGolden(t, "review-post-json/success.json", "review_json"))
}

func TestPostJSONReviewChecksProvenanceAndDecisions(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any, *[]byte)
		want string
	}{
		{"edited inventory", func(_ map[string]any, inv *[]byte) {
			*inv = bytes.Replace(*inv, []byte(`"unapproved"`), []byte(`"approved"`), 1)
		}, "does not match"},
		{"wrong schema pointer", func(a map[string]any, _ *[]byte) { a["schema_pointer"] = "/other" }, "does not match"},
		{"operation digest", func(a map[string]any, _ *[]byte) { a["operation_definition_sha256"] = "obsolete" }, "operation definition changed"},
		{"unknown decision", func(a map[string]any, _ *[]byte) { a["extra"] = true }, "only the documented"},
		{"numeric confirmation", func(a map[string]any, _ *[]byte) { a["operation_approved"] = 1 }, "must be JSON true"},
		{"wildcard unresolved", func(a map[string]any, _ *[]byte) { a["concrete_pointer"] = "/orders/*/sku" }, "invalid array selection"},
		{"noncanonical index", func(a map[string]any, _ *[]byte) { a["concrete_pointer"] = "/orders/00/sku" }, "invalid array selection"},
		{"stale digest", func(a map[string]any, _ *[]byte) {
			a["baseline"].(map[string]any)["body_sha256"] = "obsolete"
		}, "Baseline body digest does not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inventory, answers := postReviewAnswers(t, postReviewGoldenSpec, "/orders/0/sku",
				json.RawMessage(`{"orders":[{"sku":"PRIVATE-BODY-SENTINEL-74d9"}]}`))
			tc.edit(answers, &inventory)
			report, id, err := BuildPostJSONReview([]byte(postReviewGoldenSpec), "openapi.json", inventory, postTestMarshal(t, answers))
			if report != nil || id != "" || err == nil || !strings.Contains(err.Error(), tc.want) ||
				strings.Contains(err.Error(), "PRIVATE-BODY-SENTINEL") {
				t.Fatalf("not a redacted rejection: %v", err)
			}
		})
	}
}

func TestPostJSONReviewAcceptsOnlyReachableBundledExamples(t *testing.T) {
	const spec = `{"openapi":"3.1.0","components":{"examples":{
      "sample":{"value":{"orders":[{"sku":"PRIVATE-BODY-SENTINEL-74d9"}]}},
      "unrelated":{"value":{"orders":[{"sku":"PRIVATE-BODY-SENTINEL-74d9"}]}}
    }},"paths":{"/items":{"post":{"requestBody":{"content":{"application/json":{
      "schema":{"properties":{"orders":{"items":{"properties":{"sku":{"type":"string"}}}}}},
      "examples":{"linked":{"$ref":"#/components/examples/sample"}}
    }}}}}}}`
	inventory, answers := postReviewAnswers(t, spec, "/orders/0/sku", nil)
	base := answers["baseline"].(map[string]any)
	delete(base, "value")
	for _, pointer := range []string{
		"/components/examples/sample/value",
		"/paths/~1items/post/requestBody/content/application~1json/examples/linked/value",
	} {
		base["pointer"] = pointer
		report, _, err := BuildPostJSONReview([]byte(spec), "fixtures/openapi.json", inventory, postTestMarshal(t, answers))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(report, []byte(`"file": "openapi.json"`)) ||
			!bytes.Contains(report, []byte(pointer)) || bytes.Contains(report, []byte("PRIVATE-BODY-SENTINEL")) {
			t.Fatal("incorrect or unredacted example provenance")
		}
	}
	base["pointer"] = "/components/examples/unrelated/value"
	if _, _, err := BuildPostJSONReview([]byte(spec), "openapi.json", inventory, postTestMarshal(t, answers)); !errors.Is(err, errPostExample) {
		t.Fatalf("unreachable example: %v", err)
	}
}

func TestPostJSONReviewDistinguishesArrayAndLiteralStar(t *testing.T) {
	array := []any{map[string]any{"*": "redacted"}}
	field := postField{Pointer: "/*/*", Stars: []int{1}}
	if err := validatePostReviewLeaf(field, "/0/*", array); err != nil {
		t.Fatal(err)
	}
	if err := validatePostReviewLeaf(field, "/0/*", map[string]any{"0": array[0]}); err == nil {
		t.Fatal("numeric object key masqueraded as an array index")
	}
}
