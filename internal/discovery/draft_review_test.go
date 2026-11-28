package discovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

const goldenDraftInput = "input-24a9c3cf0c3d01709121ac0d09079903"

func reviewFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../tests/" + path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func goldenDraft(t *testing.T) []byte {
	t.Helper()
	var golden struct {
		Drafts map[string]string `json:"draft_files"`
	}
	if err := json.Unmarshal(reviewFixture(t, "golden/cli/discover/drafts.json"), &golden); err != nil {
		t.Fatal(err)
	}
	return []byte(golden.Drafts["case-"+strings.TrimPrefix(goldenDraftInput, "input-")+".draft.toml"])
}

func TestBuildDraftReviewReleasedArtifact(t *testing.T) {
	const answers = `{"version":1,"expected_verdict":"not_detected","parameters":{"q":{"value":"fixture-baseline"}}}`
	spec := reviewFixture(t, "fixtures/discovery/openapi30.json")
	report, id, err := BuildDraftReview(spec, "openapi.json", goldenDraft(t), []byte(answers))
	if err != nil || id != goldenDraftInput {
		t.Fatalf("BuildDraftReview: id = %q, err = %v", id, err)
	}
	var golden struct {
		Report json.RawMessage `json:"report_json"`
	}
	if err := json.Unmarshal(reviewFixture(t, "golden/cli/review-draft/success.json"), &golden); err != nil {
		t.Fatal(err)
	}
	var compact, want bytes.Buffer
	if err := json.Compact(&compact, golden.Report); err != nil {
		t.Fatal(err)
	}
	if err := json.Indent(&want, compact.Bytes(), "", "  "); err != nil {
		t.Fatal(err)
	}
	want.WriteByte('\n')
	if !bytes.Equal(report, want.Bytes()) {
		t.Fatalf("report:\n%s\nwant:\n%s", report, &want)
	}
}

func TestBuildDraftReviewRejectsInvalidInputsWithoutEcho(t *testing.T) {
	const prefix = `{"version":1,"expected_verdict":"not_detected","parameters":`
	spec := reviewFixture(t, "fixtures/discovery/openapi30.json")
	draft := goldenDraft(t)
	for _, tc := range []struct {
		name, source string
		draft        []byte
		answers      string
		reason       string
	}{
		{"malformed draft", "openapi.json", []byte(`private_marker = [`), "", "Cannot read the draft"},
		{"stale draft source", "private_marker.json", draft, "", "stale or incompatible"},
		{"untrusted source label", "../private_marker.json", draft, "", "outside the current working directory"},
		{"stale input", "openapi.json", bytes.ReplaceAll(draft, []byte(goldenDraftInput), []byte("private_marker")), "", "missing or stale"},
		{"edited draft", "openapi.json", bytes.ReplaceAll(draft, []byte(`method = "GET"`), []byte(`method = "private_marker"`)), "", "stale or incompatible"},
		{"edited case ID", "openapi.json", bytes.ReplaceAll(draft, []byte(`id = "case-`), []byte(`id = "private_marker-`)), "", "stale or incompatible"},
		{"edited definition", "openapi.json", bytes.ReplaceAll(draft, []byte(`/components/parameters/q`), []byte(`/components/private_marker`)), "", "stale or incompatible"},
		{"comments change bytes", "openapi.json", append(bytes.Clone(draft), []byte("# private_marker\n")...), "", "stale or incompatible"},
		{"duplicate JSON", "openapi.json", draft, `{"private_marker":1,"private_marker":2}`, "unique keys"},
		{"float answer version", "openapi.json", draft, `{"version":1.0,"expected_verdict":"not_detected","parameters":{}}`, "Set version to 1"},
		{"bad verdict", "openapi.json", draft, `{"version":1,"expected_verdict":"private_marker","parameters":{}}`, "Explicitly set expected_verdict"},
		{"unknown query", "openapi.json", draft, prefix + `{"private_marker":{"omit":true}}}`, "Use only declared query names"},
		{"missing decision", "openapi.json", draft, prefix + `{}}`, "missing or invalid baseline decision"},
		{"null baseline", "openapi.json", draft, prefix + `{"q":{"value":null}}}`, "require concrete non-null values"},
		{"non-scalar baseline", "openapi.json", draft, prefix + `{"q":{"value":["private_marker"]}}}`, "Supply a concrete scalar value"},
		{"extra decision key", "openapi.json", draft, prefix + `{"q":{"value":"private_marker","value_sha256":"private_marker"}}}`, "invalid decision keys"},
		{"invalid omit", "openapi.json", draft, prefix + `{"q":{"omit":false}}}`, "invalid decision keys"},
		{"arbitrary pointer", "openapi.json", draft, prefix + `{"q":{"pointer":"/private_marker"}}}`, "not a supported explicit local baseline candidate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, id, err := BuildDraftReview(spec, tc.source, tc.draft, []byte(tc.answers))
			if report != nil || id != "" || err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.reason)) || strings.Contains(err.Error(), "private_marker") {
				t.Fatalf("report = %q, id = %q, err = %v", report, id, err)
			}
		})
	}
}

func TestBuildDraftReviewLocalCandidateProvenance(t *testing.T) {
	const parameter = "/components/parameters/q"
	const schema = "/components/schemas/Q"
	const literal = `"\u00e9\u007f\ud83d\ude00<&"`
	const source = "archive/<é😀>.json"
	const spec = `{
		"openapi":"3.1.2",
		"paths":{"/a":{"get":{"parameters":[
			{"$ref":"#/components/parameters/q"},
			{"name":"aux", "in":"query","schema":{"type":"string"}}
		]}}},
		"components":{
			"parameters":{"q":{"name":"q","in":"query","required":true,
				"example":"é\u007f😀<&",
				"examples":{
					"a/~%":{"value":"é\u007f😀<&"},
					"alias":{"$ref":"#%2Fcomponents%2Fexamples%2FAlias"},
					"external":{"$ref":"https://private_marker.invalid/examples.json"},
					"cyclic":{"$ref":"#/components/examples/Cycle"},
					"missing":{"$ref":"#/components/examples/private_marker"},
					"externalValue":{"externalValue":"private_marker","value":"private_marker"}
				},
				"schema":{"$ref":"#/components/schemas/Q"}
			}},
			"examples":{
				"Alias":{"$ref":"#/components/examples/E"},
				"E":{"value":"é\u007f😀<&"},
				"Cycle":{"$ref":"#/components/examples/Cycle"}
			},
			"schemas":{"Q":{"type":"string","example":"é\u007f😀<&", "examples":["é\u007f😀<&"],"default":"é\u007f😀<&","enum":["é\u007f😀<&"]}}
		}
	}`
	draft := strings.Replace(string(goldenDraft(t)), `file = "openapi.json"`, `file = "`+source+`"`, 1)
	draft = strings.Replace(draft, "[[query_parameters]]\nname = \"q\"\nrequired = false",
		"[[query_parameters]]\nname = \"aux\"\nrequired = false\n\n[[query_parameters]]\nname = \"q\"\nrequired = true", 1)
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(literal)))
	for _, tc := range []struct {
		pointer, canonical, reason string
	}{
		{parameter + "/example", parameter + "/example", ""},
		{parameter + "/examples/a~1~0%/value", parameter + "/examples/a~1~0%/value", ""},
		{parameter + "/examples/alias", "/components/examples/E/value", ""},
		{parameter + "/examples/alias/value", "/components/examples/E/value", ""},
		{"/components/examples/E/value", "/components/examples/E/value", ""},
		{schema + "/example", schema + "/example", ""},
		{schema + "/examples/0", schema + "/examples/0", ""},
		{schema + "/default", schema + "/default", ""},
		{schema + "/enum/0", schema + "/enum/0", ""},
		{schema + "/examples/00", "", "not a supported explicit local baseline candidate"},
		{parameter + "/schema/default", "", "not a supported explicit local baseline candidate"},
		{parameter + "/examples/external", "", "Bundle the spec"},
		{parameter + "/examples/cyclic/value", "", "Break the recursive reference chain"},
		{parameter + "/examples/missing/value", "", "Point to an existing declaration"},
		{parameter + "/examples/externalValue/value", "", "not a supported explicit local baseline candidate"},
	} {
		t.Run(tc.pointer, func(t *testing.T) {
			answers := fmt.Sprintf(`{"version":1,"expected_verdict":"inconclusive","parameters":{"q":{"pointer":%q,"value_sha256":%q},"aux":{"omit":true}}}`, tc.pointer, digest)
			report, id, err := BuildDraftReview([]byte(spec), source, []byte(draft), []byte(answers))
			if tc.reason != "" {
				if report != nil || id != "" || err == nil || !strings.Contains(err.Error(), tc.reason) || strings.Contains(err.Error(), "private_marker") {
					t.Fatalf("report = %q, id = %q, err = %v", report, id, err)
				}
				return
			}
			if err != nil || id != goldenDraftInput {
				t.Fatalf("id = %q, err = %v", id, err)
			}
			want := fmt.Sprintf(`{
  "expected_verdict": "inconclusive",
  "input_id": "%s",
  "parameters": {
    "aux": {
      "status": "omitted"
    },
    "q": {
      "source": {
        "file": "archive/<\u00e9\ud83d\ude00>.json",
        "pointer": "%s"
      },
      "status": "resolved",
      "value_sha256": "%s"
    }
  },
  "report_type": "discovery_draft_review",
  "schema_version": 1,
  "source": {
    "file": "archive/<\u00e9\ud83d\ude00>.json",
    "pointer": "/paths/~1a/get/parameters/0"
  }
}
`, goldenDraftInput, tc.canonical, digest)
			if string(report) != want {
				t.Fatalf("report:\n%s\nwant:\n%s", report, want)
			}
		})
	}
	for _, tc := range []struct{ name, decision, reason string }{
		{"required omit", `{"omit":true}`, "cannot be omitted"},
		{"stale value", `{"pointer":"` + schema + `/default","value_sha256":"private_marker"}`, "Stale baseline digest"},
		{"wrong digest type", `{"pointer":"` + schema + `/default","value_sha256":{}}`, "Stale baseline digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answers := `{"version":1,"expected_verdict":"vulnerable","parameters":{"q":` + tc.decision + `,"aux":{"omit":true}}}`
			report, id, err := BuildDraftReview([]byte(spec), source, []byte(draft), []byte(answers))
			if report != nil || id != "" || err == nil || !strings.Contains(err.Error(), tc.reason) || strings.Contains(err.Error(), "private_marker") {
				t.Fatalf("report = %q, id = %q, err = %v", report, id, err)
			}
		})
	}
}

func TestBuildDraftReviewCanonicalScalarDigests(t *testing.T) {
	spec := reviewFixture(t, "fixtures/discovery/openapi30.json")
	draft := goldenDraft(t)
	for _, tc := range []struct{ input, canonical string }{
		{`-0`, `0`},
		{`-0.0`, `-0.0`},
		{`1e0`, `1.0`},
		{`1e-5`, `1e-05`},
		{`100000000000000000000000000000000001`, `100000000000000000000000000000000001`},
		{`"\ud83d\ude00"`, `"\ud83d\ude00"`},
		{`true`, `true`},
	} {
		t.Run(tc.input, func(t *testing.T) {
			answers := `{"version":1,"expected_verdict":"not_detected","parameters":{"q":{"value":` + tc.input + `}}}`
			report, _, err := BuildDraftReview(spec, "openapi.json", draft, []byte(answers))
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(tc.canonical)))
			if err != nil || !bytes.Contains(report, []byte(`"value_sha256": "`+digest+`"`)) {
				t.Fatalf("report = %q, want digest %s, err = %v", report, digest, err)
			}
		})
	}
}

func TestBuildDraftReviewRejectsLoneSurrogateAnswer(t *testing.T) {
	const answers = `{"version":1,"expected_verdict":"not_detected","parameters":{"q":{"value":"\ud800"}}}`
	spec := reviewFixture(t, "fixtures/discovery/openapi30.json")
	report, id, err := BuildDraftReview(spec, "openapi.json", goldenDraft(t), []byte(answers))
	if report != nil || id != "" || err == nil || !strings.Contains(err.Error(), "Cannot read review answers") {
		t.Fatalf("non-scalar JSON answer produced review metadata: %q, %q, %v", report, id, err)
	}
}

func TestBuildDraftReviewReferenceLimits(t *testing.T) {
	const aliasSelection = "/components/parameters/q/examples/first/value"
	for _, tc := range []struct {
		name, selection string
		chains, hops    int
		wantLimit       bool
	}{
		{"hop budget fits", aliasSelection, 1, 24, false},
		{"hop budget exceeded", aliasSelection, 1, 25, true},
		{"work budget exceeded", "/components/examples/not-a-candidate/value", 175, 24, true},
		{"selected alias before other work", aliasSelection, 175, 24, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			references := map[string]any{"first": map[string]string{"$ref": "#/components/examples/E1"}}
			examples := map[string]any{"E" + fmt.Sprint(tc.hops): map[string]string{"value": "fixture"}}
			for i := 1; i < tc.hops; i++ {
				examples["E"+fmt.Sprint(i)] = map[string]string{"$ref": fmt.Sprintf("#/components/examples/E%d", i+1)}
			}
			for i := 1; i < tc.chains; i++ {
				references[fmt.Sprintf("alias%d", i)] = map[string]string{"$ref": "#/components/examples/E1"}
			}
			refs, err := json.Marshal(references)
			if err != nil {
				t.Fatal(err)
			}
			targets, err := json.Marshal(examples)
			if err != nil {
				t.Fatal(err)
			}
			spec := fmt.Sprintf(`{"openapi":"3.1.0","paths":{"/a":{"get":{"parameters":[{"$ref":"#/components/parameters/q"}]}}},
				"components":{"parameters":{"q":{"name":"q","in":"query","schema":{"type":"string"},"examples":%s}},"examples":%s}}`, refs, targets)
			answers := fmt.Sprintf(`{"version":1,"expected_verdict":"not_detected","parameters":{"q":{"pointer":%q}}}`, tc.selection)
			report, _, err := BuildDraftReview([]byte(spec), "openapi.json", goldenDraft(t), []byte(answers))
			if tc.wantLimit {
				if report != nil || err != errReviewRefLimit {
					t.Fatalf("report = %q, err = %v", report, err)
				}
			} else if err != nil || !strings.Contains(string(report), fmt.Sprintf(`"pointer": "/components/examples/E%d/value"`, tc.hops)) {
				t.Fatalf("report = %q, err = %v", report, err)
			}
		})
	}
}

func TestBuildDraftReviewBothExportSpellings(t *testing.T) {
	const source = "one\u2028two\u2029three.json"
	const answers = `{"version":1,"expected_verdict":"not_detected","parameters":{"q":{"omit":true}}}`
	spec := reviewFixture(t, "fixtures/discovery/openapi30.json")
	for _, label := range []string{source, `one\u2028two\u2029three.json`} {
		draft := bytes.Replace(goldenDraft(t), []byte(`file = "openapi.json"`), []byte(`file = "`+label+`"`), 1)
		report, _, err := BuildDraftReview(spec, source, draft, []byte(answers))
		if err != nil || !bytes.Contains(report, []byte(`"file": "one\u2028two\u2029three.json"`)) {
			t.Fatalf("report = %q, err = %v", report, err)
		}
	}
}
