package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/natori-hrj/vintar/internal/strictjson"
)

func TestDecodeYAMLScalars(t *testing.T) {
	const data = "\ufeff" + `---
scalars:
  [null, true, false, -0, 12, 1.0, -2.3e+4, 1E-9999, "null", 'true',
   Null, TRUE, False, yes, no, on, off, 2026-01-02, 01, 0x10, 0o17,
   1_000, +1, .5, 1., ~, .inf, .nan, 1:30, "λ"]
blank:
empty: [[], {}]
literal: |-
  true
folded: >-
  null
punctuation: text ! & * # ! in comment
quoted: "! foo"
<<value: <<
"<<": keep
01: leading zero
Null: upper case
...
# trailing comment
`
	const want = `{"01":"leading zero","<<":"keep","<<value":"<<","Null":"upper case","blank":"","empty":[[],{}],"folded":"null","literal":"true","punctuation":"text ! & *","quoted":"! foo","scalars":[null,true,false,-0,12,1.0,-2.3e+4,1E-9999,"null","true","Null","TRUE","False","yes","no","on","off","2026-01-02","01","0x10","0o17","1_000","+1",".5","1.","~",".inf",".nan","1:30","λ"]}`
	got, err := DecodeYAML([]byte(data))
	if err != nil || string(got) != want {
		t.Fatalf("DecodeYAML() = %s, %v; want %s", got, err, want)
	}
	got, err = DecodeYAML([]byte("---\n...\n"))
	if err != nil || string(got) != `""` {
		t.Fatalf("explicit empty document = %s, %v; want an empty string", got, err)
	}
}

func TestDecodeYAMLRejectsRestrictedSyntax(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        error
	}{
		{"empty stream", "# comment\n", errYAMLEmpty},
		{"multiple documents", "---\na: b\n...\n---\nx: y\n", errYAMLMultiple},
		{"trailing broken document", "---\na: b\n---\n[source-marker\n", errYAMLSyntax},
		{"invalid UTF-8", "x: \xff", errYAMLUTF8},
		{"UTF-16", "\xff\xfex\x00", errYAMLUTF8},
		{"escaped surrogate", `x: "\uD800"`, errYAMLSyntax},
		{"malformed", "x: [source-marker\n", errYAMLSyntax},
		{"anchor", "x: &source-marker value\n", errYAMLAnchor},
		{"anchor on key", "&key x: value\n", errYAMLAnchor},
		{"alias with anchor", "first: &a value\nsecond: *a\n", errYAMLAnchor},
		{"unknown alias", "x: *source-marker\n", errYAMLSyntax},
		{"tag on scalar", "x: !!str source-marker\n", errYAMLTag},
		{"tag on flow sequence", "x: !!seq []\n", errYAMLTag},
		{"tag on block mapping", "x: !!map\n  child: value\n", errYAMLTag},
		{"tag on key", "{!!str 123: value}", errYAMLTag},
		{"custom tag", "x: !source-marker value\n", errYAMLTag},
		{"non-specific scalar", "x: ! value\n", errYAMLTag},
		{"non-specific empty scalar", "x: !\n", errYAMLTag},
		{"non-specific sequence", "x: ! []\n", errYAMLTag},
		{"non-specific block map", "x: !\n  child: value\n", errYAMLTag},
		{"non-specific explicit key", "? ! key\n: value\n", errYAMLTag},
		{"non-specific flow key", "{! key: value}", errYAMLTag},
		{"non-specific UTF-8 column", "{αβ: ! value}", errYAMLTag},
		{"non-specific CRLF", "a: value\r\nb: ! true\r\n", errYAMLTag},
		{"non-specific NEL", "a: value\u0085b: ! true\n", errYAMLTag},
		{"non-specific LS", "a: value\u2028b: ! true\n", errYAMLTag},
		{"non-specific initial BOM", "\ufeff! []\n", errYAMLTag},
		{"plain merge", "<<: {}\n", errYAMLMerge},
		{"duplicate decoded keys", "source-marker: 1\n\"source-\\u006darker\": 2\n", errYAMLDuplicate},
		{"nested duplicate", "x: {a: null, 'a': false}\n", errYAMLDuplicate},
		{"sequence key", "? [1, 2]\n: value\n", errYAMLKey},
		{"mapping key", "? {a: b}\n: value\n", errYAMLKey},
		{"integer key", "-10: value\n", errYAMLKey},
		{"decimal key", "2.5e2: value\n", errYAMLKey},
		{"Boolean key", "false: value\n", errYAMLKey},
		{"null key", "null: value\n", errYAMLKey},
		{"float overflow", "x: -1.2e9999\n", errYAMLNumber},
		{"integer overflow", "x: -" + strings.Repeat("1", 4301), errYAMLNumber},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeYAML([]byte(tc.input))
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("DecodeYAML() = %s, %v; want nil and %v", got, err, tc.want)
			}
			if strings.Contains(err.Error(), "source-marker") {
				t.Fatal("diagnostic echoed source text")
			}
		})
	}
}

func TestDecodeYAMLBounds(t *testing.T) {
	const prefix = "a: b\n#"
	for _, bound := range []struct {
		name string
		max  int
		make func(int) string
		err  error
	}{
		{"bytes", maxYAMLBytes, func(n int) string {
			return prefix + strings.Repeat(".", n-len(prefix))
		}, errYAMLSize},
		{"depth", maxYAMLDepth, func(n int) string {
			return strings.Repeat("[", n) + "0" + strings.Repeat("]", n)
		}, errYAMLDepth},
		{"sequence nodes", maxYAMLNodes, func(n int) string {
			return strings.Repeat("- 0\n", n-1)
		}, errYAMLNodes},
		{"mapping nodes", maxYAMLNodes, func(n int) string {
			var doc strings.Builder
			for i := 1; i < n; i++ {
				fmt.Fprintf(&doc, "k%d: 0\n", i)
			}
			return doc.String()
		}, errYAMLNodes},
	} {
		t.Run(bound.name, func(t *testing.T) {
			got, err := DecodeYAML([]byte(bound.make(bound.max)))
			if err != nil || !json.Valid(got) {
				t.Fatalf("at limit: invalid JSON or error %v", err)
			}
			got, err = DecodeYAML([]byte(bound.make(bound.max + 1)))
			if got != nil || !errors.Is(err, bound.err) {
				t.Fatalf("over limit: got output = %t, error %v; want no output and %v", got != nil, err, bound.err)
			}
		})
	}
}

func TestDecodeYAMLCanExpandPastJSONInputBound(t *testing.T) {
	const prefix = "openapi: 3.1.0\npaths: {}\nx-note: '"
	doc := []byte(prefix + strings.Repeat("\\", maxYAMLBytes/2) + "'\n")
	encoded, err := DecodeYAML(doc)
	if err != nil || len(encoded) <= maxYAMLBytes || !json.Valid(encoded) {
		t.Fatalf("DecodeYAML() did not return expanded JSON: length %d, error %v", len(encoded), err)
	}
	want, jsonErr := ListOperations(encoded)
	got, yamlErr := ListYAMLOperations(doc)
	if want != nil || got != nil || jsonErr == nil || yamlErr != jsonErr {
		t.Fatalf("YAML listing = %v, %v; JSON listing = %v, %v", got, yamlErr, want, jsonErr)
	}
}

func TestListYAMLOperations(t *testing.T) {
	const data = `openapi: 3.1.0
paths:
  /z:
    post: {}
    get: {}
  /a/~:
    $ref: '#/components/pathItems/shared'
components:
  pathItems:
    shared: {patch: {}}
`
	want := []Operation{
		{Method: "patch", Path: "/a/~", Pointer: "/components/pathItems/shared/patch"},
		{Method: "get", Path: "/z", Pointer: "/paths/~1z/get"},
		{Method: "post", Path: "/z", Pointer: "/paths/~1z/post"},
	}
	got, err := ListYAMLOperations([]byte(data))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ListYAMLOperations() = %#v, %v; want %#v", got, err, want)
	}
}

func TestListYAMLOperationsRejectsWithoutPartialResults(t *testing.T) {
	const prefix = "openapi: 3.1.0\npaths:\n  /a:\n    get: {}\n"
	for _, tc := range []struct {
		name, doc string
		want      error
	}{
		{"duplicate method", prefix + "    get: {}\n", errYAMLDuplicate},
		{"trailing document", prefix + "---\na: b\n", errYAMLMultiple},
		{"invalid method shape", prefix + "  /z: {get: false}\n", errPathItem},
		{"invalid OpenAPI version", "openapi: 3.1\npaths: {}\n", errVersion},
		{"external URL", prefix + "  /z: {$ref: 'https://example.invalid/spec.yaml#/paths/~1a'}\n", errPathItemRef},
		{"external file", prefix + "  /z: {$ref: 'other.yaml#/paths/~1a'}\n", errPathItemRef},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ListYAMLOperations([]byte(tc.doc))
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("ListYAMLOperations() = %#v, %v; want nil and %v", got, err, tc.want)
			}
		})
	}
}

func FuzzDecodeYAML(f *testing.F) {
	for _, seed := range []string{
		"openapi: 3.1.0\npaths: {/a: {post: {}, get: {}}}\n",
		"first: &anchor [yes, no]\nsecond: *anchor\n",
		"{αβ: ! false}",
		"\ufeff! []",
		"key: null\r\n'key': value\r\n",
		"\"<<\": quoted\n",
		"a: [0, -0, 1.0, 1e-99999, 1e99999]\n",
		"---\n----\n---\nnull",
		`{"/\uD800": true}`,
		"\xff",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8<<10 {
			return
		}
		encoded, err := DecodeYAML(data)
		again, againErr := DecodeYAML(data)
		if !bytes.Equal(encoded, again) || (err == nil) != (againErr == nil) {
			t.Fatal("conversion is not deterministic")
		}
		if err != nil {
			if encoded != nil || again != nil || err.Error() != againErr.Error() {
				t.Fatal("conversion returned partial output or inconsistent error")
			}
			return
		}
		if !json.Valid(encoded) {
			t.Fatal("conversion did not return valid JSON")
		}
		if _, err := strictjson.Parse(encoded); err != nil {
			t.Fatalf("converted output violated strict JSON constraints: %v", err)
		}
		got, listErr := ListYAMLOperations(data)
		want, jsonErr := ListOperations(encoded)
		if !reflect.DeepEqual(got, want) || listErr != jsonErr || (listErr != nil && got != nil) {
			t.Fatal("YAML and JSON listing disagree or returned a partial result")
		}
	})
}
