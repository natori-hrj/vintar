package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestListOperationsOrderAndPointers(t *testing.T) {
	data := []byte(`{
		"openapi":"3.0.7",
		"paths":{
			"/z/{id}":{"put":{},"post":{},"trace":{}},
			"x-ignored":false,
			"/a/~1":{"options":{},"head":{},"get":{},"patch":{},"delete":{},
				"summary":"example","description":"example","parameters":[],"servers":[],"x-ignored":42},
			"/empty":{}
		}
	}`)
	want := []Operation{
		{Method: "delete", Path: "/a/~1", Pointer: "/paths/~1a~1~01/delete"},
		{Method: "get", Path: "/a/~1", Pointer: "/paths/~1a~1~01/get"},
		{Method: "head", Path: "/a/~1", Pointer: "/paths/~1a~1~01/head"},
		{Method: "options", Path: "/a/~1", Pointer: "/paths/~1a~1~01/options"},
		{Method: "patch", Path: "/a/~1", Pointer: "/paths/~1a~1~01/patch"},
		{Method: "post", Path: "/z/{id}", Pointer: "/paths/~1z~1{id}/post"},
		{Method: "put", Path: "/z/{id}", Pointer: "/paths/~1z~1{id}/put"},
		{Method: "trace", Path: "/z/{id}", Pointer: "/paths/~1z~1{id}/trace"},
	}
	got, err := ListOperations(data)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ListOperations() = %#v, %v; want %#v", got, err, want)
	}
	encoded, err := json.Marshal(got[0])
	if err != nil || string(encoded) != `{"method":"delete","path":"/a/~1","pointer":"/paths/~1a~1~01/delete"}` {
		t.Fatalf("operation JSON = %s, %v", encoded, err)
	}
}

func TestListOperationsLocalReferences(t *testing.T) {
	data := []byte(`{
		"openapi":"3.1.2",
		"paths":{
			"/last":{"$ref":"#/paths/~1alias"},
			"/alias":{"$ref":"#/components/pathItems/a~1~01+%20%C3%A9","x-note":{}},
			"/array":{"$ref":"#%2Fx-items/0/"}
		},
		"components":{"pathItems":{"a/~1+ é":{"get":{},"post":{}}}},
		"x-items":[{"":{"head":{}}}],
		"webhooks":{"not-a-path":{"delete":{}}}
	}`)
	want := []Operation{
		{Method: "get", Path: "/alias", Pointer: "/components/pathItems/a~1~01+ é/get"},
		{Method: "post", Path: "/alias", Pointer: "/components/pathItems/a~1~01+ é/post"},
		{Method: "head", Path: "/array", Pointer: "/x-items/0//head"},
		{Method: "get", Path: "/last", Pointer: "/components/pathItems/a~1~01+ é/get"},
		{Method: "post", Path: "/last", Pointer: "/components/pathItems/a~1~01+ é/post"},
	}
	got, err := ListOperations(data)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ListOperations() = %#v, %v; want %#v", got, err, want)
	}
}

func TestListOperationsLocalReference30(t *testing.T) {
	got, err := ListOperations([]byte(`{
		"openapi":"3.0.0",
		"paths":{"/original":{"get":{}},"/alias":{"$ref":"#/paths/~1original"}}
	}`))
	want := []Operation{
		{Method: "get", Path: "/alias", Pointer: "/paths/~1original/get"},
		{Method: "get", Path: "/original", Pointer: "/paths/~1original/get"},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ListOperations() = %#v, %v; want %#v", got, err, want)
	}
}

func TestListOperationsEmpty(t *testing.T) {
	for _, data := range []string{
		`{"openapi":"3.0.0","paths":{}}`,
		`{"openapi":"3.1.0","paths":{"/empty":{},"x-extra":{}}}`,
		`{"openapi":"3.1.0","webhooks":{"hook":{"post":{}}}}`,
		`{"openapi":"3.1.0","components":{"pathItems":{"unused":{"get":{}}}}}`,
	} {
		got, err := ListOperations([]byte(data))
		if err != nil || got == nil || len(got) != 0 {
			t.Errorf("ListOperations(%q) = %#v, %v; want non-nil empty slice", data, got, err)
		}
	}
}

func TestListOperationsInvalidDocuments(t *testing.T) {
	const doc = `{"openapi":"3.1.0","paths":%s}`
	for _, tc := range []struct {
		name, data string
		want       error
	}{
		{"YAML", "openapi: 3.1.0\npaths: {}", nil},
		{"trailing", `{"openapi":"3.1.0","paths":{}} {}`, nil},
		{"duplicate root key", `{"openapi":"3.1.0","open\u0061pi":"3.1.0","paths":{}}`, nil},
		{"duplicate method", fmt.Sprintf(doc, `{"/a":{"get":{},"get":{}}}`), nil},
		{"bounded size", strings.Repeat(" ", (1<<20)+1), nil},
		{"bounded depth", strings.Repeat("[", 50) + "0" + strings.Repeat("]", 50), nil},
		{"array root", `[]`, errDocument},
		{"surrogate root key", `{"openapi":"3.1.0","paths":{},"\ud800":0}`, errDocument},
		{"Swagger", `{"swagger":"2.0","paths":{}}`, errVersion},
		{"unsupported version", `{"openapi":"3.2.0","paths":{}}`, errVersion},
		{"incomplete version", `{"openapi":"3.1","paths":{}}`, errVersion},
		{"non-string version", `{"openapi":3.1,"paths":{}}`, errVersion},
		{"missing 3.0 paths", `{"openapi":"3.0.0","components":{}}`, errPaths},
		{"missing 3.1 inventory root", `{"openapi":"3.1.0"}`, errPathsAbsent},
		{"invalid 3.1 alternative root", `{"openapi":"3.1.0","webhooks":null}`, errPathsAbsent},
		{"null paths", `{"openapi":"3.1.0","paths":null,"components":{}}`, errPaths},
		{"non-object paths", fmt.Sprintf(doc, `[]`), errPaths},
		{"invalid path name", fmt.Sprintf(doc, `{"source-marker":{}}`), errPaths},
		{"surrogate path name", fmt.Sprintf(doc, `{"/\ud800":{}}`), errPaths},
		{"non-object item", fmt.Sprintf(doc, `{"/a":[]}`), errPathItem},
		{"non-object operation", fmt.Sprintf(doc, `{"/a":{"get":null}}`), errPathItem},
		{"surrogate operation key", fmt.Sprintf(doc, `{"/a":{"get":{"\ud800":null}}}`), errPathItem},
		{"invalid operation key", fmt.Sprintf(doc, `{"/a":{"GET":{}}}`), errPathItem},
		{"invalid item metadata", fmt.Sprintf(doc, `{"/a":{"parameters":{}}}`), errPathItem},
		{"ambiguous siblings", fmt.Sprintf(doc, `{"/a":{"$ref":"#/paths/~1b","post":{}},"/b":{"get":{}}}`), errPathItem},
		{"no partial result", fmt.Sprintf(doc, `{"/a":{"get":{}},"/z":{"post":false}}`), errPathItem},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ListOperations([]byte(tc.data))
			if got != nil || err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("ListOperations() = %#v, %v; want nil and error %v", got, err, tc.want)
			}
			if strings.Contains(err.Error(), "source-marker") {
				t.Fatal("error echoed source text")
			}
		})
	}
}

func TestListOperationsInvalidReferences(t *testing.T) {
	const doc = `{"openapi":"3.1.0","paths":{"/a":{"$ref":%s},"/b":{"$ref":"#/paths/~1a"}},"x-items":[{"get":{}}],"x-scalar":1}`
	for _, tc := range []struct {
		ref  string
		want error
	}{
		{`null`, errPathItemRef},
		{`""`, errPathItemRef},
		{`"https://example.invalid/source-marker#/item"`, errPathItemRef},
		{`"./source-marker.json#/item"`, errPathItemRef},
		{`"file:///source-marker.json#/item"`, errPathItemRef},
		{`"#source-marker"`, errPathItemRef},
		{`"#"`, errPathItemRef},
		{`"#/source-marker"`, errPathItemRef},
		{`"#/x-items/0#extra"`, errPathItemRef},
		{`"#/x-items/0 "`, errPathItemRef},
		{`"#/x-items/~2"`, errPathItemRef},
		{`"#/x-items/0~"`, errPathItemRef},
		{`"#/x-items/%Q1"`, errPathItemRef},
		{`"#/x-items/%FF"`, errPathItemRef},
		{`"#/x-items/%ED%A0%80"`, errPathItemRef},
		{`"#/x-items/01"`, errPathItemRef},
		{`"#/x-items/-"`, errPathItemRef},
		{`"#/x-items/-1"`, errPathItemRef},
		{`"#/x-items/1"`, errPathItemRef},
		{`"#/x-items/999999999999999999999999"`, errPathItemRef},
		{`"#/x-scalar/get"`, errPathItemRef},
		{`"#/x-scalar"`, errPathItem},
		{`"#/paths/%7E1a"`, errPathItemLoop},
		{`"#/paths/~1b"`, errPathItemLoop},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			got, err := ListOperations([]byte(fmt.Sprintf(doc, tc.ref)))
			if got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("ListOperations() = %#v, %v; want nil and %v", got, err, tc.want)
			}
			if strings.Contains(err.Error(), "source-marker") {
				t.Fatal("error echoed source text")
			}
		})
	}
}

func TestListOperationsReferenceChainBound(t *testing.T) {
	for _, hops := range []int{maxPathItemRefs, maxPathItemRefs + 1} {
		t.Run(fmt.Sprint(hops), func(t *testing.T) {
			var doc strings.Builder
			// /a warms the cache for the same tail that /z must follow.
			doc.WriteString(`{"openapi":"3.1.0","paths":{"/z":{"$ref":"#/x-items/0"},"/a":{"$ref":"#/x-items/1"}},"x-items":[`)
			for i := 1; i < hops; i++ {
				fmt.Fprintf(&doc, `{"$ref":"#/x-items/%d"},`, i)
			}
			doc.WriteString(`{"get":{}}]}`)
			got, err := ListOperations([]byte(doc.String()))
			if hops > maxPathItemRefs {
				if got != nil || !errors.Is(err, errPathItemHops) {
					t.Fatalf("ListOperations() = %#v, %v; want chain limit error", got, err)
				}
				return
			}
			pointer := fmt.Sprintf("/x-items/%d/get", hops-1)
			want := []Operation{
				{Method: "get", Path: "/a", Pointer: pointer},
				{Method: "get", Path: "/z", Pointer: pointer},
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("ListOperations() = %#v, %v; want %#v", got, err, want)
			}
		})
	}
}

func FuzzListOperations(f *testing.F) {
	for _, seed := range []string{
		`{"openapi":"3.0.0","paths":{"/a/~":{"get":{},"post":{}}}}`,
		`{"openapi":"3.1.0","paths":{"/a":{"$ref":"#/x-items/0"}},"x-items":[{"trace":{}}]}`,
		`{"openapi":"3.1.0","paths":{"/a":{"$ref":"#/paths/~1a"}}}`,
		`{"openapi":"3.1.0","paths":{"/a":{"get":{},"get":{}}}}`,
		`{"openapi":"3.0.0","paths":{"/\ud800":{}}}`,
		"\xff",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8<<10 {
			return
		}
		got, err := ListOperations(data)
		again, errAgain := ListOperations(data)
		if (err == nil) != (errAgain == nil) || !reflect.DeepEqual(got, again) {
			t.Fatal("inventory is not deterministic")
		}
		if err != nil {
			if got != nil || err.Error() != errAgain.Error() {
				t.Fatal("rejection returned a partial result or inconsistent diagnostic")
			}
			return
		}
		for i, operation := range got {
			if !strings.HasPrefix(operation.Path, "/") ||
				!strings.HasPrefix(operation.Pointer, "/") ||
				!strings.HasSuffix(operation.Pointer, "/"+operation.Method) {
				t.Fatal("invalid operation location")
			}
			if i > 0 {
				prev := got[i-1]
				if prev.Path > operation.Path || (prev.Path == operation.Path && prev.Method >= operation.Method) {
					t.Fatal("operations are not strictly ordered by path then method")
				}
			}
		}
	})
}
