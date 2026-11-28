package casefile

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestParseReleasedHostnameBoundary(t *testing.T) {
	// The expected results were captured from parse_regression_case in
	// v0.6.0 (712e507) for all three case forms, without executing requests.
	data, err := os.ReadFile("testdata/hostname-v0.6.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name, Target, Allowed string
		Accepted              bool
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("empty released hostname fixture")
	}
	for _, form := range []struct{ name, source, baseHost string }{
		{"v1", v1, "case.invalid"},
		{"v2-get", v2Get, "case.invalid"},
		{"v2-post", v2Post, "golden.invalid"},
	} {
		t.Run(form.name, func(t *testing.T) {
			for _, v := range vectors {
				t.Run(v.Name, func(t *testing.T) {
					source := strings.Replace(form.source, "https://"+form.baseHost+"/items", v.Target+"/items", 1)
					source = strings.Replace(source, `allowed_origin = "https://`+form.baseHost+`"`, `allowed_origin = "`+v.Allowed+`"`, 1)
					parsed, err := Parse([]byte(source))
					if (err == nil) != v.Accepted {
						t.Fatalf("accepted = %t, want %t (error: %v)", err == nil, v.Accepted, err)
					}
					if err == nil && (parsed.Request.URL != v.Target+"/items" || parsed.Request.AllowedOrigin != v.Allowed) {
						t.Fatal("hostname comparison rewrote the case input")
					}
				})
			}
		})
	}
}
