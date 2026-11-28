package casefile

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestParseReleasedURLCompatibility(t *testing.T) {
	data, err := os.ReadFile("testdata/url-compatibility-v0.6.0.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name, Target, Allowed string
		ApprovalPath          string `json:"approval_path"`
		Accepted              []bool
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("empty released URL fixture")
	}
	// JSON string quoting is also TOML basic string quoting for these
	// text-only fixture fields.
	quoted := func(s string) string {
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	// The expectations are in v1, v2 GET, v2 POST order, measured through
	// v0.6.0 parse_regression_case with these complete case fixtures.
	for i, form := range []struct{ name, source, baseHost string }{
		{"v1", v1, "case.invalid"},
		{"v2-get", v2Get, "case.invalid"},
		{"v2-post", v2Post, "golden.invalid"},
	} {
		t.Run(form.name, func(t *testing.T) {
			for _, v := range vectors {
				t.Run(v.Name, func(t *testing.T) {
					if len(v.Accepted) != 3 {
						t.Fatal("fixture needs an expectation for each case format")
					}
					source := strings.Replace(form.source, `url = "https://`+form.baseHost+`/items"`, "url = "+quoted(v.Target), 1)
					source = strings.Replace(source, `allowed_origin = "https://`+form.baseHost+`"`, "allowed_origin = "+quoted(v.Allowed), 1)
					source = strings.Replace(source, `path = "/items"`, "path = "+quoted(v.ApprovalPath), 1)
					c, err := Parse([]byte(source))
					if (err == nil) != v.Accepted[i] {
						t.Fatalf("accepted = %t, want %t (error: %v)", err == nil, v.Accepted[i], err)
					}
					if err == nil && (c.Request.URL != v.Target || c.Request.AllowedOrigin != v.Allowed) {
						t.Fatal("comparison rewrote the stored URL or declared origin")
					}
				})
			}
		})
	}
}
