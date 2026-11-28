package casefile

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParseReleasedAuthorityWhitespace(t *testing.T) {
	type vector struct {
		name, target, allowed string
		v1, v2                bool
	}
	const host = "https://case.invalid"
	// All whitespace code points admitted by the released case text filter.
	// The expected results were verified through v0.6.0's public case reader.
	const spaces = " \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
	var vectors []vector
	for _, r := range spaces {
		label, space := fmt.Sprintf("U+%04X", r), string(r)
		vectors = append(vectors,
			vector{label + " trailing request port", host + ":443" + space + "/items", host, true, false},
			vector{label + " leading request port", host + ":" + space + "443/items", host, true, true},
			vector{label + " declared origin with root path", host + "/items", host + ":443" + space + "/", true, true},
			vector{label + " trailing whole URL", host + ":443" + space, host, false, false},
		)
	}
	vectors = append(vectors,
		vector{"trailing port on scoped IPv6", "https://[fe80::1%7]:+444 /items", "https://[fe80::1%7]:444", true, false},
		vector{"space inside scoped IPv6 literal", "https://[fe80::1%a b]:+444/items", "https://[fe80::1%a b]:444", true, true},
		vector{"trailing hostname space", host + " /items", host + "%20", true, false},
		vector{"leading hostname space", "https:// case.invalid/items", "https://%20case.invalid", true, true},
		vector{"encoded hostname space", host + "%20/items", host + "%20", true, true},
		vector{"tab rejected by text filter", host + `:443\t/items`, host, false, false},
	)

	for _, form := range []struct{ name, seed, hostname string }{
		{"v1", v1, "case.invalid"}, {"v2-get", v2Get, "case.invalid"}, {"v2-post", v2Post, "golden.invalid"},
	} {
		t.Run(form.name, func(t *testing.T) {
			for _, v := range vectors {
				t.Run(v.name, func(t *testing.T) {
					source := strings.Replace(form.seed, "https://"+form.hostname+"/items", v.target, 1)
					source = strings.Replace(source, `allowed_origin = "https://`+form.hostname+`"`, `allowed_origin = "`+v.allowed+`"`, 1)
					want := v.v2
					if form.name == "v1" {
						want = v.v1
					}
					parsed, err := Parse([]byte(source))
					if (err == nil) != want {
						t.Fatalf("accepted = %t, want %t (error: %v)", err == nil, want, err)
					}
					if err == nil && (parsed.Request.URL != v.target || parsed.Request.AllowedOrigin != v.allowed) {
						t.Fatal("comparison rewrote the stored URL or declared origin")
					}
				})
			}
		})
	}
}

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
