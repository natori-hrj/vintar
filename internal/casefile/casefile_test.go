package casefile

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const v1 = `version = 1
id = "example"
type = "sqli.boolean"
expected_verdict = "not_detected"
[target]
url = "https://case.invalid/items"
allowed_origin = "https://case.invalid"
params = [{ name = "name", value = "baseline" }, { name = "name", value = "" }]
[injection]
location = "query"
name = "name"
occurrence = 1
mode = "replace"
[probes]
true_payload = "true-probe"
false_payload = "false-probe"
[limits]
max_requests = 6
requests_per_second = 2
timeout_seconds = 5.0
`

const v2Get = `version = 2
identity_id = "billing-reader"
id = "get-query-boolean"
type = "sqli.boolean"
expected_verdict = "not_detected"
[request]
method = "GET"
url = "https://case.invalid/items"
allowed_origin = "https://case.invalid"
params = [["name", "baseline"], ["name", ""]]
[injection]
location = "query"
name = "name"
occurrence = 1
mode = "replace"
[probes]
true_payload = "true-probe"
false_payload = "false-probe"
[limits]
max_requests = 6
requests_per_second = 2.0
timeout_seconds = 5.0
[approval]
method = "GET"
path = "/items"
environment_class = "isolated_test"
`

const v2Post = `version = 2
identity_id = "reviewed-user"
id = "post-json-boolean"
type = "sqli.boolean"
expected_verdict = "not_detected"
[request]
method = "POST"
url = "https://golden.invalid/items"
allowed_origin = "https://golden.invalid"
json_body = '{ "name" : "baseline" }'
[injection]
location = "json_body"
pointer = "/name"
mode = "replace"
[probes]
true_payload = "true-probe"
false_payload = "false-probe"
[limits]
max_requests = 6
requests_per_second = 2.0
timeout_seconds = 5.0
[approval]
candidate_id = "post-json-candidate-00000000000000000000000000000000"
method = "POST"
path = "/items"
operation_pointer = "/paths/~1items/post"
request_body_pointer = "/paths/~1items/post/requestBody/content/application~1json"
operation_definition_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
baseline_body_sha256 = "5e5c0546e15bd689be19e8e151d0517b1ae9f6c96edfda7fbf930a72ae99056d"
side_effect = "no_side_effect"
environment_class = "isolated_test"
[approval.review]
schema_version = 2
report_type = "post_json_discovery_review"
`

func TestParseVersions(t *testing.T) {
	v1ArrayTables := strings.Replace(v1, `params = [{ name = "name", value = "baseline" }, { name = "name", value = "" }]`, `
[[target.params]]
name = "name"
value = "baseline"
[[target.params]]
name = "name"
value = ""`, 1)
	for _, tc := range []struct {
		name, input string
		version     Version
		method      Method
	}{
		{"v1", v1, Version1, GET},
		{"v1 array of tables", v1ArrayTables, Version1, GET},
		{"v2 GET", v2Get, Version2, GET},
		{"v2 POST", v2Post, Version2, POST},
		{"v2 floating constants", strings.ReplaceAll(v2Post, "version = 2", "version = 2.0"), Version2, POST},
		{"v1 raw path compatible with HTTPX", strings.Replace(v1, "/items", "/items%ZZ and cats", 1), Version1, GET},
		{"v1 normalized origin", strings.Replace(v1, "case.invalid/items", "CASE.INVALID:0443/items", 1), Version1, GET},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse([]byte(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			if c.Version != tc.version || c.Check != CheckBoolean || c.Request.Method != tc.method {
				t.Fatal("incorrect version, check, or method")
			}
			if (c.IdentityID == nil) != (tc.version == Version1) || (c.Approval == nil) != (tc.version == Version1) {
				t.Fatal("incorrect presence of v2 metadata")
			}
			if tc.method == GET {
				if len(c.Request.Params) != 2 || c.Request.Params[1] != (QueryPair{"name", ""}) ||
					c.Request.JSONBody != nil || c.Injection.JSON != nil || c.Injection.Query == nil {
					t.Fatal("incorrect query case")
				}
			} else if c.Request.Params != nil || c.Injection.Query != nil || c.Injection.JSON == nil ||
				c.Approval.PostJSON == nil || string(c.Request.JSONBody) != `{"name":"baseline"}` {
				t.Fatal("incorrect POST case or canonical body")
			}
		})
	}
}

func TestParseConditionalProbes(t *testing.T) {
	const booleanFields = "true_payload = \"true-probe\"\nfalse_payload = \"false-probe\""
	for _, tc := range []struct {
		name, probes string
		check        Check
		budget       int
	}{
		{"confirmation", booleanFields + `
[probes.confirmation]
true_payload = "confirm-true"
false_payload = "confirm-false"
baseline_preserving_control = "confirm-control"`, CheckBoolean, 18},
		{"time", "delay_payload = \"delay-probe\"\ncontrol_payload = \"control-probe\"\nexpected_delay_seconds = 0.25", CheckTime, 9},
		{"error", `error_payload = "error-probe"`, CheckError, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.Replace(v1, booleanFields, tc.probes, 1)
			src = strings.Replace(src, `"sqli.boolean"`, fmt.Sprintf("%q", tc.check), 1)
			src = strings.Replace(src, "max_requests = 6", fmt.Sprintf("max_requests = %d", tc.budget), 1)
			c, err := Parse([]byte(src))
			if err != nil {
				t.Fatal(err)
			}
			switch tc.check {
			case CheckBoolean:
				if c.Probes.Boolean == nil || c.Probes.Boolean.Confirmation == nil {
					t.Fatal("missing confirmation")
				}
			case CheckTime:
				if c.Probes.Time == nil || c.Probes.Time.ExpectedDelaySeconds != 0.25 {
					t.Fatal("missing delay")
				}
			case CheckError:
				if c.Probes.Error == nil {
					t.Fatal("missing error probe")
				}
			}
		})
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	for _, tc := range []struct {
		name, input, old, replacement string
	}{
		{"unknown root", v1, "[target]", "secret_field = true\n[target]"},
		{"unknown nested", v1, `value = ""`, `value = "", secret_field = 1`},
		{"wrong key case", v1, "version = 1", "Version = 1"},
		{"duplicate key", v1, "version = 1", "version = 1\nversion = 1"},
		{"duplicate table", v1, "[injection]", "[target]\n[injection]"},
		{"duplicate inline key", v1, `value = ""`, `value = "", value = ""`},
		{"malformed", v1, `value = ""`, `value = "secret_field`},
		{"bad utf8", v1, "baseline", "\xff"},
		{"oversized", v1, "baseline", strings.Repeat("界", MaxCaseBytes/3)},
		{"unsupported version", v1, "version = 1", "version = 3"},
		{"boolean version", v1, "version = 1", "version = true"},
		{"v1 float version", v1, "version = 1", "version = 1.0"},
		{"boolean number", v1, "requests_per_second = 2", "requests_per_second = true"},
		{"nonfinite number", v1, "requests_per_second = 2", "requests_per_second = nan"},
		{"float budget", v2Get, "max_requests = 6", "max_requests = 6.0"},
		{"float integer", v1, "occurrence = 1", "occurrence = 1.0"},
		{"TOML date", v1, "timeout_seconds = 5.0", "timeout_seconds = 2026-11-28"},
		{"missing value", v1, `, value = ""`, ""},
		{"empty required text", v1, `name = "name", value = ""`, `name = "", value = ""`},
		{"escaped control", v1, `value = ""`, `value = "\u202e"`},
		{"missing identity", v2Get, "identity_id = \"billing-reader\"\n", ""},
		{"wrong query shape", v2Get, `["name", ""]`, `{ name = "name", value = "" }`},
		{"missing occurrence", v2Get, "occurrence = 1\n", ""},
		{"missing matched name", v2Get, "occurrence = 1", "occurrence = 2"},
		{"probe union", v2Get, "[limits]", "error_payload = \"error-probe\"\n[limits]"},
		{"confirmation forbidden in v2", v2Get, "[limits]", "[probes.confirmation]\n[limits]"},
		{"wrong method shape", v2Get, `method = "GET"`, `method = "POST"`},
		{"get with post metadata", v2Get, `path = "/items"`, "path = \"/items\"\nside_effect = \"no_side_effect\""},
		{"missing pointer", v2Post, "pointer = \"/name\"\n", ""},
		{"invalid pointer", v2Post, `pointer = "/name"`, `pointer = "/~2"`},
		{"missing post metadata", v2Post, "side_effect = \"no_side_effect\"\n", ""},
		{"malformed baseline JSON", v2Post, `'{ "name" : "baseline" }'`, `'{"name":'`},
		{"duplicate baseline JSON", v2Post, `'{ "name" : "baseline" }'`, `'{"name":"baseline","name":"baseline"}'`},
		{"baseline digest mismatch", v2Post, `'{ "name" : "baseline" }'`, `'{"name":"other"}'`},
		{"v1 target query delimiter", v1, "/items", "/items?"},
		{"v1 target fragment delimiter", v1, "/items", "/items#"},
		{"v1 target userinfo", v1, "case.invalid/items", "user:secret@case.invalid/items"},
		{"v1 other origin", v1, "case.invalid/items", "other.invalid/items"},
		{"v1 invalid port", v1, `allowed_origin = "https://case.invalid"`, `allowed_origin = "https://case.invalid:99999"`},
		{"v1 relative URL", v1, `url = "https://case.invalid/items"`, `url = "/items"`},
		{"v1 padded URL", v1, `url = "https://case.invalid/items"`, `url = " https://case.invalid/items"`},
		{"v2 GET path mismatch", v2Get, `path = "/items"`, `path = "/different"`},
		{"v2 POST path mismatch", v2Post, `path = "/items"`, `path = "/different"`},
		{"v2 GET replacing with baseline", v2Get, `["name", ""]`, `["name", "true-probe"]`},
		{"v2 POST replacing with baseline", v2Post, `true_payload = "true-probe"`, `true_payload = "baseline"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.Replace(tc.input, tc.old, tc.replacement, 1)
			if src == tc.input {
				t.Fatal("test did not mutate input")
			}
			if _, err := Parse([]byte(src)); err == nil {
				t.Fatal("accepted invalid input")
			} else if strings.Contains(err.Error(), "secret_field") {
				t.Fatal("diagnostic leaks source contents")
			}
		})
	}
}

func TestParsePostJSONPointerAndDigest(t *testing.T) {
	for _, tc := range []struct {
		name, body, canonical, pointer string
		valid                          bool
	}{
		{"root string", `"baseline"`, `"baseline"`, "", true},
		{"array and escaped key", `{ "z": -0.0, "a/b~": ["café"] }`, `{"a/b~":["caf\u00e9"],"z":-0.0}`, "/a~1b~0/0", true},
		{"leading zero", `["baseline"]`, `["baseline"]`, "/00", false},
		{"out of range", `["baseline"]`, `["baseline"]`, "/1", false},
		{"not a string", `{"name":42}`, `{"name":42}`, "/name", false},
		{"lone surrogate is not replacement character", `{"\ud800":"baseline"}`, `{"\ud800":"baseline"}`, "/�", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := strings.Replace(v2Post, `{ "name" : "baseline" }`, tc.body, 1)
			src = strings.Replace(src, `pointer = "/name"`, fmt.Sprintf("pointer = %q", tc.pointer), 1)
			src = strings.Replace(src, "5e5c0546e15bd689be19e8e151d0517b1ae9f6c96edfda7fbf930a72ae99056d",
				fmt.Sprintf("%x", sha256.Sum256([]byte(tc.canonical))), 1)
			c, err := Parse([]byte(src))
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
				if c.Injection.JSON == nil || c.Injection.JSON.Pointer != tc.pointer ||
					string(c.Request.JSONBody) != tc.canonical {
					t.Fatal("did not preserve the pointer or canonical JSON")
				}
			} else if err == nil {
				t.Fatal("accepted invalid JSON pointer target")
			}
		})
	}
}

func TestParseExactByteLimit(t *testing.T) {
	src := v1 + "#" + strings.Repeat("x", MaxCaseBytes-len(v1)-1)
	if _, err := Parse([]byte(src)); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]byte(src + "x")); err == nil {
		t.Fatal("accepted one byte over limit")
	}
}

func TestEncodeQuery(t *testing.T) {
	if got := EncodeQuery(nil); got != "" {
		t.Fatalf("nil input encoded as %q", got)
	}
	pairs := []QueryPair{
		{"probe", " A+B/C?D=E&F#G%H"},
		{"probe", ""},
		{"é +", "-._~\xff"},
	}
	const want = "probe=%20A%2BB%2FC%3FD%3DE%26F%23G%25H&probe=&%C3%A9%20%2B=-._~%FF"
	if got := EncodeQuery(pairs); got != want {
		t.Fatalf("EncodeQuery = %q, want %q", got, want)
	}
}
