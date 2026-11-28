package execution

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"
)

const policyFixture = `{
	"schema_version": 1,
	"policy_type": "post_json_execution",
	"identities": [{
		"identity_id": "reviewed-user",
		"credential_kind": "bearer",
		"env_var": "VINTAR_TEST_TOKEN",
		"header_name": "Authorization"
	}],
	"approvals": [{
		"case_id": "reviewed-get",
		"identity_id": "reviewed-user",
		"credential_kind": "bearer",
		"credential_env_var": "VINTAR_TEST_TOKEN",
		"method": "GET",
		"path": "/items",
		"origin": "https://example.invalid",
		"allowed_environment_classes": ["local"]
	}, {
		"case_id": "reviewed-post",
		"identity_id": "reviewed-user",
		"credential_kind": "bearer",
		"credential_env_var": "VINTAR_TEST_TOKEN",
		"method": "POST",
		"path": "/items/%2a",
		"origin": "https://EXAMPLE.invalid:443/",
		"operation_definition_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
		"baseline_body_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"allowed_environment_classes": ["team_sandbox", "local"],
		"allowed_side_effect": "no_side_effect"
	}],
	"limits": {
		"max_requests": 48,
		"max_requests_per_second": 2.5,
		"max_timeout_seconds": 10,
		"max_response_size": 1048576,
		"max_time_execution_seconds": 45.25
	}
}`

func parsePolicyFixture(t *testing.T, source string) *RuntimePolicy {
	t.Helper()
	p, err := ParseRuntimePolicy([]byte(source))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return p
}

func fixturePolicyOrigin(t *testing.T, raw string) Origin {
	t.Helper()
	origin, err := ParseTrustedOrigin(raw)
	if err != nil {
		t.Fatalf("parse origin: %v", err)
	}
	return origin
}

func fixturePolicyRequest(t *testing.T, method string) ApprovalRequest {
	t.Helper()
	req := ApprovalRequest{
		CaseID: "reviewed-get", IdentityID: "reviewed-user", Method: method,
		Path: "/items", Environment: "local", Origin: fixturePolicyOrigin(t, "https://example.invalid"),
	}
	if method == "POST" {
		req.CaseID, req.Path, req.Environment = "reviewed-post", "/items/%2a", "team_sandbox"
		req.OperationDigest, req.BaselineDigest = strings.Repeat("0", 64), strings.Repeat("b", 64)
		req.SideEffect = "no_side_effect"
	}
	return req
}

func TestRuntimePolicyParseAndAuthorize(t *testing.T) {
	p := parsePolicyFixture(t, policyFixture+strings.Repeat(" ", maxRuntimePolicyBytes-len(policyFixture)))
	want := PolicyLimits{
		MaxRequests: 48, Rate: 2.5, Timeout: 10 * time.Second,
		MaxResponseSize: 1048576, Deadline: 45250 * time.Millisecond,
	}
	if got := p.Limits(); got != want {
		t.Fatalf("Limits() = %+v, want %+v", got, want)
	}
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			calls := 0
			credential, err := p.Authorize(fixturePolicyRequest(t, method), time.Now(), func(name string) (string, bool) {
				calls++
				if name != "VINTAR_TEST_TOKEN" {
					t.Fatal("looked up an unapproved env var")
				}
				return "synthetic-token", true
			})
			if err != nil || calls != 1 {
				t.Fatalf("Authorize: %v, %d lookups", err, calls)
			}
			headers := map[string]string{"Accept": "application/json"}
			if err := credential.Apply(headers); err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if len(headers) != 2 || headers["Accept"] != "application/json" || headers["Authorization"] != "Bearer synthetic-token" {
				t.Fatal("Apply did not set exactly the approved header")
			}
		})
	}
}

func FuzzRuntimePolicy(f *testing.F) {
	f.Add([]byte(policyFixture))
	f.Add([]byte(`{"schema_version":1,"schema_version":1}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		policy, err := ParseRuntimePolicy(data)
		if err != nil {
			if policy != nil {
				t.Fatal("invalid policy produced partial authorization state")
			}
			return
		}
		if policy == nil {
			t.Fatal("accepted policy returned no policy")
		}
		if _, err := NewGovernor(policy.Limits()); err != nil {
			t.Fatal("parsed policy returned invalid limits")
		}
	})
}

func TestRuntimePolicyRejectsNonSchemaInputs(t *testing.T) {
	const canary = "policy-canary"
	for _, tc := range []struct{ name, old, replacement string }{
		{"unknown root", `"schema_version": 1`, `"schema_version": 1, "` + canary + `": true`},
		{"wrong schema type", `"schema_version": 1`, `"schema_version": 1.0`},
		{"duplicate nested name", `"max_requests": 48`, `"max_requests": 48, "max_reque\u0073ts": 48`},
		{"nonfinite", `"max_requests_per_second": 2.5`, `"max_requests_per_second": NaN`},
		{"excess rate", `"max_requests_per_second": 2.5`, `"max_requests_per_second": 10.1`},
		{"bool as integer", `"max_requests": 48`, `"max_requests": true`},
		{"float as integer", `"max_response_size": 1048576`, `"max_response_size": 1e6`},
		{"zero duration", `"max_timeout_seconds": 10`, `"max_timeout_seconds": 0`},
		{"excess deadline", `"max_time_execution_seconds": 45.25`, `"max_time_execution_seconds": 121`},
		{"query placement", `"header_name": "Authorization"`, `"header_name": "Authorization", "placement": "query"`},
		{"wrong auth header", `"header_name": "Authorization"`, `"header_name": "X-Key"`},
		{"inline secret", `"header_name": "Authorization"`, `"header_name": "Authorization", "secret": "` + canary + `"`},
		{"invalid env name", `"env_var": "VINTAR_TEST_TOKEN"`, `"env_var": "$VINTAR_TEST_TOKEN"`},
		{"mismatched binding", `"credential_env_var": "VINTAR_TEST_TOKEN"`, `"credential_env_var": "OTHER_TOKEN"`},
		{"get with post metadata", `"method": "GET"`, `"method": "GET", "allowed_side_effect": "no_side_effect"`},
		{"post mutates", `"allowed_side_effect": "no_side_effect"`, `"allowed_side_effect": "mutates"`},
		{"bad digest", strings.Repeat("b", 64), strings.Repeat("B", 64)},
		{"duplicate environment", `"team_sandbox", "local"`, `"local", "local"`},
		{"path with query", `"/items"`, `"/items?a=b"`},
		{"template path", `"/items"`, `"/items/{id}"`},
		{"path with dot segment", `"/items"`, `"/a/%2e%2e/items"`},
		{"authority in path", `"/items"`, `"/%2fother.invalid/items"`},
		{"origin with userinfo", `"https://example.invalid"`, `"https://user@example.invalid"`},
		{"null expiry", `"header_name": "Authorization"`, `"header_name": "Authorization", "expires_at": null`},
		{"non-Z expiry", `"header_name": "Authorization"`, `"header_name": "Authorization", "expires_at": "2030-01-01T00:00:00+00:00"`},
		{"year zero", `"header_name": "Authorization"`, `"header_name": "Authorization", "expires_at": "0000-01-01T00:00:00Z"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := strings.Replace(policyFixture, tc.old, tc.replacement, 1)
			if source == policyFixture {
				t.Fatal("fixture was not changed")
			}
			p, err := ParseRuntimePolicy([]byte(source))
			if p != nil || err == nil || strings.Contains(err.Error(), canary) {
				t.Fatal("wanted a nil policy and redacted error")
			}
		})
	}
	for _, data := range [][]byte{
		nil, {0xff}, []byte(policyFixture + "{}"),
		bytes.Repeat([]byte(" "), maxRuntimePolicyBytes+1),
		[]byte(strings.Repeat("[", 49) + "0" + strings.Repeat("]", 49)),
	} {
		if p, err := ParseRuntimePolicy(data); err == nil || p != nil {
			t.Fatalf("accepted malformed or unbounded input (%d bytes)", len(data))
		}
	}
	var duplicate map[string]any
	if err := json.Unmarshal([]byte(policyFixture), &duplicate); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"identities", "approvals"} {
		items := duplicate[field].([]any)
		duplicate[field] = append(items, items[0])
		data, err := json.Marshal(duplicate)
		duplicate[field] = items
		if err != nil {
			t.Fatal(err)
		}
		if p, err := ParseRuntimePolicy(data); p != nil || err == nil {
			t.Errorf("accepted duplicate %s", field)
		}
	}
}

func TestRuntimePolicyDeniesBeforeLookup(t *testing.T) {
	noLookup := func(string) (string, bool) {
		t.Fatal("denied request reached the credential source")
		return "", false
	}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	p := parsePolicyFixture(t, policyFixture)
	valid := fixturePolicyRequest(t, "POST")
	for _, absent := range []*RuntimePolicy{nil, {}} {
		if absent.Limits() != (PolicyLimits{}) {
			t.Error("absent policy granted limits")
		}
		if _, err := absent.Authorize(valid, now, noLookup); err == nil {
			t.Error("absent policy authorized a request")
		}
	}
	wrongOrigin := fixturePolicyOrigin(t, "https://example.invalid:444")
	for _, tc := range []struct {
		name   string
		change func(*ApprovalRequest)
	}{
		{"case", func(r *ApprovalRequest) { r.CaseID = "other" }},
		{"identity", func(r *ApprovalRequest) { r.IdentityID = "other" }},
		{"method", func(r *ApprovalRequest) { r.Method = "GET" }},
		{"method casing", func(r *ApprovalRequest) { r.Method = "post" }},
		{"escape casing", func(r *ApprovalRequest) { r.Path = "/items/%2A" }},
		{"origin", func(r *ApprovalRequest) { r.Origin = wrongOrigin }},
		{"zero origin", func(r *ApprovalRequest) { r.Origin = Origin{} }},
		{"environment", func(r *ApprovalRequest) { r.Environment = "unlisted" }},
		{"environment casing", func(r *ApprovalRequest) { r.Environment = "TEAM_SANDBOX" }},
		{"operation digest", func(r *ApprovalRequest) { r.OperationDigest = strings.Repeat("a", 64) }},
		{"baseline digest", func(r *ApprovalRequest) { r.BaselineDigest = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := valid
			tc.change(&req)
			if _, err := p.Authorize(req, now, noLookup); err == nil {
				t.Fatal("mismatched approval accepted")
			}
		})
	}
	unreviewed := valid
	unreviewed.Environment = "TEAM_SANDBOX"
	unreviewedPolicy := parsePolicyFixture(t, strings.Replace(policyFixture, "team_sandbox", unreviewed.Environment, 1))
	if _, err := unreviewedPolicy.Authorize(unreviewed, now, noLookup); err == nil {
		t.Fatal("accepted POST alias that is invalid in a reviewed case")
	}
	get := fixturePolicyRequest(t, "GET")
	get.BaselineDigest = valid.BaselineDigest
	if _, err := p.Authorize(get, now, noLookup); err == nil {
		t.Fatal("GET unexpectedly accepted POST digest")
	}

	withExpiry := func(expiry string) *RuntimePolicy {
		return parsePolicyFixture(t, strings.Replace(policyFixture, `"header_name": "Authorization"`,
			`"header_name": "Authorization", "expires_at": "`+expiry+`"`, 1))
	}
	for _, expiry := range []string{"0001-01-01T00:00:00Z", "2030-01-01T00:00:01Z", "2030-01-01T00:01:45.25Z"} {
		if _, err := withExpiry(expiry).Authorize(valid, now, noLookup); err == nil {
			t.Error("accepted credential without enough expiry margin")
		}
	}
	if _, err := withExpiry("2030-01-01T00:01:45.250001Z").Authorize(valid, now, func(string) (string, bool) {
		return "synthetic-token", true
	}); err != nil {
		t.Fatalf("valid expiry was rejected: %v", err)
	}
}

func TestRuntimePolicyCredentialContractsAndRedaction(t *testing.T) {
	const canary = "synthetic-secret-canary"
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	req := fixturePolicyRequest(t, "GET")
	for _, tc := range []struct {
		kind, header, value, want string
		invalid                   []string
	}{
		{"bearer", "Authorization", canary, "Bearer " + canary, []string{"x" + canary + "é"}},
		{"basic", "AUTHORIZATION", "tést:" + canary + ":x", "Basic " + base64.StdEncoding.EncodeToString([]byte("tést:"+canary+":x")),
			[]string{canary, ":" + canary, canary + ":"}},
		{"api_key_header", "X-Test-Key", canary, canary, []string{"é" + canary}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			source := strings.ReplaceAll(policyFixture, `"bearer"`, `"`+tc.kind+`"`)
			source = strings.Replace(source, `"Authorization"`, `"`+tc.header+`"`, 1)
			p := parsePolicyFixture(t, source)
			cred, err := p.Authorize(req, now, func(string) (string, bool) { return tc.value, true })
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			wrapped := struct{ hidden Credential }{cred}
			for _, out := range []string{
				fmt.Sprintf("%v %+v %#v %s %q %x %#v", cred, cred, &cred, cred, cred, cred, wrapped),
				fmt.Sprint([]Credential{cred}),
			} {
				if strings.Contains(out, canary) || strings.Contains(out, tc.want) {
					t.Fatal("formatter exposed credential material")
				}
			}
			encoded, err := json.Marshal(cred)
			if err != nil || string(encoded) != "{}" {
				t.Fatal("credential is not opaque in JSON")
			}
			for _, headers := range []map[string]string{
				nil, {strings.ToLower(tc.header): canary}, {"aUtHoRiZaTiOn": canary},
				{"Accept": "a", "accept": "b"},
			} {
				before := maps.Clone(headers)
				if err := cred.Apply(headers); err == nil || strings.Contains(err.Error(), canary) || !maps.Equal(headers, before) {
					t.Fatal("Apply did not safely reject destination headers")
				}
			}
			headers := make(map[string]string)
			if err := cred.Apply(headers); err != nil || len(headers) != 1 || headers[tc.header] != tc.want {
				t.Fatal("incorrect credential header")
			}
			invalid := append(tc.invalid, "", " "+canary, canary+"\r\nInjected: x", canary+"\x7fx", canary+"\xff")
			for _, value := range invalid {
				c, err := p.Authorize(req, now, func(string) (string, bool) { return value, true })
				if err == nil || strings.Contains(err.Error(), canary) || c.Apply(make(map[string]string)) == nil {
					t.Fatal("invalid credential did not return a redacted error and unusable credential")
				}
			}
			if _, err := p.Authorize(req, now, func(string) (string, bool) { return canary, false }); err == nil {
				t.Fatal("missing env credential accepted")
			}
			if _, err := p.Authorize(req, now, nil); err == nil {
				t.Fatal("nil lookup accepted")
			}
			if tc.kind == "api_key_header" {
				for _, header := range []string{"Authorization", "hOSt", "Proxy-Authorization", "Content-Type", "Bad:Name"} {
					if p, err := ParseRuntimePolicy([]byte(strings.Replace(source, tc.header, header, 1))); p != nil || err == nil {
						t.Error("forbidden API-key header accepted")
					}
				}
			}
		})
	}
}
