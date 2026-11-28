package casefile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/natori-hrj/vintar/internal/strictjson"
)

var (
	idPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	environmentPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	candidatePattern   = regexp.MustCompile(`^post-json-candidate-[0-9a-f]{32}$`)
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pointerPattern     = regexp.MustCompile(`^(/([^~/]|~[01])*)*$`)
)

// validator retains the first error. Error contexts must be fixed schema
// labels, not user-supplied keys or values.
type validator struct{ err error }

func (v *validator) require(ok bool, message string) {
	if !ok && v.err == nil {
		v.err = errors.New(message)
	}
}

// TOML's generic decode preserves key case, table/array shape, and integer vs.
// float, unlike coercions that may occur when decoding directly into structs.
func (v *validator) table(raw any, message string, keys ...string) map[string]any {
	m, ok := raw.(map[string]any)
	v.require(ok && len(m) == len(keys), message)
	for _, key := range keys {
		_, present := m[key]
		v.require(present, message)
	}
	return m
}

func (v *validator) text(raw any, minLen, maxLen int, textOnly bool) string {
	s, ok := raw.(string)
	n := utf8.RuneCountInString(s)
	v.require(ok && minLen <= n && n <= maxLen, "invalid case string field")
	if textOnly {
		for _, r := range s {
			// Python's category C also includes unassigned code points, for
			// which Go does not publish a category table.
			if !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z) {
				v.require(false, "non-text character in case string field")
				break
			}
		}
	}
	return s
}

func (v *validator) integer(raw any) int64 {
	n, ok := raw.(int64)
	v.require(ok, "invalid case integer field")
	return n
}

func (v *validator) number(raw any, minValue, maxValue float64) float64 {
	var f float64
	switch n := raw.(type) {
	case int64:
		f = float64(n)
	case float64:
		f = n
	default:
		v.require(false, "invalid case number field")
	}
	v.require(!math.IsNaN(f) && minValue <= f && f <= maxValue, "case number outside allowed range")
	return f
}

func (v *validator) literal(raw any, expected, message string) {
	s, ok := raw.(string)
	v.require(ok && s == expected, message)
}

func validate(root map[string]any) (Case, error) {
	var v validator
	var c Case
	switch root["version"] {
	case int64(1):
		c.Version = Version1
	case int64(2), float64(2):
		// The v2 JSON Schema const compares equal numeric values. V1
		// checks the TOML integer type explicitly.
		c.Version = Version2
	default:
		return Case{}, errors.New("unsupported case version")
	}
	var request any
	switch c.Version {
	case Version1:
		v.table(root, "invalid v1 case fields", "version", "id", "type", "expected_verdict",
			"target", "injection", "probes", "limits")
		request = root["target"]
	case Version2:
		v.table(root, "invalid v2 case fields", "version", "identity_id", "id", "type",
			"expected_verdict", "request", "injection", "probes", "limits", "approval")
		id := v.text(root["identity_id"], 1, 64, true)
		v.require(idPattern.MatchString(id), "invalid identity identifier")
		c.IdentityID = &id
		request = root["request"]
	}

	c.ID = v.text(root["id"], 1, 64, true)
	v.require(idPattern.MatchString(c.ID), "invalid case identifier")
	c.Check = Check(v.text(root["type"], 1, 32, true))
	c.ExpectedVerdict = Verdict(v.text(root["expected_verdict"], 1, 32, true))
	switch c.ExpectedVerdict {
	case NotDetected, Inconclusive, Vulnerable:
	default:
		v.require(false, "invalid expected verdict")
	}
	c.Request = v.request(c.Version, request)
	path := v.checkTarget(c.Version, c.Request)
	var baseline string
	if c.Request.Method == GET {
		c.Injection.Query, baseline = v.queryInjection(c.Version, root["injection"], c.Request.Params)
	} else if c.Request.Method == POST {
		m := v.table(root["injection"], "invalid POST injection fields", "location", "pointer", "mode")
		v.literal(m["location"], "json_body", "invalid POST injection location")
		v.literal(m["mode"], string(Replace), "invalid POST injection mode")
		pointer := v.pointer(m["pointer"])
		c.Injection.JSON = &JSONInjection{Pointer: pointer}
		if v.err == nil {
			var ok bool
			baseline, ok = jsonStringAt(c.Request.JSONBody, pointer)
			v.require(ok, "JSON pointer does not select a string")
		}
	}
	if c.Version == Version2 {
		c.Approval = v.approval(root["approval"], c.Request)
		v.require(path == c.Approval.Path && bytePreservedPath(path), "request path differs from reviewed literal path")
	}
	var budget int64
	c.Probes, budget = v.probes(c.Version, c.Check, root["probes"])
	if c.Version == Version2 && (c.Injection.Query == nil || c.Injection.Query.Mode == Replace) {
		v.require(!c.Probes.replacesWith(baseline), "case probe equals the baseline value")
	}
	m := v.table(root["limits"], "invalid case limits fields", "max_requests", "requests_per_second", "timeout_seconds")
	c.Limits = Limits{
		MaxRequests:       v.integer(m["max_requests"]),
		RequestsPerSecond: v.number(m["requests_per_second"], 0.1, 10),
		TimeoutSeconds:    v.number(m["timeout_seconds"], 0.1, 60),
	}
	v.require(c.Limits.MaxRequests == budget, "invalid budget for case check")
	if t := c.Probes.Time; t != nil {
		timeout := c.Limits.TimeoutSeconds
		v.require(t.ExpectedDelaySeconds+0.5 <= timeout && timeout <= 8, "invalid timeout for timing check")
	}
	if v.err != nil {
		return Case{}, v.err
	}
	return c, nil
}

func (v *validator) request(version Version, raw any) Request {
	r := Request{Method: GET}
	var m map[string]any
	if version == Version1 {
		m = v.table(raw, "invalid v1 target fields", "url", "allowed_origin", "params")
	} else {
		m, _ = raw.(map[string]any)
		r.Method = Method(v.text(m["method"], 1, 4, true))
		switch r.Method {
		case GET:
			v.table(raw, "invalid GET request fields", "method", "url", "allowed_origin", "params")
		case POST:
			v.table(raw, "invalid POST request fields", "method", "url", "allowed_origin", "json_body")
		default:
			v.require(false, "unsupported case method")
		}
	}
	r.URL = v.text(m["url"], 1, 2048, true)
	r.AllowedOrigin = v.text(m["allowed_origin"], 1, 2048, true)
	if r.Method == GET {
		r.Params = v.queryPairs(version, m["params"])
	} else if r.Method == POST {
		body := v.text(m["json_body"], 1, MaxCaseBytes, true)
		if v.err == nil {
			canonical, err := strictjson.Canonicalize([]byte(body))
			v.require(err == nil, "invalid baseline JSON")
			r.JSONBody = canonical
		}
	}
	return r
}

func (v *validator) queryPairs(version Version, raw any) []QueryPair {
	items, ok := raw.([]any)
	if version == Version1 {
		v.require(ok && len(items) <= 32, "invalid v1 parameter list")
	} else {
		v.require(ok && 1 <= len(items) && len(items) <= 128, "invalid v2 parameter list")
	}
	if v.err != nil {
		return nil
	}
	out := make([]QueryPair, 0, len(items))
	for _, item := range items {
		if version == Version1 {
			m := v.table(item, "invalid v1 parameter fields", "name", "value")
			out = append(out, QueryPair{
				Name:  v.text(m["name"], 1, 128, true),
				Value: v.text(m["value"], 0, 2048, true),
			})
		} else {
			pair, ok := item.([]any)
			if !ok || len(pair) != 2 {
				v.require(false, "invalid v2 parameter pair")
				return nil
			}
			out = append(out, QueryPair{
				Name:  v.text(pair[0], 1, 256, false),
				Value: v.text(pair[1], 0, 2048, false),
			})
		}
	}
	return out
}

func (v *validator) queryInjection(version Version, raw any, params []QueryPair) (*QueryInjection, string) {
	m := v.table(raw, "invalid query injection fields", "location", "name", "occurrence", "mode")
	v.literal(m["location"], "query", "invalid query injection location")
	maxName := 256
	if version == Version1 {
		maxName = 128
	}
	q := &QueryInjection{
		Name:       v.text(m["name"], 1, maxName, version == Version1),
		Occurrence: v.integer(m["occurrence"]),
		Mode:       InjectionMode(v.text(m["mode"], 1, 7, true)),
	}
	v.require(q.Mode == Replace || q.Mode == Append, "invalid query injection mode")
	var matches int64
	var baseline string
	for _, p := range params {
		if p.Name == q.Name {
			if matches == q.Occurrence {
				baseline = p.Value
			}
			matches++
		}
	}
	v.require(0 <= q.Occurrence && q.Occurrence < matches, "query occurrence does not select a parameter")
	return q, baseline
}

func (p Probes) replacesWith(value string) bool {
	switch {
	case p.Boolean != nil:
		return p.Boolean.TruePayload == value || p.Boolean.FalsePayload == value
	case p.Time != nil:
		return p.Time.DelayPayload == value || p.Time.ControlPayload == value
	case p.Error != nil:
		return p.Error.ErrorPayload == value
	default:
		return false
	}
}

func (v *validator) probes(version Version, check Check, raw any) (Probes, int64) {
	switch check {
	case CheckBoolean:
		keys := []string{"true_payload", "false_payload"}
		m, _ := raw.(map[string]any)
		confirmation, present := m["confirmation"]
		if version == Version1 && present {
			keys = append(keys, "confirmation")
		}
		v.table(raw, "invalid Boolean probe fields", keys...)
		p := &BooleanProbes{
			TruePayload:  v.text(m["true_payload"], 1, 512, true),
			FalsePayload: v.text(m["false_payload"], 1, 512, true),
		}
		values := []string{p.TruePayload, p.FalsePayload}
		budget := int64(6)
		if version == Version1 && present {
			c := v.table(confirmation, "invalid confirmation fields", "true_payload", "false_payload", "baseline_preserving_control")
			p.Confirmation = &Confirmation{
				TruePayload:               v.text(c["true_payload"], 1, 512, true),
				FalsePayload:              v.text(c["false_payload"], 1, 512, true),
				BaselinePreservingControl: v.text(c["baseline_preserving_control"], 1, 512, true),
			}
			values = append(values, p.Confirmation.TruePayload, p.Confirmation.FalsePayload, p.Confirmation.BaselinePreservingControl)
			budget = 18
		}
		seen := make(map[string]bool, len(values))
		for _, value := range values {
			v.require(!seen[value], "case probe strings are not distinct")
			seen[value] = true
		}
		return Probes{Boolean: p}, budget
	case CheckTime:
		m := v.table(raw, "invalid timing probe fields", "delay_payload", "control_payload", "expected_delay_seconds")
		p := &TimeProbes{
			DelayPayload:         v.text(m["delay_payload"], 1, 512, true),
			ControlPayload:       v.text(m["control_payload"], 1, 512, true),
			ExpectedDelaySeconds: v.number(m["expected_delay_seconds"], 0.25, 2),
		}
		v.require(p.DelayPayload != p.ControlPayload, "case probe strings are not distinct")
		return Probes{Time: p}, 9
	case CheckError:
		m := v.table(raw, "invalid error probe fields", "error_payload")
		return Probes{Error: &ErrorProbes{ErrorPayload: v.text(m["error_payload"], 1, 512, true)}}, 4
	default:
		v.require(false, "unsupported case check")
		return Probes{}, 0
	}
}

func (v *validator) approval(raw any, request Request) *Approval {
	keys := []string{"method", "path", "environment_class"}
	if request.Method == POST {
		keys = append(keys, "candidate_id", "operation_pointer", "request_body_pointer",
			"operation_definition_sha256", "baseline_body_sha256", "side_effect", "review")
	}
	m := v.table(raw, "invalid approval fields", keys...)
	v.literal(m["method"], string(request.Method), "invalid approval method")
	a := &Approval{
		Method:           request.Method,
		Path:             v.text(m["path"], 1, MaxCaseBytes, false),
		EnvironmentClass: v.text(m["environment_class"], 1, 64, true),
	}
	v.require(strings.HasPrefix(a.Path, "/"), "invalid approval path")
	v.require(environmentPattern.MatchString(a.EnvironmentClass), "invalid approval environment class")
	if request.Method == POST {
		review := v.table(m["review"], "invalid approval review fields", "schema_version", "report_type")
		version := review["schema_version"]
		v.require(version == int64(2) || version == float64(2), "invalid approval review version")
		v.literal(review["report_type"], "post_json_discovery_review", "invalid approval review type")
		v.literal(m["side_effect"], "no_side_effect", "invalid approval side effect")
		p := &PostJSONApproval{
			CandidateID:               v.text(m["candidate_id"], 52, 52, true),
			OperationPointer:          v.pointer(m["operation_pointer"]),
			RequestBodyPointer:        v.pointer(m["request_body_pointer"]),
			OperationDefinitionSHA256: v.text(m["operation_definition_sha256"], 64, 64, true),
			BaselineBodySHA256:        v.text(m["baseline_body_sha256"], 64, 64, true),
			SideEffect:                "no_side_effect",
			Review:                    ReviewMetadata{SchemaVersion: Version2, ReportType: "post_json_discovery_review"},
		}
		v.require(candidatePattern.MatchString(p.CandidateID), "invalid approval candidate identifier")
		v.require(digestPattern.MatchString(p.OperationDefinitionSHA256) &&
			digestPattern.MatchString(p.BaselineBodySHA256), "invalid approval digest")
		sum := sha256.Sum256(request.JSONBody)
		v.require(hex.EncodeToString(sum[:]) == p.BaselineBodySHA256, "baseline JSON digest mismatch")
		a.PostJSON = p
	}
	return a
}

func (v *validator) pointer(raw any) string {
	p := v.text(raw, 0, MaxCaseBytes, false)
	v.require(pointerPattern.MatchString(p), "invalid JSON pointer")
	return p
}

var unescapePointerToken = strings.NewReplacer("~0", "~", "~1", "/")

// jsonStringAt checks the existing value without constructing a new body.
func jsonStringAt(data []byte, pointer string) (string, bool) {
	value, err := strictjson.Parse(data)
	if err != nil {
		return "", false
	}
	if pointer != "" {
		for _, escaped := range strings.Split(pointer[1:], "/") {
			token := unescapePointerToken.Replace(escaped)
			switch node := value.(type) {
			case map[string]any:
				value = node[token]
			case strictjson.SurrogateObject:
				value = node.UTF8[token]
			case []any:
				i, err := strconv.Atoi(token)
				if err != nil || i < 0 || i >= len(node) || strconv.Itoa(i) != token {
					return "", false
				}
				value = node[i]
			default:
				return "", false
			}
		}
	}
	switch value := value.(type) {
	case string:
		return value, true
	case strictjson.SurrogateString:
		// No nonempty UTF-8 TOML probe can equal a string with a lone surrogate.
		return "", true
	default:
		return "", false
	}
}
