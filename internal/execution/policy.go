package execution

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/natori-hrj/vintar/internal/strictjson"
)

const (
	maxRuntimePolicyBytes   = 262_144
	maxRuntimePolicyEntries = 128
	credentialExpiryMargin  = 60 * time.Second
)

var (
	errPolicySource = errors.New("post_json_policy_source_invalid: supply one nonempty bounded policy")
	errPolicySchema = errors.New("post_json_policy_schema_invalid: supply strict JSON matching the closed runtime policy schema")
	errPolicyQuery  = errors.New("auth_query_placement_unsupported: configure a dedicated API-key header instead")
	errPolicyDenied = errors.New("post_json_approval_mismatch: no exact approval for this request")
	errAuthExpiry   = errors.New("auth_material_expired: credential expiry must cover the policy deadline and safety margin")
	errAuthMissing  = errors.New("auth_material_unavailable: supply the approved credential")
	errAuthInvalid  = errors.New("auth_configuration_invalid: invalid credential or destination headers")
	errAuthConflict = errors.New("auth_collision: duplicate or provider-owned header")

	policyIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	policyEnvVar     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	policyExpiry     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$`)
	postEnvironment  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	policyHeaderName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
)

// PolicyLimits are the maximum settings permitted by a runtime policy.
type PolicyLimits struct {
	MaxRequests     int
	Rate            float64
	Timeout         time.Duration
	MaxResponseSize int64
	Deadline        time.Duration
}

// RuntimePolicy is an immutable, secret-free policy. Its zero value grants nothing.
type RuntimePolicy struct {
	limits     PolicyLimits
	identities map[string]policyIdentity
	approvals  map[policyApprovalKey]policyApproval
}

// Limits returns a copy of the policy ceilings, or zero limits for a nil policy.
func (p *RuntimePolicy) Limits() PolicyLimits {
	if p == nil {
		return PolicyLimits{}
	}
	return p.limits
}

// Format omits policy content from diagnostics.
func (RuntimePolicy) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<runtime policy redacted>")
}

type policyIdentity struct {
	kind, envVar, header string
	expiry               *time.Time
}

type policyApprovalKey struct {
	caseID, identityID, method, path string
	origin                           Origin
}

type policyApproval struct {
	environments                    map[string]struct{}
	operationDigest, baselineDigest string
}

// ParseRuntimePolicy reads the closed v0.6.0 runtime policy shape. It does no
// I/O and does not resolve credentials. The caller must supply trusted data.
func ParseRuntimePolicy(data []byte) (*RuntimePolicy, error) {
	if len(data) == 0 || len(data) > maxRuntimePolicyBytes {
		return nil, errPolicySource
	}
	value, err := strictjson.Parse(data)
	if err != nil {
		return nil, errPolicySchema
	}
	root, _ := value.(map[string]any)
	if !policyFields(root, "schema_version", "policy_type", "identities", "approvals", "limits") ||
		root["schema_version"] != json.Number("1") || root["policy_type"] != "post_json_execution" {
		return nil, errPolicySchema
	}
	identities, ok := root["identities"].([]any)
	if !ok || len(identities) == 0 || len(identities) > maxRuntimePolicyEntries {
		return nil, errPolicySchema
	}
	approvals, ok := root["approvals"].([]any)
	if !ok || len(approvals) == 0 || len(approvals) > maxRuntimePolicyEntries {
		return nil, errPolicySchema
	}
	limits, ok := parsePolicyLimits(root["limits"])
	if !ok {
		return nil, errPolicySchema
	}
	p := &RuntimePolicy{
		limits:     limits,
		identities: make(map[string]policyIdentity, len(identities)),
		approvals:  make(map[policyApprovalKey]policyApproval, len(approvals)),
	}
	for _, item := range identities {
		id, source, err := parsePolicyIdentity(item)
		if err != nil {
			return nil, err
		}
		if _, exists := p.identities[id]; exists {
			return nil, errPolicySchema
		}
		p.identities[id] = source
	}
	for _, item := range approvals {
		key, approval, ok := parsePolicyApproval(item, p.identities)
		if !ok {
			return nil, errPolicySchema
		}
		if _, exists := p.approvals[key]; exists {
			return nil, errPolicySchema
		}
		p.approvals[key] = approval
	}
	return p, nil
}

func policyFields(item map[string]any, keys ...string) bool {
	if len(item) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := item[key]; !ok {
			return false
		}
	}
	return true
}

func policyString(value any) string {
	text, _ := value.(string)
	return text
}

func policyText(value any, maxLen int) string {
	text := policyString(value)
	if utf8.RuneCountInString(text) > maxLen || strings.TrimSpace(text) != text {
		return ""
	}
	for _, c := range text {
		if c < ' ' {
			return ""
		}
	}
	return text
}

func parsePolicyIdentity(value any) (string, policyIdentity, error) {
	item, _ := value.(map[string]any)
	if item["placement"] == "query" {
		return "", policyIdentity{}, errPolicyQuery
	}
	fields := []string{"identity_id", "credential_kind", "env_var", "header_name"}
	_, hasExpiry := item["expires_at"]
	if hasExpiry {
		fields = append(fields, "expires_at")
	}
	if !policyFields(item, fields...) {
		return "", policyIdentity{}, errPolicySchema
	}
	id := policyString(item["identity_id"])
	source := policyIdentity{
		kind:   policyString(item["credential_kind"]),
		envVar: policyString(item["env_var"]),
		header: policyString(item["header_name"]),
	}
	if !policyIdentifier.MatchString(id) || !policyEnvVar.MatchString(source.envVar) ||
		!validPolicyHeader(source.kind, source.header) {
		return "", policyIdentity{}, errPolicySchema
	}
	if hasExpiry {
		expiry := policyString(item["expires_at"])
		if !policyExpiry.MatchString(expiry) {
			return "", policyIdentity{}, errPolicySchema
		}
		parsed, err := time.Parse(time.RFC3339Nano, expiry)
		if err != nil || parsed.Year() < 1 {
			return "", policyIdentity{}, errPolicySchema
		}
		source.expiry = &parsed
	}
	return id, source, nil
}

func validPolicyHeader(kind, header string) bool {
	if !policyHeaderName.MatchString(header) {
		return false
	}
	name := strings.ToLower(header)
	switch kind {
	case "bearer", "basic":
		return name == "authorization"
	case "api_key_header":
		switch name {
		case "authorization", "connection", "content-encoding", "content-length", "content-type",
			"cookie", "expect", "host", "keep-alive", "proxy-authenticate", "proxy-authorization",
			"proxy-connection", "set-cookie", "te", "trailer", "transfer-encoding", "upgrade":
			return false
		}
		return true
	default:
		return false
	}
}

func parsePolicyApproval(value any, identities map[string]policyIdentity) (policyApprovalKey, policyApproval, bool) {
	item, _ := value.(map[string]any)
	key := policyApprovalKey{
		caseID:     policyString(item["case_id"]),
		identityID: policyString(item["identity_id"]),
		method:     policyString(item["method"]),
		path:       policyText(item["path"], 2048),
	}
	approval := policyApproval{}
	fields := []string{"case_id", "identity_id", "credential_kind", "credential_env_var", "method", "path", "origin", "allowed_environment_classes"}
	switch key.method {
	case "GET":
	case "POST":
		fields = append(fields, "operation_definition_sha256", "baseline_body_sha256", "allowed_side_effect")
		approval.operationDigest = policyString(item["operation_definition_sha256"])
		approval.baselineDigest = policyString(item["baseline_body_sha256"])
		if item["allowed_side_effect"] != "no_side_effect" ||
			len(approval.operationDigest) != 64 || !asciiHex(approval.operationDigest) ||
			len(approval.baselineDigest) != 64 || !asciiHex(approval.baselineDigest) {
			return key, approval, false
		}
	default:
		return key, approval, false
	}
	source, found := identities[key.identityID]
	if !policyFields(item, fields...) || !policyIdentifier.MatchString(key.caseID) ||
		!found || item["credential_kind"] != source.kind || item["credential_env_var"] != source.envVar ||
		strings.ContainsAny(key.path, "{}") {
		return key, approval, false
	}
	origin, err := ParseTrustedOrigin(policyText(item["origin"], 2048))
	if err != nil {
		return key, approval, false
	}
	key.origin = origin
	if _, err := RebindApprovedPath(origin, []Origin{origin}, key.path); err != nil {
		return key, approval, false
	}
	environments, ok := item["allowed_environment_classes"].([]any)
	if !ok || len(environments) == 0 || len(environments) > 32 {
		return key, approval, false
	}
	approval.environments = make(map[string]struct{}, len(environments))
	for _, environment := range environments {
		name := policyString(environment)
		if _, duplicate := approval.environments[name]; duplicate || !policyIdentifier.MatchString(name) {
			return key, approval, false
		}
		approval.environments[name] = struct{}{}
	}
	return key, approval, true
}

func parsePolicyLimits(value any) (PolicyLimits, bool) {
	item, _ := value.(map[string]any)
	if !policyFields(item, "max_requests", "max_requests_per_second", "max_timeout_seconds",
		"max_response_size", "max_time_execution_seconds") {
		return PolicyLimits{}, false
	}
	requests, requestsOK := policyInt(item["max_requests"], 768)
	size, sizeOK := policyInt(item["max_response_size"], 1_048_576)
	rate, rateOK := policyNumber(item["max_requests_per_second"], 10)
	timeout, timeoutOK := policyNumber(item["max_timeout_seconds"], 60)
	deadline, deadlineOK := policyNumber(item["max_time_execution_seconds"], 120)
	if !(requestsOK && sizeOK && rateOK && timeoutOK && deadlineOK) {
		return PolicyLimits{}, false
	}
	return PolicyLimits{
		MaxRequests:     int(requests),
		Rate:            rate,
		Timeout:         time.Duration(timeout * float64(time.Second)),
		MaxResponseSize: size,
		Deadline:        time.Duration(deadline * float64(time.Second)),
	}, true
}

func policyInt(value any, maxValue int64) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := number.Int64()
	return n, err == nil && n >= 1 && n <= maxValue
}

func policyNumber(value any, maxValue float64) (float64, bool) {
	var n float64
	switch value := value.(type) {
	case float64:
		n = value
	case json.Number:
		var err error
		n, err = value.Float64()
		if err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	return n, n >= 0.1 && n <= maxValue
}

// ApprovalRequest identifies a validated operation. For POST, the caller must
// supply the digests and isolated-environment alias from the reviewed case
// (which attests no_side_effect), not values copied from the policy. For GET,
// both digests must be empty. Origin must also meet caller-owned trusted scope.
type ApprovalRequest struct {
	CaseID, IdentityID, Method, Path, Environment, OperationDigest, BaselineDigest string
	SideEffect                                                                     string
	Origin                                                                         Origin
}

// Authorize intersects the exact request with trusted policy before reading a
// credential. Only the approved source is consulted, and at most once.
func (p *RuntimePolicy) Authorize(request ApprovalRequest, now time.Time, lookup func(string) (string, bool)) (Credential, error) {
	source, err := p.authorizedSource(request, now)
	if err != nil {
		return Credential{}, err
	}
	return source.credential(lookup)
}

func (p *RuntimePolicy) authorizedSource(request ApprovalRequest, now time.Time) (policyIdentity, error) {
	if p == nil {
		return policyIdentity{}, errPolicyDenied
	}
	key := policyApprovalKey{
		caseID: request.CaseID, identityID: request.IdentityID, method: request.Method,
		path: request.Path, origin: request.Origin,
	}
	approval, ok := p.approvals[key]
	if !ok {
		return policyIdentity{}, errPolicyDenied
	}
	// For POST the policy's explicit environment list attests isolation, not
	// a heuristic based on the origin or on a hard-coded name such as "local".
	if _, allowed := approval.environments[request.Environment]; !allowed ||
		request.OperationDigest != approval.operationDigest || request.BaselineDigest != approval.baselineDigest ||
		request.Method == "POST" && (request.SideEffect != "no_side_effect" || !postEnvironment.MatchString(request.Environment)) {
		return policyIdentity{}, errPolicyDenied
	}
	source, ok := p.identities[key.identityID]
	if !ok {
		return policyIdentity{}, errPolicyDenied
	}
	if source.expiry != nil && (now.IsZero() || !source.expiry.After(now.Add(p.limits.Deadline+credentialExpiryMargin))) {
		return policyIdentity{}, errAuthExpiry
	}
	return source, nil
}

func (source policyIdentity) credential(lookup func(string) (string, bool)) (Credential, error) {
	if lookup == nil {
		return Credential{}, errAuthMissing
	}
	raw, ok := lookup(source.envVar)
	if !ok || raw == "" {
		return Credential{}, errAuthMissing
	}
	value, ok := policyCredentialValue(source.kind, raw)
	if !ok {
		return Credential{}, errAuthInvalid
	}
	header := source.header
	return Credential{reveal: func() (string, string) { return header, value }}, nil
}

func policyCredentialValue(kind, raw string) (string, bool) {
	if !utf8.ValidString(raw) || strings.TrimSpace(raw) != raw {
		return "", false
	}
	for _, c := range raw {
		if c < ' ' || c == 0x7f || kind != "basic" && c > '~' {
			return "", false
		}
	}
	switch kind {
	case "basic":
		user, pass, ok := strings.Cut(raw, ":")
		if !ok || user == "" || pass == "" {
			return "", false
		}
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw)), true
	case "bearer":
		return "Bearer " + raw, true
	case "api_key_header":
		return raw, true
	default:
		return "", false
	}
}

// Credential is an opaque resolved credential. Its zero value cannot be used.
type Credential struct {
	// A closure keeps the value out of structural formatting even when fmt
	// cannot call Format (e.g. when embedded in an unexported struct field).
	reveal func() (header, value string)
}

// Format redacts the credential in both ordinary and Go-syntax formatting.
func (Credential) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<credential redacted>")
}

// Apply adds exactly one credential header to a private header map for the
// already-authorized request. The caller must not log or serialize the result.
// On error the map is unchanged.
func (c Credential) Apply(headers map[string]string) error {
	if c.reveal == nil || headers == nil {
		return errAuthInvalid
	}
	header, value := c.reveal()
	providerHeader := strings.ToLower(header)
	names := make(map[string]struct{}, len(headers))
	for name := range headers {
		folded := strings.ToLower(name)
		if _, duplicate := names[folded]; duplicate || folded == providerHeader || folded == "authorization" {
			return errAuthConflict
		}
		names[folded] = struct{}{}
	}
	headers[header] = value
	return nil
}
