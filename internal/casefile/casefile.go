// Package casefile parses inert, versioned regression case data. A parsed case
// is not an executable plan or evidence of authorization.
package casefile

import (
	"errors"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
)

const MaxCaseBytes = 65_536

type Version int64

const (
	Version1 Version = 1
	Version2 Version = 2
)

type Check string

const (
	CheckBoolean Check = "sqli.boolean"
	CheckTime    Check = "sqli.time"
	CheckError   Check = "sqli.error"
)

type Verdict string

const (
	NotDetected  Verdict = "not_detected"
	Inconclusive Verdict = "inconclusive"
	Vulnerable   Verdict = "vulnerable"
)

type Method string

const (
	GET  Method = "GET"
	POST Method = "POST"
)

type Case struct {
	Version         Version
	ID              string
	IdentityID      *string // nil for v1
	Check           Check
	ExpectedVerdict Verdict
	Request         Request
	Injection       Injection
	Probes          Probes
	Limits          Limits
	Approval        *Approval // nil for v1
}

type Request struct {
	Method        Method // v1's target table is represented as a GET request
	URL           string
	AllowedOrigin string
	Params        []QueryPair // nil for POST; names may repeat
	JSONBody      []byte      // canonical baseline bytes; nil for GET
}

type Injection struct {
	Query *QueryInjection
	JSON  *JSONInjection
}

type InjectionMode string

const (
	Replace InjectionMode = "replace"
	Append  InjectionMode = "append"
)

type QueryInjection struct {
	Name       string
	Occurrence int64
	Mode       InjectionMode
}

type JSONInjection struct {
	Pointer string // empty is the root pointer; only replacement is modeled
}

// Probes holds opaque strings, not executable requests. Only the selected
// check's field is populated.
type Probes struct {
	Boolean *BooleanProbes
	Time    *TimeProbes
	Error   *ErrorProbes
}

type BooleanProbes struct {
	TruePayload  string
	FalsePayload string
	Confirmation *Confirmation
}

type Confirmation struct {
	TruePayload               string
	FalsePayload              string
	BaselinePreservingControl string
}

type TimeProbes struct {
	DelayPayload         string
	ControlPayload       string
	ExpectedDelaySeconds float64
}

type ErrorProbes struct {
	ErrorPayload string
}

type Limits struct {
	MaxRequests       int64
	RequestsPerSecond float64
	TimeoutSeconds    float64
}

type Approval struct {
	Method           Method
	Path             string
	EnvironmentClass string
	PostJSON         *PostJSONApproval // nil for GET
}

type PostJSONApproval struct {
	CandidateID               string
	OperationPointer          string
	RequestBodyPointer        string
	OperationDefinitionSHA256 string
	BaselineBodySHA256        string
	SideEffect                string
	Review                    ReviewMetadata
}

type ReviewMetadata struct {
	SchemaVersion Version
	ReportType    string
}

// Parse validates one bounded UTF-8 TOML document and its inert data fields.
// It does not bind an operator policy, build executable requests, or validate
// transport behavior. See the migration foundation notes for parity limits.
func Parse(data []byte) (Case, error) {
	if len(data) > MaxCaseBytes {
		return Case{}, errors.New("case exceeds 65536 bytes")
	}
	if !utf8.Valid(data) {
		return Case{}, errors.New("case is not valid UTF-8")
	}
	var root map[string]any
	if err := toml.Unmarshal(data, &root); err != nil {
		// Decoder diagnostics can contain untrusted keys and source text.
		return Case{}, errors.New("invalid case TOML")
	}
	return validate(root)
}
