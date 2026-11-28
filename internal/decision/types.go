// Package decision classifies saved, sanitized evidence. Its input types do
// not describe requests or contain response content.
package decision

type Check string

const (
	Boolean Check = "sqli.boolean"
	Time    Check = "sqli.time"
	Error   Check = "sqli.error"
)

type Verdict string

const (
	Vulnerable   Verdict = "vulnerable"
	NotDetected  Verdict = "not_detected"
	Inconclusive Verdict = "inconclusive"
)

// Result is the decision-to-report boundary. Only the sections belonging to
// Check may be populated. Report validates the public projection separately.
type Result struct {
	Check        Check
	Verdict      Verdict
	Reason       string
	RequestCount int64
	Verification *Verification
	Confirmation *Confirmation
	Timing       *Timing
	Error        *ErrorAnalysis
	Facts        Facts
}

type Observation struct {
	Kind       string  `json:"kind"`
	StatusCode int     `json:"status_code"`
	BodySize   int64   `json:"body_size"`
	Elapsed    float64 `json:"elapsed"`
	BodyDigest string  `json:"body_digest"`
	Truncated  bool    `json:"truncated"`
}

type Failure struct {
	Kind    string   `json:"kind"`
	Reason  string   `json:"error"`
	Elapsed *float64 `json:"elapsed"`
}

type Similarity struct {
	BaselineFalse float64 `json:"baseline_false_similarity"`
	BaselineTrue  float64 `json:"baseline_true_similarity"`
	TrueFalse     float64 `json:"true_false_similarity"`
}

type Verification struct {
	Verdict      Verdict
	Reason       string
	RequestCount int64
	Observations []Observation
	Failures     []Failure
	Evidence     *Similarity
	Confidence   *float64
}

// Confirmation contains an already-recorded confirmation outcome. A nil
// result section means confirmation was not configured.
type Confirmation struct {
	Configured   bool    `json:"configured"`
	Status       string  `json:"status"`
	Reason       *string `json:"reason_code"`
	RequestCount int64   `json:"request_count"`
}

type Timing struct {
	Status       string `json:"status"`
	Reason       string `json:"reason_code"`
	RequestCount int64  `json:"request_count"`
}

type ErrorAnalysis struct {
	Status       string `json:"status"`
	Reason       string `json:"reason_code"`
	RequestCount int64  `json:"request_count"`
	DBMS         string `json:"dbms,omitempty"`
	SignatureID  string `json:"signature_id,omitempty"`
}

// Facts is a closed union at the report boundary: zero or exactly one member.
type Facts struct {
	Operational  *OperationalFacts
	Response     *ResponseFacts
	Confirmation *ConfirmationFacts
	Timing       *TimingFacts
}

type OperationalFacts struct {
	Stage      string `json:"stage"`
	Sequence   int    `json:"sequence"`
	Kind       string `json:"probe_kind"`
	Condition  string `json:"condition"`
	StatusCode *int   `json:"status_code,omitempty"`
}

type ResponseFacts struct {
	NormalizationApplied bool           `json:"normalization_applied"`
	NormalizedEchoCount  int64          `json:"normalized_echo_count"`
	UnstablePairs        []UnstablePair `json:"unstable_pairs"`
}

type UnstablePair struct {
	Kind              string `json:"probe_kind"`
	Localization      string `json:"localization"`
	PrefixSize        *int64 `json:"prefix_size,omitempty"`
	SuffixSize        *int64 `json:"suffix_size,omitempty"`
	FirstChangedSize  *int64 `json:"first_changed_size,omitempty"`
	SecondChangedSize *int64 `json:"second_changed_size,omitempty"`
}

type ConfirmationFacts struct {
	UnstableRepeatKinds        []string `json:"unstable_repeat_kinds"`
	UnreproducedPredicatePairs []string `json:"unreproduced_predicate_pairs"`
	MismatchedRelations        []string `json:"mismatched_relations"`
	CrossPhaseMismatchedKinds  []string `json:"cross_phase_mismatched_kinds"`
}

type TimingFacts struct {
	InstabilityCauses   []string `json:"instability_causes"`
	CandidateMedianMet  *bool    `json:"candidate_median_met,omitempty"`
	CandidateMarginMet  *bool    `json:"candidate_margin_met,omitempty"`
	NoDelayConditionMet *bool    `json:"no_delay_condition_met,omitempty"`
}

// BooleanInput accepts saved observations and, optionally, their prior
// normalization results. It never performs normalization on response content.
type BooleanInput struct {
	Observations        []Observation
	Failures            []Failure
	RequestCount        int64
	BudgetUnavailable   bool
	Normalized          []Observation
	NormalizedEchoCount int64
	UnstablePairs       []UnstablePair
	Confirmation        *Confirmation
	ConfirmationFacts   Facts
}

type TimeInput struct {
	RequestCount int64
	Terminal     *OperationalFacts
	Predicates   *TimingPredicates
}

// TimingPredicates are recorded comparison results, not samples or settings
// for making timing requests.
type TimingPredicates struct {
	BaselineSpanExceeded              bool
	ControlSpanExceeded               bool
	BaselineControlDifferenceExceeded bool
	DriftExceeded                     bool
	DelaySpanExceeded                 bool
	CandidateMedianMet                bool
	CandidateMarginMet                bool
	NoDelayConditionMet               bool
}

type Signature struct {
	DBMS string
	ID   string
}

// KnownSignature checks the public batch v1 allowlist; no diagnostic text is
// accepted at this boundary.
func KnownSignature(s Signature) bool {
	switch s.DBMS {
	case "mssql":
		return s.ID == "mssql_syntax_error"
	case "mysql":
		return s.ID == "mysql_syntax_error_1064"
	case "oracle":
		return s.ID == "oracle_syntax_error"
	case "postgresql":
		return s.ID == "postgresql_syntax_error"
	case "sqlite":
		return s.ID == "sqlite_operational_syntax"
	default:
		return false
	}
}

type ErrorObservation struct {
	Kind       string
	StatusCode int
	Truncated  bool
	Matches    []Signature
	Failure    string // Fixed terminal condition; empty for a response.
}

type ErrorInput struct {
	Observations []ErrorObservation
}
