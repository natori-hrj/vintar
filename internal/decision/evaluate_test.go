package decision

import (
	"encoding/json"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
)

func loadGolden(t *testing.T, name string, dst any) {
	t.Helper()
	data, err := os.ReadFile("../../tests/golden/cli/verify/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Report struct {
			Outcomes []json.RawMessage `json:"outcomes"`
		} `json:"stdout_json"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Report.Outcomes) != 1 {
		t.Fatal("expected one golden outcome")
	}
	if err := json.Unmarshal(envelope.Report.Outcomes[0], dst); err != nil {
		t.Fatal(err)
	}
}

type goldenDecision struct {
	Verdict Verdict `json:"actual_verdict"`
	Reason  string  `json:"actual_reason_code"`
	Count   int64   `json:"request_count"`
}

func (g goldenDecision) check(t *testing.T, got Result, err error) {
	t.Helper()
	if err != nil || got.Verdict != g.Verdict || got.Reason != g.Reason || got.RequestCount != g.Count {
		t.Fatalf("got (%s, %s, %d, %v), want %+v", got.Verdict, got.Reason, got.RequestCount, err, g)
	}
}

func TestBooleanGolden(t *testing.T) {
	for _, name := range []string{"pass", "partial-inconclusive", "fail"} {
		t.Run(name, func(t *testing.T) {
			var want struct {
				goldenDecision
				Verification struct {
					Observations []Observation
					Failures     []Failure
					Evidence     *Similarity
					Confidence   *float64
				}
				Facts *OperationalFacts `json:"decision_facts"`
			}
			loadGolden(t, name, &want)
			got, err := EvaluateBoolean(BooleanInput{
				Observations: want.Verification.Observations,
				Failures:     want.Verification.Failures,
				RequestCount: want.Count,
			})
			want.check(t, got, err)
			v := got.Verification
			if v == nil || !reflect.DeepEqual(v.Observations, want.Verification.Observations) ||
				!reflect.DeepEqual(v.Failures, want.Verification.Failures) ||
				!reflect.DeepEqual(v.Evidence, want.Verification.Evidence) ||
				!reflect.DeepEqual(v.Confidence, want.Verification.Confidence) ||
				!reflect.DeepEqual(got.Facts.Operational, want.Facts) || got.Confirmation != nil {
				t.Fatalf("verification or facts differ from golden: %+v, %+v", v, got.Facts.Operational)
			}
		})
	}
}

func booleanSamples() BooleanInput {
	in := BooleanInput{RequestCount: 6}
	for i, kind := range []string{"baseline", "true", "false", "baseline", "false", "true"} {
		hex := "a"
		if kind == "false" {
			hex = "b"
		}
		in.Observations = append(in.Observations, Observation{Kind: kind, StatusCode: 200, BodySize: 3, BodyDigest: strings.Repeat(hex, 64), Elapsed: float64(i)})
	}
	return in
}

func TestBooleanSavedNormalizationAndFacts(t *testing.T) {
	in := booleanSamples()
	in.Normalized = append([]Observation(nil), in.Observations...)
	in.Normalized[3].BodyDigest = strings.Repeat("c", 64)
	in.NormalizedEchoCount = 1
	one := int64(1)
	in.UnstablePairs = []UnstablePair{{Kind: "baseline", Localization: "localized",
		PrefixSize: &one, SuffixSize: &one, FirstChangedSize: &one, SecondChangedSize: &one}}
	got, err := EvaluateBoolean(in)
	(goldenDecision{Inconclusive, "possible_dynamic_response", 6}).check(t, got, err)
	want := []Observation{in.Normalized[0], in.Normalized[3], in.Normalized[1], in.Normalized[5], in.Normalized[2], in.Normalized[4]}
	if !reflect.DeepEqual(got.Verification.Observations, want) ||
		got.Verification.Evidence != nil || got.Verification.Confidence != nil ||
		got.Facts.Response == nil || !got.Facts.Response.NormalizationApplied ||
		got.Facts.Response.NormalizedEchoCount != 1 {
		t.Fatal("lost the released grouped normalization projection or saved facts")
	}
	in.UnstablePairs = nil
	got, err = EvaluateBoolean(in)
	(goldenDecision{Inconclusive, "unstable_response", 6}).check(t, got, err)
	if pairs := got.Facts.Response.UnstablePairs; len(pairs) != 1 || pairs[0].Localization != "unlocalized" {
		t.Fatalf("unexpected unstable pair facts: %+v", pairs)
	}
}

func TestBooleanPrecedenceAndConfirmation(t *testing.T) {
	in := booleanSamples()
	in.Observations[0].StatusCode = 503
	in.Observations[1].Truncated = true
	in.Observations[2].StatusCode, in.Observations[2].Truncated = 429, true
	in.Observations[5].StatusCode = 429
	got, err := EvaluateBoolean(in)
	(goldenDecision{Inconclusive, "rate_limited", 6}).check(t, got, err)
	if got.Facts.Operational.Sequence != 3 || got.Verification.Evidence != nil {
		t.Fatal("did not select the first highest-priority response")
	}
	in = booleanSamples()
	for _, tc := range []struct {
		status, reason, final string
	}{
		{"matched", "confirmation_pattern_matched", "boolean_candidate"},
		{"mismatch", "candidate_confirmation_mismatch", "candidate_confirmation_mismatch"},
		{"operational", "confirmation_unstable", "confirmation_unstable"},
	} {
		in.Confirmation = &Confirmation{Configured: true, Status: tc.status, Reason: &tc.reason, RequestCount: 12}
		got, err = EvaluateBoolean(in)
		(goldenDecision{Inconclusive, tc.final, 18}).check(t, got, err)
		if v := got.Verification; v.Reason != "boolean_candidate" || v.Confidence != nil ||
			!reflect.DeepEqual(v.Evidence, &Similarity{BaselineTrue: 1}) || v.RequestCount != 6 {
			t.Fatalf("confirmation changed initial verification: %+v", v)
		}
	}
	in = BooleanInput{BudgetUnavailable: true}
	reason := "initial_not_eligible"
	in.Confirmation = &Confirmation{Configured: true, Status: "not_eligible", Reason: &reason}
	got, err = EvaluateBoolean(in)
	(goldenDecision{Inconclusive, "budget_unavailable", 0}).check(t, got, err)
	if got.Confirmation == nil || got.Facts.Operational == nil || got.Facts.Operational.Sequence != 1 {
		t.Fatal("lost skipped confirmation or budget facts")
	}
}

func TestTimeGoldenAndPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    TimingPredicates
	}{
		{"time-candidate", TimingPredicates{CandidateMedianMet: true, CandidateMarginMet: true, DelaySpanExceeded: true}},
		{"time-not-detected", TimingPredicates{NoDelayConditionMet: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var want struct {
				goldenDecision
				Timing Timing
			}
			loadGolden(t, tc.name, &want)
			got, err := EvaluateTime(TimeInput{RequestCount: want.Count, Predicates: &tc.p})
			want.check(t, got, err)
			if !reflect.DeepEqual(got.Timing, &want.Timing) {
				t.Fatalf("timing differs from golden: %+v", got.Timing)
			}
		})
	}
	p := TimingPredicates{BaselineSpanExceeded: true, ControlSpanExceeded: true, DriftExceeded: true,
		BaselineControlDifferenceExceeded: true, DelaySpanExceeded: true, CandidateMedianMet: true, CandidateMarginMet: true}
	got, err := EvaluateTime(TimeInput{RequestCount: 9, Predicates: &p})
	(goldenDecision{Inconclusive, "unstable_timing", 9}).check(t, got, err)
	if !reflect.DeepEqual(got.Facts.Timing.InstabilityCauses, []string{"baseline_control_difference", "drift", "delay_span"}) ||
		got.Facts.Timing.CandidateMedianMet != nil {
		t.Fatal("wrong instability cause precedence")
	}
	got, err = EvaluateTime(TimeInput{RequestCount: 9, Predicates: &TimingPredicates{CandidateMedianMet: true}})
	(goldenDecision{Inconclusive, "ambiguous_timing", 9}).check(t, got, err)
	if facts := got.Facts.Timing; !*facts.CandidateMedianMet || *facts.CandidateMarginMet ||
		*facts.NoDelayConditionMet || facts.InstabilityCauses == nil {
		t.Fatal("missing ambiguous timing flags")
	}
	got, err = EvaluateTime(TimeInput{RequestCount: 5})
	(goldenDecision{Inconclusive, "incomplete_probes", 5}).check(t, got, err)
	if fact := got.Facts.Operational; fact.Sequence != 6 || fact.Kind != "baseline" || fact.Condition != "deadline" {
		t.Fatalf("bad incomplete facts: %+v", fact)
	}
	got, err = EvaluateTime(TimeInput{RequestCount: 1, Terminal: &OperationalFacts{
		Stage: "time", Sequence: 1, Kind: "baseline", Condition: "deadline",
	}})
	(goldenDecision{Inconclusive, "probe_interrupted", 1}).check(t, got, err)
}

func TestErrorGoldenAndPrecedence(t *testing.T) {
	match := Signature{DBMS: "sqlite", ID: "sqlite_operational_syntax"}
	for _, tc := range []struct {
		name    string
		status  int
		matches []Signature
	}{
		{"error-disclosed", 500, []Signature{match}},
		{"error-not-detected", 200, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var want struct {
				goldenDecision
				Error ErrorAnalysis
			}
			loadGolden(t, tc.name, &want)
			in := ErrorInput{Observations: []ErrorObservation{
				{Kind: "baseline", StatusCode: 200}, {Kind: "probe", StatusCode: tc.status, Matches: tc.matches},
				{Kind: "baseline", StatusCode: 200}, {Kind: "probe", StatusCode: tc.status, Matches: tc.matches},
			}}
			got, err := EvaluateError(in)
			want.check(t, got, err)
			if !reflect.DeepEqual(got.Error, &want.Error) {
				t.Fatalf("error analysis differs from golden: %+v", got.Error)
			}
		})
	}
	in := ErrorInput{Observations: []ErrorObservation{
		{Kind: "baseline", StatusCode: 503}, {Kind: "probe", StatusCode: 429, Truncated: true},
	}}
	got, err := EvaluateError(in)
	(goldenDecision{Inconclusive, "rate_limited", 2}).check(t, got, err)
	if fact := got.Facts.Operational; fact.Kind != "error" || fact.Sequence != 2 || fact.Condition != "rate_limited" {
		t.Fatalf("wrong operational error facts: %+v", fact)
	}
	in.Observations[1] = ErrorObservation{Kind: "probe", Failure: "response_read"}
	got, err = EvaluateError(in)
	(goldenDecision{Inconclusive, "probe_failed", 2}).check(t, got, err)
}

func TestMalformedEvidenceIsRedacted(t *testing.T) {
	const private = "caller-controlled"
	in := booleanSamples()
	in.Observations[0].BodyDigest = private
	_, boolErr := EvaluateBoolean(in)
	in = booleanSamples()
	in.Observations[0].Elapsed = math.NaN()
	_, elapsedErr := EvaluateBoolean(in)
	status := 429
	_, timeErr := EvaluateTime(TimeInput{RequestCount: 1, Terminal: &OperationalFacts{
		Stage: "time", Sequence: 1, Kind: "baseline", Condition: "truncated", StatusCode: &status,
	}})
	_, errorErr := EvaluateError(ErrorInput{Observations: []ErrorObservation{
		{Kind: "baseline", StatusCode: 200, Matches: []Signature{{DBMS: private, ID: private}}},
	}})
	_, partialErr := EvaluateError(ErrorInput{Observations: []ErrorObservation{{Kind: "baseline", StatusCode: 200}}})
	for _, err := range []error{boolErr, elapsedErr, timeErr, errorErr, partialErr} {
		if err == nil || strings.Contains(err.Error(), private) {
			t.Fatalf("expected a fixed validation error, got %v", err)
		}
	}
}
