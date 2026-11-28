package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/natori-hrj/vintar/internal/decision"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type writerOfflineLoader struct{}

func (writerOfflineLoader) Load(string) (any, error) {
	return nil, errors.New("unregistered local schema")
}

func writerSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	const path = "../../schemas/regression-batch-report-v1.schema.json"
	const id = "https://github.com/natori-hrj/vintar/blob/main/schemas/regression-batch-report-v1.schema.json"
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(writerOfflineLoader{})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource(id, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(id)
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return schema
}

func writerJSON(t *testing.T, data []byte) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func writerBoolean() decision.Result {
	obs := make([]decision.Observation, 0, 6)
	for i, kind := range []string{"baseline", "baseline", "true", "true", "false", "false"} {
		elapsed := 0.5
		if i == 0 {
			elapsed = 0.125
		}
		obs = append(obs, decision.Observation{
			Kind: kind, StatusCode: 200, BodySize: 14, Elapsed: elapsed,
			BodyDigest: "312c297ebe6de6f4f35c6d74d28d766e559b3eae17e85585018b972b10351ebb",
		})
	}
	return decision.Result{
		Check: decision.Boolean, Verdict: decision.NotDetected,
		Reason: "no_boolean_difference", RequestCount: 6,
		Verification: &decision.Verification{
			Verdict: decision.NotDetected, Reason: "no_boolean_difference", RequestCount: 6,
			Observations: obs,
			Evidence:     &decision.Similarity{BaselineFalse: 1, BaselineTrue: 1, TrueFalse: 1},
		},
	}
}

func writerRateLimit() decision.Result {
	return decision.Result{
		Check: decision.Boolean, Verdict: decision.Inconclusive, Reason: "rate_limited", RequestCount: 1,
		Verification: &decision.Verification{
			Verdict: decision.Inconclusive, Reason: "rate_limited", RequestCount: 1,
			Observations: []decision.Observation{{
				Kind: "baseline", StatusCode: 429, Elapsed: 0.125, Truncated: true,
				BodyDigest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			}},
		},
		Facts: decision.Facts{Operational: &decision.OperationalFacts{
			Stage: "initial", Sequence: 1, Kind: "baseline", Condition: "rate_limited", StatusCode: new(429),
		}},
	}
}

func TestMarshalBatchReleasedProjection(t *testing.T) {
	schema := writerSchema(t)
	time := decision.Result{
		Check: decision.Time, Verdict: decision.Inconclusive, Reason: "timing_pattern_matched", RequestCount: 9,
		Timing: &decision.Timing{Status: "candidate", Reason: "timing_pattern_matched", RequestCount: 9},
	}
	noError := decision.Result{
		Check: decision.Error, Verdict: decision.NotDetected, Reason: "dbms_error_not_observed", RequestCount: 4,
		Error: &decision.ErrorAnalysis{Status: "not_matched", Reason: "dbms_error_not_observed", RequestCount: 4},
	}
	disclosed := decision.Result{
		Check: decision.Error, Verdict: decision.Inconclusive, Reason: "dbms_error_disclosed", RequestCount: 4,
		Error: &decision.ErrorAnalysis{
			Status: "matched", Reason: "dbms_error_disclosed", RequestCount: 4,
			DBMS: "sqlite", SignatureID: "sqlite_operational_syntax",
		},
	}
	for _, tc := range []struct {
		name    string
		planned []string
		records []Record
	}{
		{"pass", []string{"a-case"}, []Record{{"a-case", decision.NotDetected, writerBoolean()}}},
		{"fail", []string{"a-case"}, []Record{{"a-case", decision.Vulnerable, writerBoolean()}}},
		{"partial-inconclusive", []string{"a-case", "b-case"}, []Record{{"a-case", decision.NotDetected, writerRateLimit()}}},
		{"mixed-boolean-time-error", []string{"boolean-case", "error-case", "time-case"}, []Record{
			{"boolean-case", decision.NotDetected, writerBoolean()},
			{"error-case", decision.NotDetected, noError},
			{"time-case", decision.Inconclusive, time},
		}},
		{"error-disclosed", []string{"error-case"}, []Record{{"error-case", decision.Inconclusive, disclosed}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			golden := writerJSON(t, readFixture(t, "golden", "cli", "verify", tc.name+".json")).(map[string]any)
			for _, pretty := range []bool{false, true} {
				data, exit, err := MarshalBatch(tc.planned, tc.records, pretty)
				if err != nil || exit != int(golden["exit_code"].(float64)) {
					t.Fatalf("exit = %d, err = %v", exit, err)
				}
				again, _, _ := MarshalBatch(tc.planned, tc.records, pretty)
				if !bytes.Equal(again, data) || !bytes.HasSuffix(data, []byte("}\n")) {
					t.Fatal("report must be deterministic and newline terminated")
				}
				if pretty != bytes.Contains(data, []byte("\n  \"")) || (!pretty && bytes.Count(data, []byte{'\n'}) != 1) {
					t.Fatal("unexpected report indentation")
				}
				got := writerJSON(t, data)
				if err := schema.Validate(got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, golden["stdout_json"]) {
					t.Fatalf("report differs from released stdout_json: %s", data)
				}
			}
		})
	}
}

func TestMarshalBatchRejectsUnsafeInputs(t *testing.T) {
	const unsafe = "private request diagnostic"
	for name, change := range map[string]func(*Record){
		"expected verdict": func(r *Record) { r.Expected = unsafe },
		"check":            func(r *Record) { r.Decision.Check = unsafe },
		"final reason":     func(r *Record) { r.Decision.Reason = unsafe },
		"initial reason":   func(r *Record) { r.Decision.Verification.Reason = unsafe },
		"probe kind":       func(r *Record) { r.Decision.Verification.Observations[0].Kind = unsafe },
		"opaque digest":    func(r *Record) { r.Decision.Verification.Observations[0].BodyDigest = unsafe },
		"elapsed":          func(r *Record) { r.Decision.Verification.Observations[0].Elapsed = math.Inf(1) },
		"similarity":       func(r *Record) { r.Decision.Verification.Evidence.TrueFalse = math.NaN() },
		"contradictory analytical similarity": func(r *Record) {
			r.Decision.Verification.Evidence = &decision.Similarity{}
		},
		"unstable observations with a passing verdict": func(r *Record) {
			r.Decision.Verification.Observations[2].BodyDigest = strings.Repeat("b", 64)
		},
		"confirmation": func(r *Record) {
			r.Decision.Confirmation = &decision.Confirmation{Configured: true, Status: "not_eligible", Reason: new(unsafe)}
		},
		"extraneous timing": func(r *Record) { r.Decision.Timing = &decision.Timing{} },
		"wrong count":       func(r *Record) { r.Decision.RequestCount++ },
		"wrong verdict":     func(r *Record) { r.Decision.Verdict = decision.Inconclusive },
		"incomplete analytical evidence": func(r *Record) {
			v := r.Decision.Verification
			v.Observations = []decision.Observation{v.Observations[0], v.Observations[2], v.Observations[4]}
			v.RequestCount, r.Decision.RequestCount = 3, 3
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := Record{"a", decision.NotDetected, writerBoolean()}
			change(&r)
			assertNoWriterOutput(t, []string{"a"}, []Record{r})
		})
	}
}

func TestMarshalBatchRequiresReleasedDecisionFacts(t *testing.T) {
	result := writerRateLimit()
	result.Facts = decision.Facts{}
	assertNoWriterOutput(t, []string{"a"}, []Record{{"a", decision.Inconclusive, result}})
}

func TestMarshalBatchRejectsContradictoryOperationalFacts(t *testing.T) {
	result := writerRateLimit()
	result.Verification.Observations[0].StatusCode = 200
	result.Verification.Observations[0].Truncated = false
	assertNoWriterOutput(t, []string{"a"}, []Record{{"a", decision.Inconclusive, result}})
}

func TestMarshalBatchConfirmationStopUsesRecordedAttempt(t *testing.T) {
	result := writerBoolean()
	result.Verification.Verdict = decision.Inconclusive
	result.Verification.Reason = "boolean_candidate"
	result.Verification.Evidence = &decision.Similarity{BaselineTrue: 1}
	for _, i := range []int{4, 5} {
		result.Verification.Observations[i].BodyDigest = strings.Repeat("c", 64)
	}
	result.Verdict, result.Reason, result.RequestCount = decision.Inconclusive, "confirmation_timeout", 7
	result.Confirmation = &decision.Confirmation{
		Configured: true, Status: "operational", Reason: &result.Reason, RequestCount: 1,
	}
	result.Facts.Operational = &decision.OperationalFacts{
		Stage: "confirmation", Sequence: 7, Kind: "baseline", Condition: "timeout",
	}
	planned := []string{"a"}
	records := []Record{{"a", decision.Inconclusive, result}}
	if _, exit, err := MarshalBatch(planned, records, false); err != nil || exit != 3 {
		t.Fatalf("recorded confirmation timeout rejected: exit=%d, err=%v", exit, err)
	}
	result.Facts.Operational.Sequence = 8
	result.Facts.Operational.Kind = "true_1"
	assertNoWriterOutput(t, planned, records)

	result.Reason, result.RequestCount = "confirmation_budget_unavailable", 6
	result.Confirmation.RequestCount = 0
	result.Facts.Operational.Sequence = 7
	result.Facts.Operational.Kind = "baseline"
	result.Facts.Operational.Condition = "budget_unavailable"
	records[0].Decision = result
	if _, exit, err := MarshalBatch(planned, records, false); err != nil || exit != 3 {
		t.Fatalf("budget stop before the next attempt rejected: exit=%d, err=%v", exit, err)
	}
}

func TestMarshalBatchFactVariants(t *testing.T) {
	schema := writerSchema(t)
	response := writerBoolean()
	response.Reason, response.Verification.Reason = "possible_dynamic_response", "possible_dynamic_response"
	response.Verdict, response.Verification.Verdict = decision.Inconclusive, decision.Inconclusive
	response.Verification.Evidence = nil
	response.Verification.Observations[2].BodySize = 5
	response.Verification.Observations[3].BodySize = 7
	response.Verification.Observations[3].BodyDigest = strings.Repeat("b", 64)
	response.Facts.Response = &decision.ResponseFacts{
		UnstablePairs: []decision.UnstablePair{{
			Kind: "true", Localization: "localized",
			PrefixSize: new(int64(0)), SuffixSize: new(int64(3)),
			FirstChangedSize: new(int64(2)), SecondChangedSize: new(int64(4)),
		}},
	}
	confirmation := writerBoolean()
	confirmation.Reason, confirmation.Verification.Reason = "candidate_confirmation_mismatch", "boolean_candidate"
	confirmation.Verdict, confirmation.Verification.Verdict = decision.Inconclusive, decision.Inconclusive
	confirmation.Verification.Evidence = &decision.Similarity{BaselineTrue: 1}
	for _, i := range []int{4, 5} {
		confirmation.Verification.Observations[i].BodyDigest = strings.Repeat("c", 64)
	}
	confirmation.RequestCount = 18
	confirmation.Confirmation = &decision.Confirmation{
		Configured: true, Status: "mismatch", Reason: new("candidate_confirmation_mismatch"), RequestCount: 12,
	}
	confirmation.Facts.Confirmation = &decision.ConfirmationFacts{MismatchedRelations: []string{"baseline_true"}}
	timing := decision.Result{
		Check: decision.Time, Verdict: decision.Inconclusive, Reason: "ambiguous_timing", RequestCount: 9,
		Timing: &decision.Timing{Status: "inconclusive", Reason: "ambiguous_timing", RequestCount: 9},
		Facts: decision.Facts{Timing: &decision.TimingFacts{
			CandidateMedianMet: new(true), CandidateMarginMet: new(false), NoDelayConditionMet: new(false),
		}},
	}
	unstable := decision.Result{
		Check: decision.Time, Verdict: decision.Inconclusive, Reason: "unstable_timing", RequestCount: 9,
		Timing: &decision.Timing{Status: "inconclusive", Reason: "unstable_timing", RequestCount: 9},
		Facts:  decision.Facts{Timing: &decision.TimingFacts{InstabilityCauses: []string{"drift"}}},
	}
	probeFailure := decision.Result{
		Check: decision.Boolean, Verdict: decision.Inconclusive, Reason: "probe_failed", RequestCount: 1,
		Verification: &decision.Verification{
			Verdict: decision.Inconclusive, Reason: "probe_failed", RequestCount: 1,
			Failures: []decision.Failure{{Kind: "baseline", Reason: "timeout"}},
		},
		Facts: decision.Facts{Operational: &decision.OperationalFacts{
			Stage: "initial", Sequence: 1, Kind: "baseline", Condition: "timeout",
		}},
	}
	for _, tc := range []struct {
		name     string
		result   decision.Result
		contains string
		breakIt  func(*decision.Result)
	}{
		{"response", response, `"prefix_size":0`, func(r *decision.Result) {
			r.Facts.Response.UnstablePairs[0].PrefixSize = nil
		}},
		{"confirmation", confirmation, `"unreproduced_predicate_pairs":[]`, func(r *decision.Result) {
			r.Facts.Confirmation.MismatchedRelations = []string{"baseline_true", "baseline_true"}
		}},
		{"ambiguous timing", timing, `"instability_causes":[]`, func(r *decision.Result) {
			r.Facts.Timing.InstabilityCauses = []string{"drift"}
		}},
		{"unstable timing", unstable, `"instability_causes":["drift"]`, func(r *decision.Result) {
			r.Facts.Timing.CandidateMedianMet = new(false)
		}},
		{"probe failure", probeFailure, `"failures":[{"elapsed":null,"error":"timeout","kind":"baseline"}]`, func(r *decision.Result) {
			r.Verification.Failures[0].Reason = "private failure detail"
		}},
		{"facts union", writerRateLimit(), `"status_code":429`, func(r *decision.Result) {
			r.Facts.Response = &decision.ResponseFacts{}
		}},
		{"operational enum", writerRateLimit(), `"status_code":429`, func(r *decision.Result) {
			r.Facts.Operational.Condition = "private operational detail"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records := []Record{{"a", decision.Inconclusive, tc.result}}
			data, exit, err := MarshalBatch([]string{"a"}, records, false)
			if err != nil || exit != 3 {
				t.Fatalf("exit = %d, err = %v", exit, err)
			}
			if err := schema.Validate(writerJSON(t, data)); err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(data, []byte(tc.contains)) {
				t.Fatalf("missing projection %q: %s", tc.contains, data)
			}
			tc.breakIt(&records[0].Decision)
			assertNoWriterOutput(t, []string{"a"}, records)
		})
	}
}

func TestMarshalBatchExplicitSectionAlignment(t *testing.T) {
	for _, result := range []decision.Result{
		{
			Check: decision.Time, Verdict: decision.Inconclusive, Reason: "incomplete_probes", RequestCount: 0,
			Timing: &decision.Timing{Status: "inconclusive", Reason: "incomplete_probes", RequestCount: 1},
		},
		{
			Check: decision.Error, Verdict: decision.Inconclusive, Reason: "dbms_error_disclosed", RequestCount: 4,
			Error: &decision.ErrorAnalysis{
				Status: "matched", Reason: "dbms_error_disclosed", RequestCount: 4,
				DBMS: "sqlite", SignatureID: "postgresql_syntax_error",
			},
		},
		{
			Check: decision.Error, Verdict: decision.Inconclusive, Reason: "non_success_status", RequestCount: 1,
			Error: &decision.ErrorAnalysis{Status: "inconclusive", Reason: "non_success_status", RequestCount: 1},
		},
	} {
		assertNoWriterOutput(t, []string{"a"}, []Record{{"a", decision.Inconclusive, result}})
	}
}

func assertNoWriterOutput(t *testing.T, planned []string, executed []Record) {
	t.Helper()
	data, exit, err := MarshalBatch(planned, executed, false)
	if data != nil || exit != 2 || err == nil || err.Error() != "invalid batch report input" {
		t.Fatalf("got %d bytes, exit %d, error %v; want no bytes, exit 2 and fixed error", len(data), exit, err)
	}
}

func TestMarshalBatchAggregation(t *testing.T) {
	schema := writerSchema(t)
	fail := Record{"b", decision.Vulnerable, writerBoolean()}
	inconclusive := Record{"a", decision.NotDetected, writerRateLimit()}
	for _, tc := range []struct {
		records []Record
		exit    int
		status  Status
		counts  Counts
		used    int64
	}{
		{[]Record{inconclusive}, 3, Inconclusive, Counts{Inconclusive: 1, NotRun: 2}, 1},
		{[]Record{inconclusive, fail}, 1, Fail, Counts{Fail: 1, Inconclusive: 1, NotRun: 1}, 7},
	} {
		data, exit, err := MarshalBatch([]string{"a", "b", "c"}, tc.records, false)
		if err != nil || exit != tc.exit {
			t.Fatalf("exit = %d, err = %v", exit, err)
		}
		if err := schema.Validate(writerJSON(t, data)); err != nil {
			t.Fatal(err)
		}
		var b Batch
		if err := json.Unmarshal(data, &b); err != nil {
			t.Fatal(err)
		}
		if err := b.ValidateSummary(exit); err != nil {
			t.Fatal(err)
		}
		if b.Complete || b.Status != tc.status || b.Counts != tc.counts || b.RequestsUsed != tc.used {
			t.Fatalf("wrong batch aggregation: %s", data)
		}
	}
	assertNoWriterOutput(t, []string{"a"}, nil)
	assertNoWriterOutput(t, []string{"a"}, []Record{inconclusive, fail})
	assertNoWriterOutput(t, []string{"a", "a"}, []Record{inconclusive})
	assertNoWriterOutput(t, []string{"a", strings.Repeat("x", 65)}, []Record{inconclusive})
	assertNoWriterOutput(t, []string{"b", "a"}, []Record{inconclusive})
}
