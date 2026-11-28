package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/natori-hrj/vintar/internal/decision"
)

func TestObservationStopInvariantMatrix(t *testing.T) {
	schema := writerSchema(t)
	type evaluate func() (decision.Result, error)
	confirmation := func(reason, condition string, count int64, sequence int) evaluate {
		return func() (decision.Result, error) {
			observations := writerBoolean().Verification.Observations
			for _, i := range []int{4, 5} {
				observations[i].BodyDigest = strings.Repeat("c", 64)
			}
			return decision.EvaluateBoolean(decision.BooleanInput{
				Observations: observations, RequestCount: 6,
				Confirmation: &decision.Confirmation{Configured: true, Status: "operational", Reason: &reason, RequestCount: count},
				ConfirmationFacts: decision.Facts{Operational: &decision.OperationalFacts{
					Stage: "confirmation", Sequence: sequence, Kind: "baseline", Condition: condition,
				}},
			})
		}
	}
	for _, tc := range []struct {
		name  string
		count int64
		stop  int
		run   evaluate
	}{
		{"initial-before-budget", 0, 1, func() (decision.Result, error) {
			return decision.EvaluateBoolean(decision.BooleanInput{BudgetUnavailable: true})
		}},
		{"initial-failure", 2, 2, func() (decision.Result, error) {
			return decision.EvaluateBoolean(decision.BooleanInput{
				Observations: writerBoolean().Verification.Observations[:1], RequestCount: 2,
				Failures: []decision.Failure{{Kind: "true", Reason: "timeout"}},
			})
		}},
		{"confirmation-before-budget", 6, 7, confirmation("confirmation_budget_unavailable", "budget_unavailable", 0, 7)},
		{"confirmation-first-timeout", 7, 7, confirmation("confirmation_timeout", "timeout", 1, 7)},
		{"time-incomplete-empty", 0, 1, func() (decision.Result, error) { return decision.EvaluateTime(decision.TimeInput{}) }},
		{"time-incomplete-prefix", 8, 9, func() (decision.Result, error) {
			return decision.EvaluateTime(decision.TimeInput{RequestCount: 8})
		}},
		{"time-terminal", 2, 2, func() (decision.Result, error) {
			return decision.EvaluateTime(decision.TimeInput{RequestCount: 2, Terminal: &decision.OperationalFacts{
				Stage: "time", Sequence: 2, Kind: "control", Condition: "timeout",
			}})
		}},
		{"error-second-timeout", 2, 2, func() (decision.Result, error) {
			return decision.EvaluateError(decision.ErrorInput{Observations: []decision.ErrorObservation{
				{Kind: "baseline", StatusCode: 200}, {Kind: "probe", Failure: "timeout"},
			}})
		}},
		{"error-second-rate-limit", 2, 2, func() (decision.Result, error) {
			return decision.EvaluateError(decision.ErrorInput{Observations: []decision.ErrorObservation{
				{Kind: "baseline", StatusCode: 200}, {Kind: "probe", StatusCode: 429, Truncated: true},
			}})
		}},
		{"error-completed-baseline-status", 4, 1, func() (decision.Result, error) {
			return decision.EvaluateError(decision.ErrorInput{Observations: []decision.ErrorObservation{
				{Kind: "baseline", StatusCode: 503}, {Kind: "probe", StatusCode: 200},
				{Kind: "baseline", StatusCode: 503}, {Kind: "probe", StatusCode: 200},
			}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.run()
			if err != nil || result.RequestCount != tc.count || result.Facts.Operational == nil ||
				result.Facts.Operational.Sequence != tc.stop {
				t.Fatalf("invalid matrix fixture: %v", err)
			}
			planned := []string{"valid", "second"}
			records := []Record{{"valid", decision.Inconclusive, result}}
			wire, exit, err := MarshalBatch(planned, records, false)
			if err != nil || exit != 3 || len(wire) == 0 {
				t.Fatalf("valid stop: exit=%d, err=%v", exit, err)
			}
			if err := schema.Validate(writerJSON(t, wire)); err != nil {
				t.Fatal(err)
			}
			// Include a valid prefix. An invalid second result must not
			// cause even the prefix to be written.
			records = append(records, Record{"second", decision.Inconclusive, result})
			f := *result.Facts.Operational
			for seq := range 20 {
				if seq == tc.stop || (result.Check == decision.Error && result.Reason == "non_success_status" && seq == 2) {
					// A complete Error summary may point to either representative.
					continue
				}
				t.Run(fmt.Sprintf("sequence-%d", seq), func(t *testing.T) {
					mutated := f
					mutated.Sequence = seq
					if f.Stage == "error" && seq >= 1 && seq <= 4 {
						// Keep the kind positionally valid to isolate the sequence invariant.
						mutated.Kind = []string{"baseline", "error"}[(seq-1)%2]
					}
					records[1].Decision.Facts.Operational = &mutated
					assertNoWriterOutput(t, planned, records)
				})
			}
			for _, change := range []func(*decision.OperationalFacts){
				func(f *decision.OperationalFacts) { f.Stage = "wrong" },
				func(f *decision.OperationalFacts) { f.Kind = "wrong" },
				func(f *decision.OperationalFacts) { f.Condition = "wrong" },
			} {
				mutated := f
				change(&mutated)
				records[1].Decision.Facts.Operational = &mutated
				assertNoWriterOutput(t, planned, records)
			}
			records[1].Decision = result
			records[1].Decision.RequestCount++
			assertNoWriterOutput(t, planned, records)
		})
	}
}

func TestIncompleteObservationShapes(t *testing.T) {
	samples := writerBoolean().Verification.Observations[:1]
	incomplete, err := decision.EvaluateBoolean(decision.BooleanInput{RequestCount: 1, Observations: samples})
	if err != nil || incomplete.Reason != "insufficient_evidence" {
		t.Fatalf("invalid incomplete Boolean fixture: %v", err)
	}
	plan := []string{"case"}
	if _, exit, err := MarshalBatch(plan, []Record{{"case", decision.Inconclusive, incomplete}}, false); err != nil || exit != 3 {
		t.Fatalf("valid incomplete Boolean should write exit 3: %d, %v", exit, err)
	}
	for _, tc := range []struct {
		name string
		run  func() (decision.Result, error)
	}{
		{"Boolean budget with a completed observation", func() (decision.Result, error) {
			return decision.EvaluateBoolean(decision.BooleanInput{RequestCount: 1, Observations: samples, BudgetUnavailable: true})
		}},
		{"Time predicates with incomplete observations", func() (decision.Result, error) {
			return decision.EvaluateTime(decision.TimeInput{RequestCount: 8, Predicates: &decision.TimingPredicates{NoDelayConditionMet: true}})
		}},
		{"Error prefix without a terminal observation", func() (decision.Result, error) {
			return decision.EvaluateError(decision.ErrorInput{Observations: []decision.ErrorObservation{{Kind: "baseline", StatusCode: 200}}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := tc.run()
			if err == nil {
				t.Fatal("constructor accepted inconsistent evidence")
			}
			assertNoWriterOutput(t, plan, []Record{{"case", decision.Inconclusive, r}})
		})
	}
}

func TestTimingCauseInvariantMatrix(t *testing.T) {
	result, err := decision.EvaluateTime(decision.TimeInput{
		RequestCount: 9, Predicates: &decision.TimingPredicates{DriftExceeded: true},
	})
	if err != nil || result.Reason != "unstable_timing" {
		t.Fatalf("invalid timing fixture: %v", err)
	}
	plan := []string{"case"}
	order := [...]string{"baseline_span", "control_span", "baseline_control_difference", "drift", "delay_span"}
	for mask := range 1 << len(order) {
		t.Run(fmt.Sprintf("causes-%05b", mask), func(t *testing.T) {
			var causes []string
			for i, cause := range order {
				if mask&(1<<i) != 0 {
					causes = append(causes, cause)
				}
			}
			record := result
			record.Facts.Timing = &decision.TimingFacts{InstabilityCauses: causes}
			batch := []Record{{"case", decision.Inconclusive, record}}
			// Drift replaces the two span causes; it does not replace the
			// baseline/control difference or delay span causes.
			if mask == 0 || (mask&0b01000 != 0 && mask&0b00011 != 0) {
				assertNoWriterOutput(t, plan, batch)
				return
			}
			if data, exit, err := MarshalBatch(plan, batch, false); err != nil || exit != 3 || len(data) == 0 {
				t.Fatalf("valid cause combination: exit=%d, err=%v", exit, err)
			}
		})
	}
}
