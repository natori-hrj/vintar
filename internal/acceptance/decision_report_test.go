package acceptance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/natori-hrj/vintar/internal/decision"
	"github.com/natori-hrj/vintar/internal/report"
)

func TestOfflineDecisionReportGoldens(t *testing.T) {
	root := repoRoot(t)
	schema := publishedSchemas(t, root)[batchSchema]
	for _, name := range []string{
		"pass", "fail", "partial-inconclusive", "time-candidate", "time-not-detected",
		"error-disclosed", "error-not-detected", "mixed-boolean-time", "mixed-boolean-time-error",
	} {
		t.Run(name, func(t *testing.T) {
			golden := readFixture(t, root, "tests/golden/cli/verify/"+name+".json")
			var expected struct {
				Exit  int             `json:"exit_code"`
				Batch json.RawMessage `json:"stdout_json"`
			}
			if err := json.Unmarshal(golden, &expected); err != nil {
				t.Fatal(err)
			}
			var saved struct {
				Planned  []string `json:"planned_case_ids"`
				Outcomes []struct {
					CaseID       string           `json:"case_id"`
					Expected     decision.Verdict `json:"expected_verdict"`
					Check        decision.Check   `json:"check_type"`
					Verification struct {
						RequestCount int64                  `json:"request_count"`
						Observations []decision.Observation `json:"observations"`
						Failures     []decision.Failure     `json:"failures"`
					} `json:"verification"`
				} `json:"outcomes"`
			}
			if err := json.Unmarshal(expected.Batch, &saved); err != nil {
				t.Fatal(err)
			}
			records := make([]report.Record, 0, len(saved.Outcomes))
			for _, input := range saved.Outcomes {
				var result decision.Result
				var err error
				switch input.Check {
				case "": // v0.6.0 Boolean outcomes omit the outer check_type.
					v := input.Verification
					result, err = decision.EvaluateBoolean(decision.BooleanInput{
						Observations: v.Observations, Failures: v.Failures, RequestCount: v.RequestCount,
					})
				case decision.Time:
					// The public goldens carry only derived timing status.
					// Supply synthetic comparison facts, not that status.
					predicates := decision.TimingPredicates{CandidateMedianMet: true, CandidateMarginMet: true}
					if name == "time-not-detected" {
						predicates = decision.TimingPredicates{NoDelayConditionMet: true}
					}
					result, err = decision.EvaluateTime(decision.TimeInput{RequestCount: 9, Predicates: &predicates})
				case decision.Error:
					observations := []decision.ErrorObservation{
						{Kind: "baseline", StatusCode: 200}, {Kind: "probe", StatusCode: 200},
						{Kind: "baseline", StatusCode: 200}, {Kind: "probe", StatusCode: 200},
					}
					if name == "error-disclosed" {
						for _, i := range []int{1, 3} {
							observations[i].Matches = []decision.Signature{{DBMS: "sqlite", ID: "sqlite_operational_syntax"}}
						}
					}
					result, err = decision.EvaluateError(decision.ErrorInput{Observations: observations})
				default:
					t.Fatal("unexpected check type in release fixture")
				}
				if err != nil {
					t.Fatalf("evaluate saved evidence: %v", err)
				}
				records = append(records, report.Record{CaseID: input.CaseID, Expected: input.Expected, Decision: result})
			}
			for _, pretty := range []bool{false, true} {
				got, exit, err := report.MarshalBatch(saved.Planned, records, pretty)
				if err != nil || exit != expected.Exit || !bytes.HasSuffix(got, []byte("\n")) {
					t.Fatalf("encode batch: exit=%d, err=%v", exit, err)
				}
				equivalentJSON(t, got, expected.Batch)
				if err := schema.Validate(decodeSchemaJSON(t, "offline batch", got)); err != nil {
					t.Fatalf("generated batch v1 is invalid: %v", err)
				}
				repeat, repeatExit, err := report.MarshalBatch(saved.Planned, records, pretty)
				if err != nil || repeatExit != exit || !bytes.Equal(repeat, got) {
					t.Fatal("report serialization was not deterministic")
				}
			}
		})
	}
}

func TestOfflineRecordedConfirmationStaysInconclusive(t *testing.T) {
	root := repoRoot(t)
	schema := publishedSchemas(t, root)[batchSchema]
	observations := make([]decision.Observation, 0, 6)
	for _, kind := range []string{"baseline", "true", "false"} {
		digit := "a"
		if kind == "false" {
			digit = "b"
		}
		observation := decision.Observation{Kind: kind, StatusCode: 200, BodySize: 1, BodyDigest: strings.Repeat(digit, 64)}
		observations = append(observations, observation, observation)
	}
	reason := "confirmation_pattern_matched"
	result, err := decision.EvaluateBoolean(decision.BooleanInput{
		Observations: observations,
		RequestCount: 6,
		Confirmation: &decision.Confirmation{Configured: true, Status: "matched", Reason: &reason, RequestCount: 12},
	})
	if err != nil || result.Verdict != decision.Inconclusive || result.Reason != "boolean_candidate" || result.RequestCount != 18 {
		t.Fatalf("saved confirmation did not preserve released decision semantics: %v", err)
	}
	got, exit, err := report.MarshalBatch([]string{"example"}, []report.Record{
		{CaseID: "example", Expected: decision.Inconclusive, Decision: result},
	}, false)
	if err != nil || exit != 3 {
		t.Fatalf("matched confirmation must be reported as inconclusive: exit=%d, err=%v", exit, err)
	}
	if err := schema.Validate(decodeSchemaJSON(t, "saved confirmation", got)); err != nil {
		t.Fatalf("confirmation report is invalid: %v", err)
	}
}

func TestOfflineIncompleteTimingReport(t *testing.T) {
	root := repoRoot(t)
	schema := publishedSchemas(t, root)[batchSchema]
	result, err := decision.EvaluateTime(decision.TimeInput{RequestCount: 0})
	if err != nil || result.Verdict != decision.Inconclusive || result.Reason != "incomplete_probes" {
		t.Fatalf("unstarted timing evidence did not stay inconclusive: %v", err)
	}
	payload, exit, err := report.MarshalBatch([]string{"first", "not-run"}, []report.Record{
		{CaseID: "first", Expected: decision.Inconclusive, Decision: result},
	}, false)
	if err != nil || exit != 3 {
		t.Fatalf("incomplete timing evidence did not produce exit 3: %v", err)
	}
	if err := schema.Validate(decodeSchemaJSON(t, "incomplete timing", payload)); err != nil {
		t.Fatalf("incomplete timing report is invalid: %v", err)
	}
	var batch report.Batch
	if err := json.Unmarshal(payload, &batch); err != nil {
		t.Fatal(err)
	}
	if batch.Complete || batch.RequestsUsed != 0 || batch.Counts.Inconclusive != 1 || batch.Counts.NotRun != 1 {
		t.Fatal("incomplete timing report lost not-run or request accounting")
	}
}
