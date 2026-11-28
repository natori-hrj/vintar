package report

import (
	"encoding/json"
	"errors"

	"github.com/natori-hrj/vintar/internal/decision"
)

// Record is one executed case and its typed, offline decision.
type Record struct {
	CaseID   string
	Expected decision.Verdict
	Decision decision.Result
}

var errBatchInput = errors.New("invalid batch report input")

// object is private to the projection. Maps give encoding/json a consistent
// lexicographic key order, including inside nested report sections.
type object map[string]any

// MarshalBatch produces one released-shape v1 report followed by a newline.
// Executed records must be a nonempty prefix of planned. An invalid input
// produces no report, exit code 2 and a fixed error that never echoes input.
func MarshalBatch(planned []string, executed []Record, pretty bool) ([]byte, int, error) {
	if len(executed) == 0 || len(executed) > len(planned) || len(planned) > maxCaseCount {
		return nil, 2, errBatchInput
	}
	seen := make(map[string]bool, len(planned))
	for _, id := range planned {
		if seen[id] || !caseID.MatchString(id) {
			return nil, 2, errBatchInput
		}
		seen[id] = true
	}

	outcomes := make([]object, 0, len(executed))
	counts := Counts{NotRun: len(planned) - len(executed)}
	var used int64
	for i, record := range executed {
		r := record.Decision
		if record.CaseID != planned[i] || !validVerdict(record.Expected) ||
			decision.ValidateResult(r) != nil || !validPublicProjection(r) || r.RequestCount > maxJSONCount-used {
			return nil, 2, errBatchInput
		}
		used += r.RequestCount
		match := r.Verdict == record.Expected
		status := (Outcome{ActualVerdict: string(r.Verdict), ExpectationMatch: match}).statusFromVerdict()
		switch status {
		case Pass:
			counts.Pass++
		case Fail:
			counts.Fail++
		case Inconclusive:
			counts.Inconclusive++
		default:
			return nil, 2, errBatchInput
		}
		outcomes = append(outcomes, projectOutcome(record, match, status))
	}
	status, exit := counts.result()
	doc := object{
		"schema_version":    BatchVersion,
		"report_type":       BatchType,
		"status":            status,
		"complete":          counts.NotRun == 0,
		"exit_code":         exit,
		"planned_case_ids":  planned,
		"executed_case_ids": planned[:len(executed)],
		"not_run_case_ids":  planned[len(executed):],
		"planned_count":     len(planned),
		"executed_count":    len(executed),
		"requests_used":     used,
		"outcomes":          outcomes,
		"counts": object{
			"pass": counts.Pass, "fail": counts.Fail,
			"inconclusive": counts.Inconclusive, "not_run": counts.NotRun,
		},
	}
	var data []byte
	var err error
	if pretty {
		data, err = json.MarshalIndent(doc, "", "  ")
	} else {
		data, err = json.Marshal(doc)
	}
	if err != nil {
		return nil, 2, errBatchInput
	}
	return append(data, '\n'), exit, nil
}

func projectOutcome(record Record, match bool, status Status) object {
	r := record.Decision
	o := object{
		"case_id": record.CaseID, "expected_verdict": record.Expected,
		"actual_verdict": r.Verdict, "actual_reason_code": r.Reason,
		"request_count": r.RequestCount, "expectation_match": match, "status": status,
	}
	switch r.Check {
	case decision.Boolean:
		c := r.Confirmation
		if c == nil {
			c = &decision.Confirmation{Status: "not_configured"}
		}
		o["confirmation"] = object{
			"configured": c.Configured, "status": c.Status, "reason_code": c.Reason,
			"request_count": c.RequestCount,
		}
		o["verification"] = projectVerification(r.Verification)
	case decision.Time:
		o["check_type"] = r.Check
		o["timing"] = projectAnalysis(r.Timing.Status, r.Timing.Reason, r.Timing.RequestCount)
	case decision.Error:
		o["check_type"] = r.Check
		e := r.Error
		section := projectAnalysis(e.Status, e.Reason, e.RequestCount)
		if e.Reason == "dbms_error_disclosed" {
			section["dbms"], section["signature_id"] = e.DBMS, e.SignatureID
		}
		o["error"] = section
	}
	if facts := projectFacts(r.Facts); facts != nil {
		o["decision_facts"] = facts
	}
	return o
}

func projectAnalysis(status, reason string, count int64) object {
	return object{"status": status, "reason_code": reason, "request_count": count}
}

func projectVerification(v *decision.Verification) object {
	observations := make([]object, 0, len(v.Observations))
	for _, o := range v.Observations {
		observations = append(observations, object{
			"kind": o.Kind, "status_code": o.StatusCode, "body_size": o.BodySize,
			"elapsed": o.Elapsed, "body_digest": o.BodyDigest, "truncated": o.Truncated,
		})
	}
	failures := make([]object, 0, len(v.Failures))
	for _, f := range v.Failures {
		failures = append(failures, object{"kind": f.Kind, "error": f.Reason, "elapsed": f.Elapsed})
	}
	var evidence object
	if e := v.Evidence; e != nil {
		evidence = object{
			"baseline_false_similarity": e.BaselineFalse,
			"baseline_true_similarity":  e.BaselineTrue,
			"true_false_similarity":     e.TrueFalse,
		}
	}
	return object{
		"schema_version": BatchVersion, "check_type": "sqli_boolean",
		"verdict": v.Verdict, "reason_code": v.Reason, "request_count": v.RequestCount,
		"observations": observations, "failures": failures, "evidence": evidence, "confidence": v.Confidence,
	}
}
