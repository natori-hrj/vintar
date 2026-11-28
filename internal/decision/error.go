package decision

import (
	"errors"
	"slices"
)

var errIncompleteErrorEvidence = errors.New("incomplete saved error evidence without a terminal condition")

// EvaluateError classifies only registered matches from recorded observations.
func EvaluateError(in ErrorInput) (Result, error) {
	obs := in.Observations
	if len(obs) > 4 {
		return Result{}, errInvalidEvidence
	}
	var signature Signature
	var facts *OperationalFacts
	finish := func(reason string) (Result, error) {
		return errorResult(int64(len(obs)), reason, signature, facts)
	}
	stop := func(i int, condition string, status *int) {
		kind := "baseline"
		if i%2 == 1 {
			kind = "error"
		}
		facts = &OperationalFacts{
			Stage: "error", Sequence: i + 1, Kind: kind, Condition: condition, StatusCode: status,
		}
	}
	for i, o := range obs {
		if (i%2 == 0 && o.Kind != "baseline") ||
			(i%2 == 1 && o.Kind != "probe" && o.Kind != "error") {
			return Result{}, errInvalidEvidence
		}
		if o.Failure != "" {
			if i != len(obs)-1 || o.StatusCode != 0 || o.Truncated || len(o.Matches) != 0 {
				return Result{}, errInvalidEvidence
			}
			reason := errorStopReason(o.Failure)
			if reason == "" {
				return Result{}, errInvalidEvidence
			}
			stop(i, o.Failure, nil)
			return finish(reason)
		}
		if !validStatus(o.StatusCode) || !validMatches(o.Matches) {
			return Result{}, errInvalidEvidence
		}
		condition := responseCondition(o.StatusCode, o.Truncated)
		if condition == "rate_limited" || condition == "truncated" {
			if i != len(obs)-1 {
				return Result{}, errInvalidEvidence
			}
			stop(i, condition, &o.StatusCode)
			return finish(responseReason(condition))
		}
	}
	if len(obs) != 4 {
		return Result{}, errIncompleteErrorEvidence
	}

	b, p := obs[0], obs[1]
	switch {
	case b.StatusCode != obs[2].StatusCode || p.StatusCode != obs[3].StatusCode:
		return finish("unstable_response")
	case !slices.Equal(b.Matches, obs[2].Matches):
		return finish("unstable_error_signal")
	case len(b.Matches) != 0:
		return finish("baseline_dbms_error")
	case !slices.Equal(p.Matches, obs[3].Matches):
		return finish("unstable_error_signal")
	case !successStatus(b.StatusCode):
		stop(0, "non_success_status", &b.StatusCode)
		return finish("non_success_status")
	case len(p.Matches) == 0:
		if !successStatus(p.StatusCode) {
			stop(1, "non_success_status", &p.StatusCode)
			return finish("non_success_status")
		}
		return finish("dbms_error_not_observed")
	case len(p.Matches) != 1:
		return finish("ambiguous_dbms_error")
	default:
		signature = p.Matches[0]
		return finish("dbms_error_disclosed")
	}
}

func errorStopReason(condition string) string {
	switch condition {
	case "timeout":
		return "probe_timeout"
	case "connection", "response_read", "unknown":
		return "probe_failed"
	case "rate_limit", "cancelled":
		return "probe_interrupted"
	case "rate_limited", "truncated", "non_success_status":
		return responseReason(condition)
	}
	return ""
}

// errorResult constructs and validates the same public summary for both a
// fresh decision and a saved summary. Terminal stops end at the last attempt.
// A non-success status can instead identify a representative of a completed pair.
func errorResult(n int64, reason string, signature Signature, f *OperationalFacts) (Result, error) {
	if n < 1 || n > 4 {
		return Result{}, errInvalidEvidence
	}
	verdict, status := Inconclusive, "inconclusive"
	switch reason {
	case "dbms_error_disclosed":
		if !KnownSignature(signature) {
			return Result{}, errInvalidEvidence
		}
		status = "matched"
	case "dbms_error_not_observed":
		verdict, status = NotDetected, "not_matched"
	}
	if reason != "dbms_error_disclosed" && signature != (Signature{}) {
		return Result{}, errInvalidEvidence
	}
	switch reason {
	case "dbms_error_disclosed", "dbms_error_not_observed", "baseline_dbms_error", "unstable_response",
		"unstable_error_signal", "ambiguous_dbms_error", "non_success_status":
		if n != 4 {
			return Result{}, errInvalidEvidence
		}
	case "truncated_response", "probe_timeout", "probe_failed", "probe_interrupted", "rate_limited":
	default:
		return Result{}, errInvalidEvidence
	}
	if f != nil {
		positionOK := int64(f.Sequence) == n
		if reason == "non_success_status" {
			positionOK = f.Sequence == 1 || f.Sequence == 2
		}
		if f.Stage != "error" || !positionOK || errorStopReason(f.Condition) != reason ||
			!validOperationalStatus(*f) {
			return Result{}, errInvalidEvidence
		}
		kind := "baseline"
		if f.Sequence%2 == 0 {
			kind = "error"
		}
		if f.Kind != kind {
			return Result{}, errInvalidEvidence
		}
	}
	return Result{
		Check: Error, Verdict: verdict, Reason: reason, RequestCount: n,
		Error: &ErrorAnalysis{Status: status, Reason: reason, RequestCount: n, DBMS: signature.DBMS, SignatureID: signature.ID},
		Facts: Facts{Operational: f},
	}, nil
}

func validMatches(matches []Signature) bool {
	for i, match := range matches {
		// The allowlist contains exactly one ID per DBMS. The saved set is
		// strictly ordered by DBMS, so duplicates cannot occur.
		if !KnownSignature(match) || (i > 0 && matches[i-1].DBMS >= match.DBMS) {
			return false
		}
	}
	return true
}
