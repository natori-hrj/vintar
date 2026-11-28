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
	result := Result{Check: Error, Verdict: Inconclusive, RequestCount: int64(len(obs))}
	analysis := ErrorAnalysis{Status: "inconclusive", RequestCount: result.RequestCount}
	finish := func(reason string) (Result, error) {
		result.Reason, analysis.Reason = reason, reason
		result.Error = &analysis
		return result, nil
	}
	stop := func(i int, condition string, status *int) {
		kind := "baseline"
		if i%2 == 1 {
			kind = "error"
		}
		result.Facts.Operational = &OperationalFacts{
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
			var reason string
			switch o.Failure {
			case "timeout":
				reason = "probe_timeout"
			case "connection", "response_read", "unknown":
				reason = "probe_failed"
			case "rate_limit", "cancelled":
				reason = "probe_interrupted"
			default:
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
		analysis.Status, result.Verdict = "not_matched", NotDetected
		return finish("dbms_error_not_observed")
	case len(p.Matches) != 1:
		return finish("ambiguous_dbms_error")
	default:
		analysis.Status, analysis.DBMS, analysis.SignatureID = "matched", p.Matches[0].DBMS, p.Matches[0].ID
		return finish("dbms_error_disclosed")
	}
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
