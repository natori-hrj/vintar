package decision

import "errors"

var errInvalidEvidence = errors.New("invalid saved decision evidence")

// This order only identifies positions in saved timing evidence.
var timeKinds = [...]string{"baseline", "control", "delay", "control", "delay", "baseline", "delay", "baseline", "control"}

// EvaluateTime classifies recorded timing predicates or a recorded stop.
func EvaluateTime(in TimeInput) (Result, error) {
	n := in.RequestCount
	if n < 0 || n > int64(len(timeKinds)) {
		return Result{}, errInvalidEvidence
	}
	result := Result{Check: Time, Verdict: Inconclusive, RequestCount: n}
	status := "inconclusive"
	switch {
	case in.Terminal != nil:
		f := *in.Terminal
		if in.Predicates != nil || f.Stage != "time" || f.Sequence < 1 ||
			f.Sequence > len(timeKinds) || f.Kind != timeKinds[f.Sequence-1] ||
			!validOperationalStatus(f) {
			return Result{}, errInvalidEvidence
		}
		if f.Condition == "deadline" && int64(f.Sequence) == n+1 {
			result.Reason = "incomplete_probes"
		} else if int64(f.Sequence) != n {
			return Result{}, errInvalidEvidence
		} else {
			switch f.Condition {
			case "timeout":
				result.Reason = "probe_timeout"
			case "request_failed":
				result.Reason = "probe_failed"
			case "interrupted", "deadline":
				result.Reason = "probe_interrupted"
			case "rate_limited", "truncated", "non_success_status":
				result.Reason = responseReason(f.Condition)
			default:
				return Result{}, errInvalidEvidence
			}
		}
		f.StatusCode = copyPointer(f.StatusCode)
		result.Facts.Operational = &f
	case n < int64(len(timeKinds)):
		if in.Predicates != nil {
			return Result{}, errInvalidEvidence
		}
		result.Reason = "incomplete_probes"
		result.Facts.Operational = &OperationalFacts{
			Stage: "time", Sequence: int(n) + 1, Kind: timeKinds[n], Condition: "deadline",
		}
	case in.Predicates == nil:
		return Result{}, errInvalidEvidence
	default:
		p := *in.Predicates
		causes := make([]string, 0, 5)
		for _, cause := range []struct {
			name string
			met  bool
		}{
			{"baseline_span", p.BaselineSpanExceeded && !p.DriftExceeded},
			{"control_span", p.ControlSpanExceeded && !p.DriftExceeded},
			{"baseline_control_difference", p.BaselineControlDifferenceExceeded},
			{"drift", p.DriftExceeded},
			{"delay_span", p.DelaySpanExceeded},
		} {
			if cause.met {
				causes = append(causes, cause.name)
			}
		}
		candidate := p.CandidateMedianMet && p.CandidateMarginMet
		baselineControlUnstable := len(causes) != 0 && causes[0] != "delay_span"
		switch {
		case baselineControlUnstable || (p.DelaySpanExceeded && !candidate):
			result.Reason = "unstable_timing"
			result.Facts.Timing = &TimingFacts{InstabilityCauses: causes}
		case candidate:
			result.Reason, status = "timing_pattern_matched", "candidate"
		case p.NoDelayConditionMet:
			result.Reason, status, result.Verdict = "timing_pattern_not_matched", "not_confirmed", NotDetected
		default:
			result.Reason = "ambiguous_timing"
			result.Facts.Timing = &TimingFacts{
				InstabilityCauses:   causes,
				CandidateMedianMet:  &p.CandidateMedianMet,
				CandidateMarginMet:  &p.CandidateMarginMet,
				NoDelayConditionMet: &p.NoDelayConditionMet,
			}
		}
	}
	result.Timing = &Timing{Status: status, Reason: result.Reason, RequestCount: n}
	return result, nil
}

func validStatus(status int) bool   { return status >= 100 && status <= 599 }
func successStatus(status int) bool { return status >= 200 && status <= 299 }

func responseCondition(status int, truncated bool) string {
	switch {
	case status == 429:
		return "rate_limited"
	case truncated:
		return "truncated"
	case !successStatus(status):
		return "non_success_status"
	default:
		return ""
	}
}

func responseReason(condition string) string {
	if condition == "truncated" {
		return "truncated_response"
	}
	return condition
}

func validOperationalStatus(f OperationalFacts) bool {
	switch f.Condition {
	case "rate_limited", "truncated", "non_success_status":
		return f.StatusCode != nil && validStatus(*f.StatusCode) &&
			responseCondition(*f.StatusCode, f.Condition == "truncated") == f.Condition
	default:
		return f.StatusCode == nil
	}
}

func copyPointer[T any](p *T) *T {
	if p == nil {
		return nil
	}
	value := *p
	return &value
}
