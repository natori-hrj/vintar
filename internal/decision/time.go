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
	var reason string
	var facts Facts
	switch {
	case in.Terminal != nil:
		f := *in.Terminal
		if in.Predicates != nil {
			return Result{}, errInvalidEvidence
		}
		reason = timeStopReason(n, f)
		f.StatusCode = copyPointer(f.StatusCode)
		facts.Operational = &f
	case n < int64(len(timeKinds)):
		if in.Predicates != nil {
			return Result{}, errInvalidEvidence
		}
		reason = "incomplete_probes"
		facts.Operational = &OperationalFacts{
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
			reason = "unstable_timing"
			facts.Timing = &TimingFacts{InstabilityCauses: causes}
		case candidate:
			reason = "timing_pattern_matched"
		case p.NoDelayConditionMet:
			reason = "timing_pattern_not_matched"
		default:
			reason = "ambiguous_timing"
			facts.Timing = &TimingFacts{
				InstabilityCauses:   causes,
				CandidateMedianMet:  &p.CandidateMedianMet,
				CandidateMarginMet:  &p.CandidateMarginMet,
				NoDelayConditionMet: &p.NoDelayConditionMet,
			}
		}
	}
	return timeResult(n, reason, facts)
}

func timeStopReason(n int64, f OperationalFacts) string {
	if f.Stage != "time" || f.Sequence < 1 || f.Sequence > len(timeKinds) ||
		f.Kind != timeKinds[f.Sequence-1] || !validOperationalStatus(f) {
		return ""
	}
	if f.Condition == "deadline" && int64(f.Sequence) == n+1 {
		return "incomplete_probes"
	}
	if int64(f.Sequence) != n {
		return ""
	}
	switch f.Condition {
	case "timeout":
		return "probe_timeout"
	case "request_failed":
		return "probe_failed"
	case "interrupted", "deadline":
		return "probe_interrupted"
	case "rate_limited", "truncated", "non_success_status":
		return responseReason(f.Condition)
	}
	return ""
}

// timeResult is shared by assessment and validation of saved summaries.
func timeResult(n int64, reason string, facts Facts) (Result, error) {
	if n < 0 || n > int64(len(timeKinds)) || reason == "" {
		return Result{}, errInvalidEvidence
	}
	verdict, status := Inconclusive, "inconclusive"
	if facts.Operational != nil {
		if facts.Timing != nil || timeStopReason(n, *facts.Operational) != reason {
			return Result{}, errInvalidEvidence
		}
	} else {
		if n != int64(len(timeKinds)) {
			return Result{}, errInvalidEvidence
		}
		switch reason {
		case "timing_pattern_matched":
			status = "candidate"
		case "timing_pattern_not_matched":
			verdict, status = NotDetected, "not_confirmed"
		case "unstable_timing", "ambiguous_timing":
		default:
			return Result{}, errInvalidEvidence
		}
		if !validTimingFacts(reason, facts.Timing) {
			return Result{}, errInvalidEvidence
		}
	}
	return Result{
		Check: Time, Verdict: verdict, Reason: reason, RequestCount: n,
		Timing: &Timing{Status: status, Reason: reason, RequestCount: n}, Facts: facts,
	}, nil
}

func validTimingFacts(reason string, f *TimingFacts) bool {
	switch reason {
	case "unstable_timing":
		return f != nil && len(f.InstabilityCauses) != 0 &&
			orderedSubset(f.InstabilityCauses, []string{"baseline_span", "control_span", "baseline_control_difference", "drift", "delay_span"}) &&
			f.CandidateMedianMet == nil && f.CandidateMarginMet == nil && f.NoDelayConditionMet == nil
	case "ambiguous_timing":
		return f != nil && len(f.InstabilityCauses) == 0 && f.CandidateMedianMet != nil &&
			f.CandidateMarginMet != nil && f.NoDelayConditionMet != nil &&
			!(*f.CandidateMedianMet && *f.CandidateMarginMet) && !*f.NoDelayConditionMet
	default:
		return f == nil
	}
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
