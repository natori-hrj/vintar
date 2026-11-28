package report

import "github.com/natori-hrj/vintar/internal/decision"

func validFacts(r decision.Result) bool {
	f := r.Facts
	members := 0
	for _, present := range []bool{f.Operational != nil, f.Response != nil, f.Confirmation != nil, f.Timing != nil} {
		if present {
			members++
		}
	}
	if members == 0 {
		// The reader schema also accepts older reports. The released writer
		// requires facts for these non-decisions and does not invent them.
		switch r.Check {
		case decision.Boolean:
			return !oneOf(r.Reason, "budget_unavailable", "probe_failed", "rate_limited", "truncated_response",
				"non_success_status", "possible_dynamic_response", "unstable_response",
				"confirmation_budget_unavailable", "confirmation_preflight_failed", "confirmation_budget_exceeded",
				"confirmation_rate_limit_interrupted", "confirmation_timeout", "confirmation_request_failed",
				"confirmation_rate_limited", "confirmation_truncated", "confirmation_non_success_status",
				"confirmation_unstable", "candidate_confirmation_mismatch", "confirmation_cross_phase_mismatch")
		case decision.Time:
			return oneOf(r.Reason, "timing_pattern_matched", "timing_pattern_not_matched")
		}
		return true
	}
	if members != 1 || r.Verdict != decision.Inconclusive {
		return false
	}
	switch {
	case f.Operational != nil:
		return validOperationalFacts(r, f.Operational)
	case f.Response != nil:
		return r.Check == decision.Boolean && validResponseFacts(r.Reason, f.Response)
	case f.Confirmation != nil:
		return r.Check == decision.Boolean && validConfirmationFacts(r.Reason, f.Confirmation)
	default:
		return r.Check == decision.Time && validTimingFacts(r.Reason, f.Timing)
	}
}

func validOperationalFacts(r decision.Result, f *decision.OperationalFacts) bool {
	if f.Sequence < 1 || f.Sequence > 18 {
		return false
	}
	switch r.Check {
	case decision.Boolean:
		if r.Confirmation != nil && r.Confirmation.Status == "operational" {
			// Confirmation facts use the combined initial/confirmation sequence.
			if f.Stage != "confirmation" || int64(f.Sequence) <= r.Verification.RequestCount || !confirmationKind(f.Kind) ||
				int64(f.Sequence) > r.RequestCount+1 || !confirmationCondition(r.Reason, f.Condition) {
				return false
			}
		} else {
			if f.Stage != "initial" || !booleanKind(f.Kind) {
				return false
			}
			switch r.Reason {
			case "budget_unavailable":
				if f.Sequence != 1 || f.Condition != "budget_unavailable" {
					return false
				}
			case "probe_failed":
				if int64(f.Sequence) > r.RequestCount || !failureReason(f.Condition) {
					return false
				}
			default:
				if int64(f.Sequence) > r.RequestCount || !responseCondition(r.Reason, f.Condition) {
					return false
				}
			}
		}
	case decision.Time:
		// These positions are public report metadata, not request settings.
		order := [...]string{"baseline", "control", "delay", "control", "delay", "baseline", "delay", "baseline", "control"}
		sequence := r.RequestCount
		if r.Reason == "incomplete_probes" {
			sequence++
		}
		if f.Stage != "time" || f.Sequence > len(order) || int64(f.Sequence) != sequence ||
			f.Kind != order[f.Sequence-1] || !timingCondition(r.Reason, f.Condition) {
			return false
		}
	case decision.Error:
		order := [...]string{"baseline", "error", "baseline", "error"}
		if f.Stage != "error" || f.Sequence > len(order) || int64(f.Sequence) > r.RequestCount ||
			f.Kind != order[f.Sequence-1] || !errorCondition(r.Reason, f.Condition) {
			return false
		}
	default:
		return false
	}

	switch f.Condition {
	case "rate_limited":
		return f.StatusCode != nil && *f.StatusCode == 429
	case "truncated":
		return f.StatusCode != nil && validHTTP(*f.StatusCode) && *f.StatusCode != 429
	case "non_success_status":
		return f.StatusCode != nil && validHTTP(*f.StatusCode) && *f.StatusCode != 429 &&
			(*f.StatusCode < 200 || *f.StatusCode > 299)
	default:
		return f.StatusCode == nil
	}
}

func responseCondition(reason, condition string) bool {
	switch reason {
	case "rate_limited", "non_success_status":
		return condition == reason
	case "truncated_response":
		return condition == "truncated"
	}
	return false
}

func timingCondition(reason, condition string) bool {
	switch reason {
	case "incomplete_probes":
		return condition == "deadline"
	case "probe_timeout":
		return condition == "timeout"
	case "probe_failed":
		return condition == "request_failed"
	case "probe_interrupted":
		return oneOf(condition, "interrupted", "deadline")
	}
	return responseCondition(reason, condition)
}

func errorCondition(reason, condition string) bool {
	switch reason {
	case "probe_timeout":
		return condition == "timeout"
	case "probe_failed":
		return oneOf(condition, "connection", "response_read", "unknown")
	case "probe_interrupted":
		return oneOf(condition, "rate_limit", "cancelled")
	}
	return responseCondition(reason, condition)
}

func confirmationCondition(reason, condition string) bool {
	switch reason {
	case "confirmation_budget_unavailable":
		return condition == "budget_unavailable"
	case "confirmation_preflight_failed":
		return condition == "preflight_failed"
	case "confirmation_budget_exceeded":
		return condition == "budget_exceeded"
	case "confirmation_rate_limit_interrupted":
		return condition == "rate_limit_interrupted"
	case "confirmation_timeout":
		return condition == "timeout"
	case "confirmation_request_failed":
		return oneOf(condition, "connection", "response_read", "unknown")
	case "confirmation_rate_limited":
		return condition == "rate_limited"
	case "confirmation_truncated":
		return condition == "truncated"
	case "confirmation_non_success_status":
		return condition == "non_success_status"
	}
	return false
}

func confirmationKind(kind string) bool {
	return oneOf(kind, "baseline", "true_1", "false_1", "baseline_preserving_control", "true_2", "false_2")
}

func validResponseFacts(reason string, f *decision.ResponseFacts) bool {
	if !oneOf(reason, "possible_dynamic_response", "unstable_response") ||
		!validCount(f.NormalizedEchoCount) || f.NormalizationApplied != (f.NormalizedEchoCount > 0) ||
		len(f.UnstablePairs) < 1 || len(f.UnstablePairs) > 3 {
		return false
	}
	allLocalized := true
	for _, pair := range f.UnstablePairs {
		if !booleanKind(pair.Kind) || !oneOf(pair.Localization, "localized", "unlocalized") {
			return false
		}
		localized := pair.Localization == "localized"
		allLocalized = allLocalized && localized
		for _, n := range []*int64{pair.PrefixSize, pair.SuffixSize, pair.FirstChangedSize, pair.SecondChangedSize} {
			if localized != (n != nil) || (n != nil && !validCount(*n)) {
				return false
			}
		}
	}
	return (reason == "possible_dynamic_response") == allLocalized
}

func uniqueEnums(values []string, allowed func(string) bool) bool {
	seen := make(map[string]bool)
	for _, value := range values {
		if !allowed(value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func validConfirmationFacts(reason string, f *decision.ConfirmationFacts) bool {
	if !uniqueEnums(f.UnstableRepeatKinds, confirmationKind) ||
		!uniqueEnums(f.UnreproducedPredicatePairs, func(s string) bool { return oneOf(s, "true", "false") }) ||
		!uniqueEnums(f.MismatchedRelations, func(s string) bool { return oneOf(s, "baseline_true", "baseline_control", "baseline_false") }) ||
		!uniqueEnums(f.CrossPhaseMismatchedKinds, booleanKind) {
		return false
	}
	unstable := len(f.UnstableRepeatKinds) != 0 || len(f.UnreproducedPredicatePairs) != 0
	mismatch := len(f.MismatchedRelations) != 0
	crossPhase := len(f.CrossPhaseMismatchedKinds) != 0
	return unstable == (reason == "confirmation_unstable") &&
		mismatch == (reason == "candidate_confirmation_mismatch") &&
		crossPhase == (reason == "confirmation_cross_phase_mismatch") &&
		(unstable || mismatch || crossPhase)
}

func validTimingFacts(reason string, f *decision.TimingFacts) bool {
	switch reason {
	case "unstable_timing":
		return len(f.InstabilityCauses) > 0 && f.CandidateMedianMet == nil && f.CandidateMarginMet == nil &&
			f.NoDelayConditionMet == nil && uniqueEnums(f.InstabilityCauses, func(s string) bool {
			return oneOf(s, "baseline_span", "control_span", "baseline_control_difference", "drift", "delay_span")
		})
	case "ambiguous_timing":
		return len(f.InstabilityCauses) == 0 && f.CandidateMedianMet != nil && f.CandidateMarginMet != nil &&
			f.NoDelayConditionMet != nil && !(*f.CandidateMedianMet && *f.CandidateMarginMet) && !*f.NoDelayConditionMet
	}
	return false
}

func factStrings(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

func projectFacts(f decision.Facts) object {
	switch {
	case f.Operational != nil:
		v := f.Operational
		o := object{
			"category": "operational", "stage": v.Stage, "sequence": v.Sequence,
			"probe_kind": v.Kind, "condition": v.Condition,
		}
		if v.StatusCode != nil {
			o["status_code"] = *v.StatusCode
		}
		return o
	case f.Response != nil:
		v := f.Response
		pairs := make([]object, 0, len(v.UnstablePairs))
		for _, pair := range v.UnstablePairs {
			p := object{"probe_kind": pair.Kind, "localization": pair.Localization}
			if pair.Localization == "localized" {
				p["prefix_size"], p["suffix_size"] = *pair.PrefixSize, *pair.SuffixSize
				p["first_changed_size"], p["second_changed_size"] = *pair.FirstChangedSize, *pair.SecondChangedSize
			}
			pairs = append(pairs, p)
		}
		return object{
			"category": "response_dynamics", "normalization_applied": v.NormalizationApplied,
			"normalized_echo_count": v.NormalizedEchoCount, "unstable_pairs": pairs,
		}
	case f.Confirmation != nil:
		v := f.Confirmation
		return object{
			"category": "confirmation_relation", "unstable_repeat_kinds": factStrings(v.UnstableRepeatKinds),
			"unreproduced_predicate_pairs": factStrings(v.UnreproducedPredicatePairs),
			"mismatched_relations":         factStrings(v.MismatchedRelations),
			"cross_phase_mismatched_kinds": factStrings(v.CrossPhaseMismatchedKinds),
		}
	case f.Timing != nil:
		v := f.Timing
		o := object{"category": "timing_dynamics", "instability_causes": factStrings(v.InstabilityCauses)}
		if v.CandidateMedianMet != nil {
			o["candidate_median_met"] = *v.CandidateMedianMet
			o["candidate_margin_met"] = *v.CandidateMarginMet
			o["no_delay_condition_met"] = *v.NoDelayConditionMet
		}
		return o
	}
	return nil
}
