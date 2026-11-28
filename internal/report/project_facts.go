package report

import "github.com/natori-hrj/vintar/internal/decision"

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
