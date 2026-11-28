package decision

import (
	"math"
	"slices"
)

const maxReportCount = 1<<53 - 1

var booleanKinds = [...]string{"baseline", "true", "false", "baseline", "false", "true"}
var groupedBooleanIndexes = [...]int{0, 2, 4, 1, 5, 3}

// EvaluateBoolean classifies saved signatures and, when supplied, projects an
// already-recorded confirmation outcome.
func EvaluateBoolean(in BooleanInput) (Result, error) {
	obs := in.Observations
	n := len(obs)
	if n > len(booleanKinds) || len(in.Failures) > 1 ||
		in.RequestCount != int64(n+len(in.Failures)) || in.RequestCount > int64(len(booleanKinds)) ||
		(in.BudgetUnavailable && in.RequestCount != 0) ||
		!validCount(in.NormalizedEchoCount) {
		return Result{}, errInvalidEvidence
	}
	var indexes [6]int
	for i := range indexes {
		indexes[i] = i
	}
	// Completed analyzer reports group repeats. Recorded attempts can instead
	// arrive chronologically. Use chronological positions for facts in both
	// cases. The released complete analysis emits the grouped projection.
	if n == len(booleanKinds) && obs[1].Kind == "baseline" {
		indexes = groupedBooleanIndexes
	}
	for i, j := range indexes[:n] {
		if obs[j].Kind != booleanKinds[i] || !validObservation(obs[j]) ||
			(n < len(booleanKinds) && obs[j].StatusCode == 429 &&
				(i != n-1 || len(in.Failures) != 0)) {
			return Result{}, errInvalidEvidence
		}
	}

	signatures := obs
	if len(in.Normalized) != 0 {
		if n != len(booleanKinds) || len(in.Normalized) != n {
			return Result{}, errInvalidEvidence
		}
		for i, normalized := range in.Normalized {
			raw := obs[i]
			if !validObservation(normalized) || normalized.Kind != raw.Kind ||
				normalized.StatusCode != raw.StatusCode || normalized.Truncated != raw.Truncated ||
				normalized.Elapsed != raw.Elapsed ||
				(in.NormalizedEchoCount == 0 && !sameSignature(normalized, raw)) {
				return Result{}, errInvalidEvidence
			}
		}
		signatures = in.Normalized
	} else if in.NormalizedEchoCount != 0 {
		return Result{}, errInvalidEvidence
	}

	v := &Verification{
		Verdict: Inconclusive, RequestCount: in.RequestCount,
		Observations: append([]Observation{}, obs...),
		Failures:     append([]Failure{}, in.Failures...),
	}
	var facts Facts
	var unstable []UnstablePair
	if n == len(booleanKinds) {
		var ok bool
		unstable, ok = unstableBooleanPairs(in.UnstablePairs, signatures, indexes)
		if !ok {
			return Result{}, errInvalidEvidence
		}
	} else if len(in.UnstablePairs) != 0 {
		return Result{}, errInvalidEvidence
	}
	switch {
	case in.BudgetUnavailable:
		v.Reason = "budget_unavailable"
		facts.Operational = &OperationalFacts{Stage: "initial", Sequence: 1, Kind: "baseline", Condition: v.Reason}
	case len(v.Failures) != 0:
		f := &v.Failures[0]
		if f.Kind != booleanKinds[n] ||
			!slices.Contains([]string{"timeout", "connection", "response_read", "budget_exceeded", "rate_limit", "cancelled", "unknown"}, f.Reason) ||
			(f.Elapsed != nil && !validElapsed(*f.Elapsed)) {
			return Result{}, errInvalidEvidence
		}
		f.Elapsed = copyPointer(f.Elapsed)
		v.Reason = "probe_failed"
		facts.Operational = &OperationalFacts{Stage: "initial", Sequence: n + 1, Kind: f.Kind, Condition: f.Reason}
	default:
		facts.Operational = initialResponseStop(obs, indexes)
		if n == len(booleanKinds) && (obs[1].Kind == "baseline" ||
			facts.Operational == nil || facts.Operational.Condition != "rate_limited") {
			for i, pos := range [...]int{0, 3, 1, 5, 2, 4} {
				v.Observations[i] = signatures[indexes[pos]]
			}
		}
		switch {
		case facts.Operational != nil:
			v.Reason = responseReason(facts.Operational.Condition)
		case n != len(booleanKinds):
			v.Reason = "insufficient_evidence"
		case len(unstable) != 0:
			v.Reason = "possible_dynamic_response"
			for _, pair := range unstable {
				if pair.Localization == "unlocalized" {
					v.Reason = "unstable_response"
					break
				}
			}
			facts.Response = &ResponseFacts{
				NormalizationApplied: in.NormalizedEchoCount > 0,
				NormalizedEchoCount:  in.NormalizedEchoCount,
				UnstablePairs:        unstable,
			}
		default:
			classifyStableBoolean(v, signatures[indexes[0]], signatures[indexes[1]], signatures[indexes[2]])
		}
	}
	result := Result{Check: Boolean, Verdict: v.Verdict, Reason: v.Reason, RequestCount: v.RequestCount, Verification: v, Facts: facts}
	if !applyRecordedConfirmation(&result, in.Confirmation, in.ConfirmationFacts) {
		return Result{}, errInvalidEvidence
	}
	return result, nil
}

func validCount(n int64) bool { return n >= 0 && n <= maxReportCount }

func validElapsed(s float64) bool { return s >= 0 && !math.IsInf(s, 0) }

func validObservation(o Observation) bool {
	if !validStatus(o.StatusCode) || !validCount(o.BodySize) || !validElapsed(o.Elapsed) || len(o.BodyDigest) != 64 {
		return false
	}
	for i := range o.BodyDigest {
		c := o.BodyDigest[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func sameSignature(a, b Observation) bool {
	return a.StatusCode == b.StatusCode && a.BodySize == b.BodySize && a.BodyDigest == b.BodyDigest
}

func initialResponseStop(obs []Observation, indexes [6]int) *OperationalFacts {
	for _, condition := range []string{"rate_limited", "truncated", "non_success_status"} {
		for i, j := range indexes[:len(obs)] {
			o := obs[j]
			if responseCondition(o.StatusCode, o.Truncated) == condition {
				return &OperationalFacts{Stage: "initial", Sequence: i + 1, Kind: o.Kind,
					Condition: condition, StatusCode: &o.StatusCode}
			}
		}
	}
	return nil
}

func unstableBooleanPairs(saved []UnstablePair, obs []Observation, indexes [6]int) ([]UnstablePair, bool) {
	var unstable []UnstablePair
	for i, j := range [...]int{3, 5, 4} {
		a, b := obs[indexes[i]], obs[indexes[j]]
		if sameSignature(a, b) {
			continue
		}
		pair := UnstablePair{Kind: a.Kind, Localization: "unlocalized"}
		if len(saved) != 0 && saved[0].Kind == a.Kind {
			pair, saved = saved[0], saved[1:]
			p, s, aLen, bLen := pair.PrefixSize, pair.SuffixSize, pair.FirstChangedSize, pair.SecondChangedSize
			switch pair.Localization {
			case "unlocalized":
				if p != nil || s != nil || aLen != nil || bLen != nil {
					return nil, false
				}
			case "localized":
				if a.StatusCode != b.StatusCode || !validRegionSize(a.BodySize, p, s, aLen) ||
					!validRegionSize(b.BodySize, p, s, bLen) || (*aLen == 0 && *bLen == 0) {
					return nil, false
				}
				pair.PrefixSize, pair.SuffixSize = copyPointer(p), copyPointer(s)
				pair.FirstChangedSize, pair.SecondChangedSize = copyPointer(aLen), copyPointer(bLen)
			default:
				return nil, false
			}
		}
		unstable = append(unstable, pair)
	}
	return unstable, len(saved) == 0
}

func validRegionSize(size int64, prefix, suffix, changed *int64) bool {
	return prefix != nil && suffix != nil && changed != nil &&
		validCount(*prefix) && validCount(*suffix) && validCount(*changed) &&
		*prefix+*suffix+*changed == size
}

func classifyStableBoolean(v *Verification, baseline, t, f Observation) {
	e := &Similarity{}
	if sameSignature(baseline, t) {
		e.BaselineTrue = 1
	}
	if sameSignature(baseline, f) {
		e.BaselineFalse = 1
	}
	if sameSignature(t, f) {
		e.TrueFalse = 1
	}
	v.Evidence = e
	switch {
	case e.BaselineTrue == 1 && e.BaselineFalse == 1:
		v.Verdict, v.Reason = NotDetected, "no_boolean_difference"
	case e.BaselineTrue == 1:
		v.Reason = "boolean_candidate"
	case e.TrueFalse == 1:
		v.Verdict, v.Reason = NotDetected, "no_boolean_difference_literal_input"
	default:
		v.Reason = "unexpected_difference"
	}
}

const baselinePreservingControl = "baseline_preserving_control"

// Names and positions are used only to validate recorded confirmation facts.
var confirmationKinds = [...]string{"baseline", "true_1", "false_1", baselinePreservingControl, "true_2", "false_2"}
var confirmationFactIndexes = [...]int{0, 1, 2, 3, 4, 5, 0, 5, 4, 3, 2, 1}

func applyRecordedConfirmation(r *Result, saved *Confirmation, facts Facts) bool {
	if facts.Response != nil || facts.Timing != nil || (facts.Operational != nil && facts.Confirmation != nil) {
		return false
	}
	hasFacts := facts.Operational != nil || facts.Confirmation != nil
	if saved == nil || !saved.Configured {
		return !hasFacts && (saved == nil ||
			(saved.Status == "not_configured" && saved.Reason == nil && saved.RequestCount == 0))
	}
	c := *saved
	if c.Reason == nil || c.RequestCount < 0 || c.RequestCount > 12 {
		return false
	}
	reason := *c.Reason
	if c.Status == "not_eligible" {
		if hasFacts || r.Reason == "boolean_candidate" || c.RequestCount != 0 || reason != "initial_not_eligible" {
			return false
		}
		c.Reason = &reason
		r.Confirmation = &c
		return true
	}
	if r.Reason != "boolean_candidate" {
		return false
	}
	final := reason
	switch c.Status {
	case "matched":
		if hasFacts || reason != "confirmation_pattern_matched" || c.RequestCount != 12 {
			return false
		}
		final = "boolean_candidate"
	case "mismatch":
		if reason != "candidate_confirmation_mismatch" || c.RequestCount != 12 ||
			!applyConfirmationRelations(&r.Facts, reason, facts) {
			return false
		}
	case "operational":
		switch reason {
		case "confirmation_unstable", "confirmation_cross_phase_mismatch":
			if c.RequestCount != 12 || !applyConfirmationRelations(&r.Facts, reason, facts) {
				return false
			}
		default:
			if !applyConfirmationStop(&r.Facts, reason, c.RequestCount, facts) {
				return false
			}
		}
	default:
		return false
	}
	c.Reason = &reason
	r.Verdict, r.Reason, r.Confirmation = Inconclusive, final, &c
	r.RequestCount += c.RequestCount
	return true
}

func applyConfirmationStop(dst *Facts, reason string, count int64, facts Facts) bool {
	if facts.Confirmation != nil {
		return false
	}
	var conditions []string
	sequence := int(count) + 6
	switch reason {
	case "confirmation_budget_unavailable", "confirmation_preflight_failed":
		if count != 0 {
			return false
		}
		sequence++
		if reason == "confirmation_budget_unavailable" {
			conditions = []string{"budget_unavailable"}
		} else {
			conditions = []string{"preflight_failed"}
		}
	case "confirmation_budget_exceeded":
		conditions = []string{"budget_exceeded"}
	case "confirmation_rate_limit_interrupted":
		conditions = []string{"rate_limit_interrupted"}
	case "confirmation_timeout":
		conditions = []string{"timeout"}
	case "confirmation_request_failed":
		conditions = []string{"connection", "response_read", "unknown"}
	case "confirmation_rate_limited":
		conditions = []string{"rate_limited"}
	case "confirmation_truncated":
		conditions = []string{"truncated"}
	case "confirmation_non_success_status":
		conditions = []string{"non_success_status"}
	default:
		return false
	}
	if sequence == 6 && reason != "confirmation_budget_exceeded" {
		return false
	}
	if facts.Operational == nil {
		return true
	}
	f := *facts.Operational
	if f.Stage != "confirmation" || f.Sequence < 7 || f.Sequence > 18 ||
		(f.Sequence != sequence && !(reason == "confirmation_budget_exceeded" && f.Sequence == sequence+1)) ||
		f.Kind != confirmationKinds[confirmationFactIndexes[f.Sequence-7]] ||
		!slices.Contains(conditions, f.Condition) || !validOperationalStatus(f) {
		return false
	}
	f.StatusCode = copyPointer(f.StatusCode)
	dst.Operational = &f
	return true
}

func applyConfirmationRelations(dst *Facts, reason string, facts Facts) bool {
	if facts.Operational != nil {
		return false
	}
	if facts.Confirmation == nil {
		return true
	}
	f := *facts.Confirmation
	if !orderedSubset(f.UnstableRepeatKinds, confirmationKinds[:]) ||
		!orderedSubset(f.UnreproducedPredicatePairs, []string{"true", "false"}) ||
		!orderedSubset(f.MismatchedRelations, []string{"baseline_true", "baseline_control", "baseline_false"}) ||
		!orderedSubset(f.CrossPhaseMismatchedKinds, []string{"baseline", "true", "false"}) ||
		(len(f.UnstableRepeatKinds)+len(f.UnreproducedPredicatePairs) > 0) != (reason == "confirmation_unstable") ||
		(len(f.MismatchedRelations) > 0) != (reason == "candidate_confirmation_mismatch") ||
		(len(f.CrossPhaseMismatchedKinds) > 0) != (reason == "confirmation_cross_phase_mismatch") {
		return false
	}
	dst.Confirmation = &ConfirmationFacts{
		UnstableRepeatKinds:        append([]string{}, f.UnstableRepeatKinds...),
		UnreproducedPredicatePairs: append([]string{}, f.UnreproducedPredicatePairs...),
		MismatchedRelations:        append([]string{}, f.MismatchedRelations...),
		CrossPhaseMismatchedKinds:  append([]string{}, f.CrossPhaseMismatchedKinds...),
	}
	return true
}

func orderedSubset(values, order []string) bool {
	for _, value := range order {
		if len(values) != 0 && values[0] == value {
			values = values[1:]
		}
	}
	return len(values) == 0
}
