package decision

import "reflect"

// ValidateResult checks a mutable, saved decision summary before another
// package consumes it. All stage, count, reason and observation consistency
// rules belong here or in the shared assessment constructors. This does
// not establish the authenticity of observations absent from a summary.
func ValidateResult(r Result) error {
	if !validCount(r.RequestCount) {
		return errInvalidEvidence
	}
	var valid bool
	switch r.Check {
	case Boolean:
		valid = r.Timing == nil && r.Error == nil && validBooleanResult(r)
	case Time:
		if r.Verification == nil && r.Confirmation == nil && r.Error == nil &&
			r.Facts.Response == nil && r.Facts.Confirmation == nil {
			derived, err := timeResult(r.RequestCount, r.Reason, r.Facts)
			valid = err == nil && r.Verdict == derived.Verdict && r.Timing != nil && *r.Timing == *derived.Timing
		}
	case Error:
		if r.Verification == nil && r.Confirmation == nil && r.Timing == nil && r.Error != nil &&
			r.Facts.Response == nil && r.Facts.Confirmation == nil && r.Facts.Timing == nil {
			derived, err := errorResult(r.RequestCount, r.Reason,
				Signature{DBMS: r.Error.DBMS, ID: r.Error.SignatureID}, r.Facts.Operational)
			valid = err == nil && r.Verdict == derived.Verdict && *r.Error == *derived.Error
		}
	}
	if !valid {
		return errInvalidEvidence
	}
	return nil
}

func validBooleanResult(r Result) bool {
	v := r.Verification
	if v == nil || r.Facts.Timing != nil {
		return false
	}
	switch v.Reason {
	case "boolean_differential", "connection_error":
		return validArchivedBoolean(r)
	}
	input := BooleanInput{
		Observations: v.Observations, Failures: v.Failures,
		RequestCount: v.RequestCount, BudgetUnavailable: v.Reason == "budget_unavailable",
		Confirmation: r.Confirmation,
	}
	if c := r.Confirmation; c != nil && c.Configured && c.Status != "not_eligible" {
		input.ConfirmationFacts = r.Facts
	}
	if f := r.Facts.Response; f != nil {
		input.UnstablePairs = f.UnstablePairs
		if f.NormalizationApplied {
			// The released verification summary stores the normalized projection.
			input.Normalized, input.NormalizedEchoCount = v.Observations, f.NormalizedEchoCount
		}
	}
	replayed, err := EvaluateBoolean(input)
	return err == nil && replayed.Verdict == r.Verdict && replayed.Reason == r.Reason &&
		replayed.RequestCount == r.RequestCount &&
		replayed.Verification.Verdict == v.Verdict && replayed.Verification.Reason == v.Reason &&
		reflect.DeepEqual(replayed.Verification.Evidence, v.Evidence) &&
		reflect.DeepEqual(replayed.Facts.Operational, r.Facts.Operational) &&
		reflect.DeepEqual(replayed.Facts.Response, r.Facts.Response) &&
		// When present, the confirmation facts were replayed from these same
		// values; their allocated empty slices need not match nil slices.
		(replayed.Facts.Confirmation != nil) == (r.Facts.Confirmation != nil)
}

// Older Boolean summaries have no corresponding current classifier output.
// Preserve their bounded structural rules and their non-PASS verdicts.
func validArchivedBoolean(r Result) bool {
	v := r.Verification
	if v.Reason != r.Reason || v.Verdict != r.Verdict || v.RequestCount != r.RequestCount ||
		r.Facts != (Facts{}) || v.RequestCount != int64(len(v.Observations))+int64(len(v.Failures)) {
		return false
	}
	if v.Reason == "boolean_differential" {
		if v.Verdict != Vulnerable || len(v.Failures) != 0 || v.Evidence == nil {
			return false
		}
	} else if v.Verdict != Inconclusive {
		return false
	}
	kinds := make(map[string]bool, 3)
	for _, o := range v.Observations {
		if !booleanKind(o.Kind) || !validObservation(o) ||
			(v.Verdict == Vulnerable && (o.Truncated || !successStatus(o.StatusCode))) {
			return false
		}
		kinds[o.Kind] = true
	}
	for _, f := range v.Failures {
		if !booleanKind(f.Kind) || !validBooleanFailure(f) {
			return false
		}
	}
	if e := v.Evidence; e != nil {
		if len(kinds) != 3 || !unitInterval(e.BaselineFalse) || !unitInterval(e.BaselineTrue) || !unitInterval(e.TrueFalse) {
			return false
		}
	}
	c := r.Confirmation
	switch {
	case c == nil:
		return true
	case c.Status == "not_configured":
		return !c.Configured && c.Reason == nil && c.RequestCount == 0
	case c.Status == "not_eligible":
		return c.Configured && c.Reason != nil && *c.Reason == "initial_not_eligible" && c.RequestCount == 0
	}
	return false
}

func booleanKind(kind string) bool { return kind == "baseline" || kind == "true" || kind == "false" }
func unitInterval(n float64) bool  { return n >= 0 && n <= 1 }
