package report

import (
	"math"
	"regexp"
	"slices"

	"github.com/natori-hrj/vintar/internal/decision"
)

func oneOf(value string, allowed ...string) bool {
	return slices.Contains(allowed, value)
}

func validVerdict(v decision.Verdict) bool {
	return v == decision.Vulnerable || v == decision.NotDetected || v == decision.Inconclusive
}

func validCount(n int64) bool     { return n >= 0 && n <= maxJSONCount }
func validHTTP(n int) bool        { return n >= 100 && n <= 599 }
func unitInterval(n float64) bool { return n >= 0 && n <= 1 }
func validElapsed(n float64) bool { return n >= 0 && n <= math.MaxFloat64 }

var bodyDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validDecision(r decision.Result) bool {
	if !validVerdict(r.Verdict) || !validCount(r.RequestCount) {
		return false
	}
	var valid bool
	switch r.Check {
	case decision.Boolean:
		valid = r.Timing == nil && r.Error == nil && validBoolean(r)
	case decision.Time:
		valid = r.Verification == nil && r.Confirmation == nil && r.Error == nil && validTiming(r)
	case decision.Error:
		valid = r.Verification == nil && r.Confirmation == nil && r.Timing == nil && validError(r)
	}
	return valid && validFacts(r)
}

func validTiming(r decision.Result) bool {
	t := r.Timing
	if t == nil || t.Reason != r.Reason || t.RequestCount != r.RequestCount {
		return false
	}
	switch r.Reason {
	case "timing_pattern_matched":
		return t.Status == "candidate" && r.Verdict == decision.Inconclusive && r.RequestCount == 9
	case "timing_pattern_not_matched":
		return t.Status == "not_confirmed" && r.Verdict == decision.NotDetected && r.RequestCount == 9
	default:
		if t.Status != "inconclusive" || r.Verdict != decision.Inconclusive {
			return false
		}
		switch r.Reason {
		case "incomplete_probes":
			return r.RequestCount <= 8
		case "unstable_timing", "ambiguous_timing":
			return r.RequestCount == 9
		case "probe_timeout", "probe_failed", "probe_interrupted", "rate_limited", "non_success_status", "truncated_response":
			return r.RequestCount >= 1 && r.RequestCount <= 9
		}
	}
	return false
}

func validError(r decision.Result) bool {
	e := r.Error
	if e == nil || e.Reason != r.Reason || e.RequestCount != r.RequestCount ||
		r.RequestCount < 1 || r.RequestCount > 4 {
		return false
	}
	if r.Reason == "dbms_error_disclosed" {
		return e.Status == "matched" && r.Verdict == decision.Inconclusive && r.RequestCount == 4 &&
			decision.KnownSignature(decision.Signature{DBMS: e.DBMS, ID: e.SignatureID})
	}
	if e.DBMS != "" || e.SignatureID != "" {
		return false
	}
	if r.Reason == "dbms_error_not_observed" {
		return e.Status == "not_matched" && r.Verdict == decision.NotDetected && r.RequestCount == 4
	}
	if e.Status != "inconclusive" || r.Verdict != decision.Inconclusive {
		return false
	}
	switch r.Reason {
	case "baseline_dbms_error", "unstable_response", "unstable_error_signal", "ambiguous_dbms_error", "non_success_status":
		return r.RequestCount == 4
	case "truncated_response", "probe_timeout", "probe_failed", "probe_interrupted", "rate_limited":
		return true
	}
	return false
}

func validBoolean(r decision.Result) bool {
	v := r.Verification
	if v == nil || !validVerification(v) {
		return false
	}
	initialUnchanged := r.Reason == v.Reason && r.Verdict == v.Verdict && r.RequestCount == v.RequestCount
	c := r.Confirmation
	if c == nil {
		return initialUnchanged
	}
	if c.Status == "not_configured" {
		return initialUnchanged && !c.Configured && c.Reason == nil && c.RequestCount == 0
	}
	if !c.Configured || c.Reason == nil || c.RequestCount < 0 || c.RequestCount > 12 ||
		r.RequestCount != v.RequestCount+c.RequestCount {
		return false
	}
	eligible := eligibleInitial(v)
	if c.Status == "not_eligible" {
		return !eligible && initialUnchanged && c.RequestCount == 0 && *c.Reason == "initial_not_eligible"
	}
	if !eligible || r.Verdict != decision.Inconclusive {
		return false
	}
	switch c.Status {
	case "matched":
		return *c.Reason == "confirmation_pattern_matched" && c.RequestCount == 12 && r.Reason == "boolean_candidate"
	case "mismatch":
		return *c.Reason == "candidate_confirmation_mismatch" && c.RequestCount == 12 && r.Reason == *c.Reason
	case "operational":
		if r.Reason != *c.Reason {
			return false
		}
		switch r.Reason {
		case "confirmation_budget_unavailable", "confirmation_preflight_failed":
			return c.RequestCount == 0
		case "confirmation_budget_exceeded":
			return true
		case "confirmation_unstable", "confirmation_cross_phase_mismatch":
			return c.RequestCount == 12
		case "confirmation_rate_limit_interrupted", "confirmation_timeout", "confirmation_request_failed",
			"confirmation_rate_limited", "confirmation_truncated", "confirmation_non_success_status":
			return c.RequestCount >= 1
		}
	}
	return false
}

func validVerification(v *decision.Verification) bool {
	if !validCount(v.RequestCount) || int64(len(v.Observations)) > v.RequestCount ||
		v.RequestCount-int64(len(v.Observations)) != int64(len(v.Failures)) {
		return false
	}
	switch v.Reason {
	case "boolean_differential":
		if v.Verdict != decision.Vulnerable {
			return false
		}
	case "no_boolean_difference", "no_boolean_difference_literal_input":
		if v.Verdict != decision.NotDetected {
			return false
		}
	case "budget_unavailable":
		if v.Verdict != decision.Inconclusive || v.RequestCount != 0 {
			return false
		}
	case "boolean_candidate", "connection_error", "insufficient_evidence", "non_success_status",
		"possible_dynamic_response", "probe_failed", "rate_limited", "truncated_response", "unexpected_difference", "unstable_response":
		if v.Verdict != decision.Inconclusive {
			return false
		}
	default:
		return false
	}
	if v.Confidence != nil && !unitInterval(*v.Confidence) {
		return false
	}
	var baseline, trueProbe, falseProbe int
	for _, o := range v.Observations {
		switch o.Kind {
		case "baseline":
			baseline++
		case "true":
			trueProbe++
		case "false":
			falseProbe++
		default:
			return false
		}
		if !validHTTP(o.StatusCode) || !validCount(o.BodySize) || !validElapsed(o.Elapsed) ||
			!bodyDigest.MatchString(o.BodyDigest) ||
			(v.Verdict != decision.Inconclusive && (o.Truncated || o.StatusCode < 200 || o.StatusCode > 299)) {
			return false
		}
	}
	for _, f := range v.Failures {
		if !booleanKind(f.Kind) || !failureReason(f.Reason) ||
			(f.Elapsed != nil && !validElapsed(*f.Elapsed)) {
			return false
		}
	}
	if e := v.Evidence; e != nil {
		if baseline == 0 || trueProbe == 0 || falseProbe == 0 ||
			!unitInterval(e.BaselineFalse) || !unitInterval(e.BaselineTrue) || !unitInterval(e.TrueFalse) {
			return false
		}
	}
	switch v.Reason {
	case "boolean_candidate", "no_boolean_difference", "no_boolean_difference_literal_input", "unexpected_difference":
		if baseline != 2 || trueProbe != 2 || falseProbe != 2 || len(v.Failures) != 0 || v.Evidence == nil {
			return false
		}
	case "possible_dynamic_response", "unstable_response":
		if baseline != 2 || trueProbe != 2 || falseProbe != 2 || len(v.Failures) != 0 || v.Evidence != nil {
			return false
		}
	}
	return v.Verdict == decision.Inconclusive || (len(v.Failures) == 0 && v.Evidence != nil)
}

func eligibleInitial(v *decision.Verification) bool {
	if v.Verdict != decision.Inconclusive || v.Reason != "boolean_candidate" || v.RequestCount != 6 ||
		len(v.Observations) != 6 || len(v.Failures) != 0 || v.Evidence == nil {
		return false
	}
	kinds := make(map[string]int, 3)
	for _, o := range v.Observations {
		if o.Truncated || o.StatusCode < 200 || o.StatusCode > 299 {
			return false
		}
		kinds[o.Kind]++
	}
	return kinds["baseline"] == 2 && kinds["true"] == 2 && kinds["false"] == 2
}

func booleanKind(kind string) bool { return oneOf(kind, "baseline", "true", "false") }

func failureReason(reason string) bool {
	return oneOf(reason, "timeout", "connection", "response_read", "budget_exceeded", "rate_limit", "cancelled", "unknown")
}
