package report

import "github.com/natori-hrj/vintar/internal/decision"

func validVerdict(v decision.Verdict) bool {
	return v == decision.Vulnerable || v == decision.NotDetected || v == decision.Inconclusive
}

// validPublicProjection checks public report requirements not needed to
// classify observations. Decision owns semantic consistency.
func validPublicProjection(r decision.Result) bool {
	if v := r.Verification; v != nil && v.Confidence != nil {
		if n := *v.Confidence; !(n >= 0 && n <= 1) {
			return false
		}
	}
	if c := r.Confirmation; c != nil && (c.Status == "operational" || c.Status == "mismatch") {
		// The released writer requires facts even when an abstract saved
		// confirmation can be classified without them.
		return r.Facts.Operational != nil || r.Facts.Confirmation != nil
	}
	return true
}
