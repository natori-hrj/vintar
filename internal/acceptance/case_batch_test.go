//go:build linux || darwin || windows

package acceptance

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/natori-hrj/vintar/internal/casefile"
	"github.com/natori-hrj/vintar/internal/decision"
	"github.com/natori-hrj/vintar/internal/report"
)

func TestOfflineCaseBatchWithSavedObservations(t *testing.T) {
	root := repoRoot(t)
	cases, err := casefile.LoadBatch(filepath.Join(root, "tests/golden/cases"), 19)
	if err != nil || len(cases) != 3 {
		t.Fatalf("load case batch: got %d cases; %v", len(cases), err)
	}
	var observations []decision.Observation
	for _, kind := range []string{"baseline", "true", "false"} {
		sample := decision.Observation{
			Kind: kind, StatusCode: 200, BodySize: 1, BodyDigest: strings.Repeat("a", 64),
		}
		observations = append(observations, sample, sample)
	}
	boolean, err := decision.EvaluateBoolean(decision.BooleanInput{Observations: observations, RequestCount: 6})
	if err != nil {
		t.Fatal(err)
	}
	errorCheck, err := decision.EvaluateError(decision.ErrorInput{Observations: []decision.ErrorObservation{
		{Kind: "baseline", StatusCode: 200}, {Kind: "probe", StatusCode: 200},
		{Kind: "baseline", StatusCode: 200}, {Kind: "probe", StatusCode: 200},
	}})
	if err != nil {
		t.Fatal(err)
	}
	timing, err := decision.EvaluateTime(decision.TimeInput{
		RequestCount: 9, Predicates: &decision.TimingPredicates{NoDelayConditionMet: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	results := map[string]decision.Result{
		"post-json-boolean": boolean, "post-json-error": errorCheck, "post-json-time": timing,
	}
	var planned []string
	var records []report.Record
	for _, c := range cases {
		r, found := results[c.ID]
		if !found || r.Check != decision.Check(c.Check) || r.RequestCount != c.Limits.MaxRequests {
			t.Fatalf("saved fixture does not match case %q", c.ID)
		}
		planned = append(planned, c.ID)
		records = append(records, report.Record{CaseID: c.ID, Expected: decision.Verdict(c.ExpectedVerdict), Decision: r})
	}
	data, exit, err := report.MarshalBatch(planned, records, false)
	if err != nil || exit != 0 {
		t.Fatalf("saved observation report: exit=%d, err=%v", exit, err)
	}
	if err := publishedSchemas(t, root)[batchSchema].Validate(decodeSchemaJSON(t, "case batch", data)); err != nil {
		t.Fatal(err)
	}
	again, repeatExit, err := report.MarshalBatch(planned, records, false)
	if err != nil || repeatExit != exit || !bytes.Equal(data, again) {
		t.Fatal("saved observation report is not deterministic")
	}
	records[2].Decision.RequestCount--
	data, exit, err = report.MarshalBatch(planned, records, false)
	if err == nil || exit != 2 || len(data) != 0 {
		t.Fatalf("invalid observation count: wrote %d bytes, exit=%d, err=%v", len(data), exit, err)
	}
}
