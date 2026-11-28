package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReleasedBatchSummaries(t *testing.T) {
	for _, name := range []string{
		"pass", "fail", "partial-inconclusive", "mixed-boolean-time-error",
	} {
		t.Run(name, func(t *testing.T) {
			data := readFixture(t, "golden", "cli", "verify", name+".json")
			var golden struct {
				Exit  int   `json:"exit_code"`
				Batch Batch `json:"stdout_json"`
			}
			if err := json.Unmarshal(data, &golden); err != nil {
				t.Fatal(err)
			}
			if err := golden.Batch.ValidateSummary(golden.Exit); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLegacyBatchSummaryRejectsContradictions(t *testing.T) {
	data := readFixture(t, "fixtures", "regression-batch-report-v1-legacy.json")
	for _, tc := range []struct {
		name   string
		exit   int
		change func(*Batch)
	}{
		{name: "legacy", exit: 3},
		{name: "wrong exit", exit: 0},
		{name: "wrong request total", exit: 3, change: func(b *Batch) { b.RequestsUsed++ }},
		{name: "wrong case order", exit: 3, change: func(b *Batch) {
			b.PlannedIDs[0], b.PlannedIDs[1] = b.PlannedIDs[1], b.PlannedIDs[0]
		}},
		{name: "incomplete success", exit: 3, change: func(b *Batch) { b.Status = Pass }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var batch Batch
			if err := json.Unmarshal(data, &batch); err != nil {
				t.Fatal(err)
			}
			if tc.change != nil {
				tc.change(&batch)
			}
			err := batch.ValidateSummary(tc.exit)
			wantErr := tc.name != "legacy"
			if (err != nil) != wantErr {
				t.Fatalf("ValidateSummary error = %v, want error: %v", err, wantErr)
			}
		})
	}
}

func TestBatchStatusPrecedence(t *testing.T) {
	for _, tc := range []struct {
		counts Counts
		status Status
		exit   int
	}{
		{Counts{Pass: 1}, Pass, 0},
		{Counts{Pass: 1, NotRun: 1}, Inconclusive, 3},
		{Counts{Inconclusive: 1}, Inconclusive, 3},
		{Counts{Fail: 1, Inconclusive: 1, NotRun: 1}, Fail, 1},
	} {
		status, exit := tc.counts.result()
		if status != tc.status || exit != tc.exit {
			t.Errorf("%+v: got (%s, %d), want (%s, %d)", tc.counts, status, exit, tc.status, tc.exit)
		}
	}
}

func readFixture(t *testing.T, parts ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "tests"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
