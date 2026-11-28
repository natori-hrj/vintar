// Package report describes Vintar's versioned public batch report.
package report

import (
	"encoding/json"
	"errors"
	"regexp"
	"slices"
)

const (
	BatchVersion = 1
	BatchType    = "regression_batch"
	maxCaseCount = 128
	maxJSONCount = 1<<53 - 1
)

// Status is the CI result, distinct from a check's verdict.
type Status string

const (
	Pass         Status = "pass"
	Fail         Status = "fail"
	Inconclusive Status = "inconclusive"
)

type Counts struct {
	Pass         int `json:"pass"`
	Fail         int `json:"fail"`
	Inconclusive int `json:"inconclusive"`
	NotRun       int `json:"not_run"`
}

// Outcome retains check-specific sections as JSON. Callers validating untrusted
// reports must check those sections against the published schema.
type Outcome struct {
	CaseID           string          `json:"case_id"`
	ExpectedVerdict  string          `json:"expected_verdict"`
	ActualVerdict    string          `json:"actual_verdict"`
	ExpectationMatch bool            `json:"expectation_match"`
	Status           Status          `json:"status"`
	CheckType        string          `json:"check_type,omitempty"`
	ActualReasonCode string          `json:"actual_reason_code,omitempty"`
	RequestCount     *int64          `json:"request_count,omitempty"`
	Verification     json.RawMessage `json:"verification,omitempty"`
	Confirmation     json.RawMessage `json:"confirmation,omitempty"`
	Timing           json.RawMessage `json:"timing,omitempty"`
	Error            json.RawMessage `json:"error,omitempty"`
	DecisionFacts    json.RawMessage `json:"decision_facts,omitempty"`
}

type Batch struct {
	SchemaVersion int       `json:"schema_version"`
	ReportType    string    `json:"report_type"`
	Status        Status    `json:"status"`
	Complete      bool      `json:"complete"`
	ExitCode      int       `json:"exit_code"`
	PlannedIDs    []string  `json:"planned_case_ids"`
	ExecutedIDs   []string  `json:"executed_case_ids"`
	NotRunIDs     []string  `json:"not_run_case_ids"`
	PlannedCount  int       `json:"planned_count"`
	ExecutedCount int       `json:"executed_count"`
	RequestsUsed  int64     `json:"requests_used"`
	Counts        Counts    `json:"counts"`
	Outcomes      []Outcome `json:"outcomes"`
}

// ValidateSummary checks cross-field accounting after structural schema
// validation. It does not validate the check-specific recorded evidence.
func (b Batch) ValidateSummary(processExit int) error {
	if b.SchemaVersion != BatchVersion || b.ReportType != BatchType {
		return errors.New("unsupported batch report")
	}
	if !b.validCaseOrder() {
		return errors.New("inconsistent batch case ordering")
	}
	if b.PlannedCount != len(b.PlannedIDs) || b.ExecutedCount != len(b.ExecutedIDs) ||
		b.Complete != (len(b.NotRunIDs) == 0) {
		return errors.New("inconsistent batch completion")
	}

	counts := Counts{NotRun: len(b.NotRunIDs)}
	var used int64
	for i, outcome := range b.Outcomes {
		if outcome.CaseID != b.ExecutedIDs[i] {
			return errors.New("inconsistent batch outcome ordering")
		}
		if outcome.ExpectationMatch != (outcome.ExpectedVerdict == outcome.ActualVerdict) {
			return errors.New("inconsistent expectation match")
		}
		status := outcome.statusFromVerdict()
		if status != outcome.Status {
			return errors.New("inconsistent batch outcome status")
		}
		switch status {
		case Pass:
			counts.Pass++
		case Fail:
			counts.Fail++
		case Inconclusive:
			counts.Inconclusive++
		default:
			return errors.New("invalid batch outcome status")
		}
		requests, err := outcome.requests()
		if err != nil || requests < 0 || requests > maxJSONCount-used {
			return errors.New("invalid batch outcome request count")
		}
		used += requests
	}

	if b.Counts != counts || b.RequestsUsed != used {
		return errors.New("inconsistent batch accounting")
	}
	status, exit := counts.result()
	if b.Status != status || b.ExitCode != exit || processExit != exit {
		return errors.New("inconsistent batch status or exit code")
	}
	return nil
}

// Check the public mapping without re-evaluating any check-specific evidence.
func (o Outcome) statusFromVerdict() Status {
	switch o.ActualVerdict {
	case "inconclusive":
		return Inconclusive
	case "vulnerable":
		return Fail
	case "not_detected":
		if o.ExpectationMatch {
			return Pass
		}
		return Fail
	default:
		return ""
	}
}

var caseID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func (b Batch) validCaseOrder() bool {
	if len(b.ExecutedIDs) == 0 || len(b.PlannedIDs) > maxCaseCount ||
		len(b.PlannedIDs) != len(b.ExecutedIDs)+len(b.NotRunIDs) ||
		len(b.Outcomes) != len(b.ExecutedIDs) {
		return false
	}
	if !slices.Equal(b.PlannedIDs[:len(b.ExecutedIDs)], b.ExecutedIDs) ||
		!slices.Equal(b.PlannedIDs[len(b.ExecutedIDs):], b.NotRunIDs) {
		return false
	}
	seen := make(map[string]bool, len(b.PlannedIDs))
	for _, id := range b.PlannedIDs {
		if seen[id] || !caseID.MatchString(id) {
			return false
		}
		seen[id] = true
	}
	return true
}

func (o Outcome) requests() (int64, error) {
	if o.RequestCount != nil {
		return *o.RequestCount, nil
	}
	// The original v1 envelope stored this only in verification.
	var legacy struct {
		RequestCount int64 `json:"request_count"`
	}
	if len(o.Verification) != 0 {
		if err := json.Unmarshal(o.Verification, &legacy); err != nil {
			return 0, err
		}
	}
	return legacy.RequestCount, nil
}

func (c Counts) result() (Status, int) {
	if c.Fail != 0 {
		return Fail, 1
	}
	if c.Inconclusive != 0 || c.NotRun != 0 {
		return Inconclusive, 3
	}
	return Pass, 0
}
