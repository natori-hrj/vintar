package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/natori-hrj/vintar/internal/casefile"
	"github.com/natori-hrj/vintar/internal/decision"
	"github.com/natori-hrj/vintar/internal/execution/internal/httpio"
	"github.com/natori-hrj/vintar/internal/report"
)

const (
	fixedPipelineSecret = "fixture-private-pipeline"
	fixedResponseMarker = "rawmark" // Shorter than the response cap.
)

// This composition belongs to the tests: the only possible wire request is
// the fixed baseline POST below, to a supplied IPv4 loopback listener. Cases
// supply approval metadata and limits, never request variants or predicates.
type fixedPipeline struct {
	source       string
	target       Origin
	trusted      Origin
	policy       string
	budget       int
	timeDeadline time.Duration
	lookups      []string
}

func newFixedPipeline(t *testing.T, endpoint string, mismatch bool) *fixedPipeline {
	t.Helper()
	target := fixturePolicyOrigin(t, endpoint)
	if target.scheme != "http" || target.host != "127.0.0.1" {
		t.Fatal("fixed pipeline requires IPv4 loopback")
	}
	dir := t.TempDir()
	for _, name := range []string{"post-json-error-v2.toml", "post-json-time-v2.toml"} {
		b, err := os.ReadFile(filepath.Join("../../tests/golden/cases", name))
		if err != nil {
			t.Fatal(err)
		}
		if mismatch {
			b = bytes.Replace(b, []byte(`expected_verdict = "not_detected"`), []byte(`expected_verdict = "vulnerable"`), 1)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Operator-supplied values are independent of the loaded case files.
	const approval = `{
		"case_id":%q,"identity_id":"reviewed-user","credential_kind":"api_key_header",
		"credential_env_var":"PIPELINE_FIXTURE_KEY","method":"POST","path":"/items",
		"origin":%q,"allowed_environment_classes":["isolated_test"],"allowed_side_effect":"no_side_effect",
		"operation_definition_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
		"baseline_body_sha256":"5e5c0546e15bd689be19e8e151d0517b1ae9f6c96edfda7fbf930a72ae99056d"
	}`
	policy := fmt.Sprintf(`{
		"schema_version":1,"policy_type":"post_json_execution",
		"identities":[{"identity_id":"reviewed-user","credential_kind":"api_key_header","env_var":"PIPELINE_FIXTURE_KEY","header_name":"X-Fixture-Key"}],
		"approvals":[%s,%s],
		"limits":{"max_requests":13,"max_requests_per_second":5,"max_timeout_seconds":2,"max_response_size":8,"max_time_execution_seconds":15}
	}`, fmt.Sprintf(approval, "post-json-error", endpoint), fmt.Sprintf(approval, "post-json-time", endpoint))
	return &fixedPipeline{source: dir, target: target, trusted: target, policy: policy, budget: 13, timeDeadline: 5 * time.Second}
}

func (f *fixedPipeline) run(ctx context.Context,
	send func(context.Context, httpio.Request, time.Duration, int64) (httpio.Response, error),
) ([]byte, int, error) {
	if f.target.scheme != "http" || f.target.host != "127.0.0.1" {
		return nil, 2, errors.New("fixed pipeline requires IPv4 loopback")
	}
	policy, err := LoadRuntimePolicy(func(name string) (string, bool) {
		return f.policy, name == "VINTAR_RUNTIME_POLICY_JSON"
	})
	if err != nil {
		return nil, 2, err
	}
	limits := policy.Limits()
	limits.MaxRequests = min(limits.MaxRequests, f.budget)
	cases, err := casefile.LoadBatch(f.source, int64(limits.MaxRequests))
	if err != nil {
		return nil, 2, err
	}
	if len(cases) != 2 || cases[0].ID != "post-json-error" || cases[0].Check != casefile.CheckError ||
		cases[1].ID != "post-json-time" || cases[1].Check != casefile.CheckTime ||
		f.timeDeadline <= 0 || f.timeDeadline > limits.Deadline {
		return nil, 2, errors.New("invalid fixed pipeline plan")
	}
	var planned []string
	var approvals []ApprovalRequest
	for _, c := range cases {
		a := c.Approval
		if c.Version != casefile.Version2 || a.Method != casefile.POST || a.Path != "/items" ||
			string(c.Request.JSONBody) != boundaryBody {
			return nil, 2, errors.New("fixed pipeline baseline mismatch")
		}
		planned = append(planned, c.ID)
		approvals = append(approvals, ApprovalRequest{
			CaseID: c.ID, IdentityID: *c.IdentityID, Origin: f.target, Method: string(a.Method),
			Path: a.Path, Environment: a.EnvironmentClass, OperationDigest: a.PostJSON.OperationDefinitionSHA256,
			BaselineDigest: a.PostJSON.BaselineBodySHA256, SideEffect: a.PostJSON.SideEffect,
		})
		limits.Rate = min(limits.Rate, c.Limits.RequestsPerSecond)
	}
	governor, err := policy.Governor(limits)
	if err != nil {
		return nil, 2, err
	}
	prepared, err := policy.PrepareAll(ctx, approvals, []Origin{f.trusted}, time.Now(), func(name string) (string, bool) {
		f.lookups = append(f.lookups, name)
		return fixedPipelineSecret, name == "PIPELINE_FIXTURE_KEY"
	})
	if err != nil {
		return fixedPipelineFailure(ctx, err)
	}

	endpoint := fmt.Sprintf("http://127.0.0.1:%d/items", f.target.port)
	var records []report.Record
	for i, c := range cases {
		op := prepared[i]
		if op.URL != endpoint || op.Method != http.MethodPost {
			return nil, 2, errors.New("unexpected fixed wire request")
		}
		caseDeadline := limits.Deadline
		if c.Check == casefile.CheckTime {
			caseDeadline = f.timeDeadline
		}
		caseCtx, cancel := context.WithTimeout(ctx, caseDeadline)
		result, err := runFixedCase(caseCtx, c, op, governor, send)
		cancel()
		if err != nil || ctx.Err() != nil {
			return fixedPipelineFailure(ctx, err)
		}
		records = append(records, report.Record{CaseID: c.ID, Expected: decision.Verdict(c.ExpectedVerdict), Decision: result})
		if result.Facts.Operational != nil {
			break
		}
	}
	return report.MarshalBatch(planned, records, false)
}

func fixedPipelineFailure(ctx context.Context, err error) ([]byte, int, error) {
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil, 130, context.Canceled
	}
	if ctx.Err() != nil {
		return nil, 2, ctx.Err()
	}
	return nil, 2, err
}

func runFixedCase(ctx context.Context, c casefile.Case, op PreparedOperation, governor *Governor,
	send func(context.Context, httpio.Request, time.Duration, int64) (httpio.Response, error),
) (decision.Result, error) {
	timeout := min(governor.limits.Timeout, time.Duration(c.Limits.TimeoutSeconds*float64(time.Second)))
	var observations []decision.ErrorObservation
	var started int64
	for started < c.Limits.MaxRequests {
		before := started
		var res httpio.Response
		err := governor.Run(ctx, func(requestCtx context.Context, cap int64) (bool, error) {
			requestCtx, cancel := context.WithTimeout(requestCtx, timeout)
			defer cancel()
			req := httpio.Request{Method: op.Method, URL: op.URL, Body: []byte(boundaryBody), Headers: map[string]string{}}
			if err := op.ApplyCredential(req.Headers); err != nil {
				return false, err
			}
			started++
			var err error
			res, err = send(requestCtx, req, timeout, cap)
			if requestCtx.Err() != nil {
				return true, requestCtx.Err()
			}
			return res.Status == http.StatusTooManyRequests || res.Truncated, err
		})
		if err != nil {
			if c.Check == casefile.CheckTime && started == before && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return decision.EvaluateTime(decision.TimeInput{RequestCount: started})
			}
			return decision.Result{}, err
		}
		if c.Check == casefile.CheckError {
			kind := "baseline"
			if started%2 == 0 {
				kind = "probe"
			}
			observations = append(observations, decision.ErrorObservation{Kind: kind, StatusCode: res.Status, Truncated: res.Truncated})
			if res.Status == http.StatusTooManyRequests || res.Truncated {
				break
			}
		} else if res.Status != http.StatusNoContent || res.Truncated {
			// Saved timing predicates belong only to this complete fixture.
			return decision.Result{}, errors.New("unexpected fixed timing response")
		}
	}
	if c.Check == casefile.CheckError {
		return decision.EvaluateError(decision.ErrorInput{Observations: observations})
	}
	return decision.EvaluateTime(decision.TimeInput{
		RequestCount: started, Predicates: &decision.TimingPredicates{NoDelayConditionMet: true},
	})
}

func TestFixedPipelineMock(t *testing.T) {
	for _, tc := range []struct {
		name       string
		exit, sent int
		lookup     bool
	}{
		{"complete", 0, 13, true},
		{"expectation mismatch", 1, 13, true},
		{"case deadline before next attempt", 3, 5, true},
		{"case request timeout", 2, 5, true},
		{"cancellation between attempts", 130, 5, true},
		{"already canceled", 130, 0, false},
		{"insufficient aggregate ceiling", 2, 0, false},
		{"invalid case deadline", 2, 0, false},
		{"independent origin mismatch", 2, 0, false},
		{"second approval mismatch", 2, 0, false},
		{"invalid observation", 2, 4, true},
		{"unexpected second case response", 2, 5, true},
		{"transport error with secret", 2, 5, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFixedPipeline(t, "http://127.0.0.1:18760", tc.name == "expectation mismatch")
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				switch tc.name {
				case "case deadline before next attempt":
					f.timeDeadline = 700 * time.Millisecond
				case "already canceled":
					cancel()
				case "insufficient aggregate ceiling":
					f.budget--
				case "invalid case deadline":
					f.timeDeadline = 0
				case "independent origin mismatch":
					f.trusted.port++
				case "second approval mismatch":
					i := strings.LastIndex(f.policy, "5e5c0546")
					f.policy = f.policy[:i] + strings.Replace(f.policy[i:], "5e5c0546", "00000000", 1)
				}
				var calls int
				var starts []time.Duration
				start := time.Now()
				send := func(ctx context.Context, req httpio.Request, timeout time.Duration, cap int64) (httpio.Response, error) {
					if !slices.Equal(f.lookups, []string{"PIPELINE_FIXTURE_KEY"}) || cap != 8 ||
						req.URL != "http://127.0.0.1:18760/items" || string(req.Body) != boundaryBody ||
						len(req.Headers) != 1 || req.Headers["X-Fixture-Key"] != fixedPipelineSecret {
						t.Fatal("request escaped the fixture approval, credential, or response limits")
					}
					// Distinct maps prevent headers added during a send from
					// contaminating any later request.
					req.Headers["Unrelated"] = "must not carry over"
					calls++
					starts = append(starts, time.Since(start))
					wantTimeout := 2 * time.Second
					if calls > 4 {
						wantTimeout = time.Second
					}
					if timeout != wantTimeout {
						t.Fatalf("request %d timeout: %v, want %v", calls, timeout, wantTimeout)
					}
					if calls == 4 && tc.name == "invalid observation" {
						return httpio.Response{Status: 99}, nil
					}
					if calls == 5 {
						switch tc.name {
						case "cancellation between attempts":
							time.AfterFunc(50*time.Millisecond, cancel)
						case "case request timeout":
							<-ctx.Done()
							if time.Since(start) != 3*time.Second {
								t.Fatal("case request did not observe its own timeout")
							}
							return httpio.Response{}, ctx.Err()
						case "unexpected second case response":
							return httpio.Response{Status: http.StatusOK}, nil
						case "transport error with secret":
							return httpio.Response{}, errors.New(fixedPipelineSecret)
						}
					}
					return httpio.Response{Status: http.StatusNoContent}, nil
				}
				data, exit, err := f.run(ctx, send)
				if exit != tc.exit || calls != tc.sent || (len(f.lookups) != 0) != tc.lookup {
					t.Fatalf("exit=%d sends=%d lookups=%d, want exit=%d sends=%d lookup=%t",
						exit, calls, len(f.lookups), tc.exit, tc.sent, tc.lookup)
				}
				if tc.exit == 2 || tc.exit == 130 {
					if len(data) != 0 || err == nil || strings.Contains(err.Error(), fixedPipelineSecret) {
						t.Fatal("failed pipeline emitted bytes, omitted its error, or leaked a secret")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				for i, at := range starts {
					if at != time.Duration(i)*500*time.Millisecond {
						t.Fatalf("shared rate changed at attempt %d: %v", i+1, starts)
					}
				}
				batch := readFixedPipelineReport(t, data, exit, calls)
				if len(batch.Outcomes) != 2 || batch.Outcomes[0].Count != 4 || batch.Outcomes[1].Count != calls-4 ||
					len(batch.NotRun) != 0 {
					t.Fatal("report did not preserve individual case counts")
				}
				if tc.exit == 3 {
					stop := batch.Outcomes[1].Facts
					if stop.Stage != "time" || stop.Sequence != 2 || stop.Kind != "control" || stop.Condition != "deadline" {
						t.Fatalf("case deadline did not identify the next unstarted attempt: %+v", stop)
					}
				}
				if tc.exit == 0 {
					calls, starts, f.lookups, start = 0, nil, nil, time.Now()
					again, repeatExit, err := f.run(ctx, send)
					if err != nil || repeatExit != 0 || calls != 13 || !bytes.Equal(data, again) {
						t.Fatal("fixed report did not repeat byte for byte")
					}
				}
			})
		})
	}
}

type fixedPipelineReport struct {
	Exit     int      `json:"exit_code"`
	Requests int      `json:"requests_used"`
	NotRun   []string `json:"not_run_case_ids"`
	Outcomes []struct {
		Count int                       `json:"request_count"`
		Facts decision.OperationalFacts `json:"decision_facts"`
	} `json:"outcomes"`
}

func readFixedPipelineReport(t *testing.T, data []byte, exit, attempts int) fixedPipelineReport {
	t.Helper()
	var batch fixedPipelineReport
	if err := json.Unmarshal(data, &batch); err != nil || batch.Exit != exit ||
		batch.Requests != attempts || bytes.Contains(data, []byte(fixedPipelineSecret)) ||
		bytes.Contains(data, []byte(fixedResponseMarker)) {
		t.Fatal("report does not match exit code and attempts, or contains private data")
	}
	return batch
}

func TestFixedPipelineLoopback(t *testing.T) {
	var connections, received atomic.Int32
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 128))
		if err != nil || string(body) != boundaryBody || r.Method != http.MethodPost ||
			r.RequestURI != "/items" || r.Header.Get("X-Fixture-Key") != fixedPipelineSecret ||
			r.Header.Get("Authorization") != "" {
			t.Error("listener received something other than the approved inert baseline")
		}
		if received.Add(1) == 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		io.WriteString(w, fixedResponseMarker)
	}))
	server.Listener.Close()
	server.Listener = listener
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	rejected := newFixedPipeline(t, server.URL, false)
	rejected.trusted.port++ // The attempted target and policy still match the watched listener.
	var rejectedCalls int
	data, exit, err := rejected.run(t.Context(), func(ctx context.Context, req httpio.Request, timeout time.Duration, cap int64) (httpio.Response, error) {
		rejectedCalls++
		return httpio.Send(ctx, req, timeout, cap)
	})
	if err == nil || exit != 2 || len(data) != 0 || len(rejected.lookups) != 0 ||
		rejectedCalls != 0 || connections.Load() != 0 {
		t.Fatal("unapproved target reached credentials, output, or the listener")
	}
	f := newFixedPipeline(t, server.URL, false)
	var sawMarker bool
	data, exit, err = f.run(t.Context(), func(ctx context.Context, req httpio.Request, timeout time.Duration, cap int64) (httpio.Response, error) {
		res, err := httpio.Send(ctx, req, timeout, cap)
		if res.Status == http.StatusOK && !res.Truncated && string(res.Body) == fixedResponseMarker {
			sawMarker = true
		}
		return res, err
	})
	if err != nil || exit != 3 || received.Load() != 2 || !sawMarker ||
		!slices.Equal(f.lookups, []string{"PIPELINE_FIXTURE_KEY"}) {
		t.Fatal("rate limit did not stop the two-case loopback batch")
	}
	batch := readFixedPipelineReport(t, data, exit, 2)
	if len(batch.Outcomes) != 1 || batch.Outcomes[0].Count != 2 || !slices.Equal(batch.NotRun, []string{"post-json-time"}) {
		t.Fatal("rate-limited batch reported work that never started")
	}
	stop := batch.Outcomes[0].Facts
	if stop.Stage != "error" || stop.Sequence != 2 || stop.Kind != "error" ||
		stop.Condition != "rate_limited" || stop.StatusCode == nil || *stop.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("rate-limited observation had the wrong stop coordinate: %+v", stop)
	}
}
