package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/natori-hrj/vintar/internal/casefile"
	"github.com/natori-hrj/vintar/internal/execution/internal/httpio"
)

const boundaryGET = `version = 2
identity_id = "fixture-reader"
id = "fixture-get"
type = "sqli.boolean"
expected_verdict = "not_detected"
[request]
method = "GET"
url = "https://stored.invalid/items/%7Estatus"
allowed_origin = "https://stored.invalid"
params = [["name", "one two+"], ["name", ""]]
[injection]
location = "query"
name = "name"
occurrence = 1
mode = "replace"
[probes]
true_payload = "inert-a"
false_payload = "inert-b"
[limits]
max_requests = 6
requests_per_second = 2.0
timeout_seconds = 5.0
[approval]
method = "GET"
path = "/items/%7Estatus"
environment_class = "isolated_test"
`

const (
	boundaryQuery  = "name=one%20two%2B&name="
	boundaryBody   = `{"name":"baseline"}`
	boundaryReader = "fixture-private-reader"
	boundaryWriter = "fixture-private-writer"
)

type boundaryObservation struct {
	CaseID    string
	Started   bool
	Status    int
	BodyBytes int
	Truncated bool
	Elapsed   time.Duration
}

type boundaryFixture struct {
	target    Origin
	trusted   []Origin
	policy    string
	requested PolicyLimits
	lookups   []string
	noWriter  bool
}

func newBoundaryFixture(t *testing.T, endpoint, operatorOrigin string) *boundaryFixture {
	t.Helper()
	target := fixturePolicyOrigin(t, endpoint)
	if target.scheme != "http" || target.host != "127.0.0.1" {
		t.Fatal("the execution fixture requires IPv4 loopback")
	}
	allowed := fixturePolicyOrigin(t, operatorOrigin)
	// Independent operator data. Approval values are not generated from the
	// parsed case; in particular, the stored POST digests must match these.
	policy := fmt.Sprintf(`{
		"schema_version":1,"policy_type":"post_json_execution",
		"identities":[
			{"identity_id":"fixture-reader","credential_kind":"bearer","env_var":"FIXTURE_READER","header_name":"Authorization"},
			{"identity_id":"reviewed-user","credential_kind":"api_key_header","env_var":"FIXTURE_WRITER","header_name":"X-Fixture-Key"}
		],
		"approvals":[
			{"case_id":"fixture-get","identity_id":"fixture-reader","credential_kind":"bearer","credential_env_var":"FIXTURE_READER","method":"GET","path":"/items/%%7Estatus","origin":%[1]q,"allowed_environment_classes":["isolated_test"]},
			{"case_id":"post-json-boolean","identity_id":"reviewed-user","credential_kind":"api_key_header","credential_env_var":"FIXTURE_WRITER","method":"POST","path":"/items","origin":%[1]q,"allowed_environment_classes":["isolated_test"],"allowed_side_effect":"no_side_effect",
			 "operation_definition_sha256":"0000000000000000000000000000000000000000000000000000000000000000",
			 "baseline_body_sha256":"5e5c0546e15bd689be19e8e151d0517b1ae9f6c96edfda7fbf930a72ae99056d"}
		],
		"limits":{"max_requests":2,"max_requests_per_second":5,"max_timeout_seconds":1,"max_response_size":8,"max_time_execution_seconds":2}
	}`, operatorOrigin)
	return &boundaryFixture{
		target:    target,
		trusted:   []Origin{allowed},
		policy:    policy,
		requested: PolicyLimits{MaxRequests: 2, Rate: 10, Timeout: time.Second, MaxResponseSize: 32, Deadline: 2 * time.Second},
	}
}

// exercise joins existing components for exactly two test fixtures. It is not
// a case runner: no probe fields, external input, or production CLI are used.
// Two identities exercise the credential boundary; the released verify CLI
// accepts only one v2 identity per batch.
func (f *boundaryFixture) exercise(t *testing.T, ctx context.Context,
	send func(context.Context, httpio.Request, time.Duration, int64) (httpio.Response, error),
) ([]boundaryObservation, error) {
	t.Helper()
	post, err := os.ReadFile("../../tests/golden/cases/post-json-boolean-v2.toml")
	if err != nil {
		t.Fatal(err)
	}
	var requests []ApprovalRequest
	for _, raw := range [][]byte{[]byte(boundaryGET), post} {
		stored, err := casefile.Parse(raw)
		if err != nil || stored.Version != casefile.Version2 {
			t.Fatal("fixed v2 case fixture did not parse")
		}
		approval := stored.Approval
		request := ApprovalRequest{
			CaseID: stored.ID, IdentityID: *stored.IdentityID, Origin: f.target,
			Method: string(approval.Method), Path: approval.Path, Environment: approval.EnvironmentClass,
		}
		if metadata := approval.PostJSON; metadata != nil {
			if string(stored.Request.JSONBody) != boundaryBody {
				t.Fatal("approved canonical body changed")
			}
			request.OperationDigest = metadata.OperationDefinitionSHA256
			request.BaselineDigest = metadata.BaselineBodySHA256
			request.SideEffect = metadata.SideEffect
		} else if casefile.EncodeQuery(stored.Request.Params) != boundaryQuery {
			t.Fatal("approved baseline query changed")
		}
		requests = append(requests, request)
	}
	policy, err := LoadRuntimePolicy(func(name string) (string, bool) {
		return f.policy, name == "VINTAR_RUNTIME_POLICY_JSON"
	})
	if err != nil {
		return nil, err
	}
	governor, err := policy.Governor(f.requested)
	if err != nil {
		return nil, err
	}
	if len(requests) > governor.limits.MaxRequests {
		return nil, errors.New("fixed batch exceeds request budget")
	}
	prepared, err := policy.PrepareAll(ctx, requests, f.trusted, time.Now(), func(name string) (string, bool) {
		f.lookups = append(f.lookups, name)
		switch name {
		case "FIXTURE_READER":
			return boundaryReader, true
		case "FIXTURE_WRITER":
			return boundaryWriter, !f.noWriter
		default:
			return "", false
		}
	})
	if err != nil {
		return nil, err
	}
	got := make([]boundaryObservation, len(prepared))
	for i := range got {
		got[i].CaseID = requests[i].CaseID
	}
	query := boundaryQuery
	endpoint := fmt.Sprintf("http://127.0.0.1:%d", f.target.port)
	wire := []httpio.Request{
		{Method: "GET", URL: endpoint + "/items/%7Estatus", RawQuery: &query},
		{Method: "POST", URL: endpoint + "/items", Body: []byte(boundaryBody)},
	}
	for i, op := range prepared {
		if op.URL != wire[i].URL || op.Method != wire[i].Method {
			t.Fatal("fixture preflight changed an approved wire destination or method")
		}
	}
	for i, op := range prepared {
		err := governor.Run(ctx, func(ctx context.Context, cap int64) (bool, error) {
			req := wire[i]
			req.Headers = map[string]string{}
			if err := op.ApplyCredential(req.Headers); err != nil {
				return false, err
			}
			got[i].Started = true
			res, err := send(ctx, req, governor.limits.Timeout, cap)
			if err != nil {
				return false, err
			}
			got[i].Status = res.Status
			got[i].BodyBytes = len(res.Body)
			got[i].Truncated = res.Truncated
			got[i].Elapsed = res.Elapsed
			return res.Status == http.StatusTooManyRequests, nil
		})
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

func TestExecutionBoundaryRejectsBeforeSecretsOrSend(t *testing.T) {
	for name, change := range map[string]func(*boundaryFixture){
		"missing independent authorization": func(f *boundaryFixture) { f.trusted = nil },
		"mismatched runtime target":         func(f *boundaryFixture) { f.target.port++ },
		"invalid inline policy":             func(f *boundaryFixture) { f.policy = "" },
		"second approval digest": func(f *boundaryFixture) {
			f.policy = strings.Replace(f.policy, "5e5c0546", "00000000", 1)
		},
		"second approval environment": func(f *boundaryFixture) {
			i := strings.LastIndex(f.policy, "isolated_test")
			f.policy = f.policy[:i] + strings.Replace(f.policy[i:], "isolated_test", "other", 1)
		},
		"insufficient budget": func(f *boundaryFixture) { f.requested.MaxRequests = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f := newBoundaryFixture(t, "http://127.0.0.1:18760", "http://127.0.0.1:18760")
			change(f)
			got, err := f.exercise(t, t.Context(), func(context.Context, httpio.Request, time.Duration, int64) (httpio.Response, error) {
				t.Fatal("rejected batch started a request")
				return httpio.Response{}, nil
			})
			if got != nil || err == nil || len(f.lookups) != 0 {
				t.Fatal("rejection returned observations or resolved credentials")
			}
		})
	}
}

func TestExecutionBoundaryMockSchedule(t *testing.T) {
	for _, tc := range []struct {
		mode      string
		wantCount int
		wantError error
	}{
		{mode: "complete", wantCount: 2},
		{mode: "deadline while rate-limited", wantCount: 1, wantError: context.DeadlineExceeded},
		{mode: "operation timeout", wantCount: 1, wantError: context.DeadlineExceeded},
		{mode: "cancel while rate-limited", wantCount: 1, wantError: context.Canceled},
		{mode: "already canceled", wantError: context.Canceled},
		{mode: "transport failure", wantCount: 1, wantError: errors.New("execution operation failed")},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newBoundaryFixture(t, "http://127.0.0.1:18760", "http://127.0.0.1:18760")
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				switch tc.mode {
				case "deadline while rate-limited":
					f.requested.Deadline = 150 * time.Millisecond
				case "operation timeout":
					f.requested.Timeout = 100 * time.Millisecond
				case "already canceled":
					cancel()
				}
				start := time.Now()
				var starts []time.Duration
				got, err := f.exercise(t, ctx, func(ctx context.Context, _ httpio.Request, _ time.Duration, cap int64) (httpio.Response, error) {
					if !reflect.DeepEqual(f.lookups, []string{"FIXTURE_READER", "FIXTURE_WRITER"}) || cap != 8 {
						t.Fatal("send started before both credentials were resolved or without policy response cap")
					}
					starts = append(starts, time.Since(start))
					switch tc.mode {
					case "cancel while rate-limited":
						time.AfterFunc(50*time.Millisecond, cancel)
					case "operation timeout":
						<-ctx.Done()
						return httpio.Response{}, ctx.Err()
					case "transport failure":
						return httpio.Response{}, errors.New(boundaryReader)
					}
					return httpio.Response{Status: http.StatusNoContent}, nil
				})
				match := errors.Is(err, tc.wantError)
				if tc.mode == "transport failure" {
					match = err != nil && err.Error() == tc.wantError.Error()
				}
				if !match || len(starts) != tc.wantCount {
					t.Fatalf("unexpected termination: mode=%s starts=%v", tc.mode, starts)
				}
				if tc.mode == "complete" && !reflect.DeepEqual(starts, []time.Duration{0, 200 * time.Millisecond}) {
					t.Fatalf("policy rate was not enforced: %v", starts)
				}
				if tc.wantCount == 0 {
					if len(f.lookups) != 0 || got != nil {
						t.Fatal("already-canceled batch resolved credentials")
					}
					return
				}
				if len(got) != 2 || !got[0].Started || got[1].Started != (tc.wantCount == 2) {
					t.Fatal("observations miscounted starts")
				}
			})
		})
	}
}

func TestExecutionBoundaryLoopback(t *testing.T) {
	type wireEvent struct {
		method, uri, body string
		credentialOK      bool
	}
	events := make(chan wireEvent, 4)
	var connections atomic.Int32
	var drop atomic.Bool
	var redirectConnections atomic.Int32
	redirect := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	redirect.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			redirectConnections.Add(1)
		}
	}
	redirect.Start()
	defer redirect.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 128))
		auth := r.Header.Get("Authorization")
		key := r.Header.Get("X-Fixture-Key")
		isGET := r.RequestURI == "/items/%7Estatus?"+boundaryQuery
		credentialOK := err == nil && (isGET && auth == "Bearer "+boundaryReader && key == "" ||
			!isGET && auth == "" && key == boundaryWriter)
		events <- wireEvent{r.Method, r.RequestURI, string(body), credentialOK}
		if drop.Load() {
			conn, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error("fixture could not close the connection before a response")
				return
			}
			conn.Close()
			return
		}
		if isGET {
			w.Header().Set("Location", redirect.URL+"/redirect-trap")
			w.WriteHeader(http.StatusFound)
		}
		io.WriteString(w, boundaryWriter) // Synthetic response data; must not escape into observations.
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
	rejected := newBoundaryFixture(t, server.URL, server.URL)
	rejected.policy = strings.Replace(rejected.policy, "5e5c0546", "00000000", 1)
	if got, err := rejected.exercise(t, t.Context(), httpio.Send); err == nil || got != nil ||
		len(rejected.lookups) != 0 || connections.Load() != 0 {
		t.Fatal("rejected approval reached credential lookup or the loopback listener")
	}
	missing := newBoundaryFixture(t, server.URL, server.URL)
	missing.noWriter = true
	if got, err := missing.exercise(t, t.Context(), httpio.Send); !errors.Is(err, errAuthMissing) || got != nil ||
		len(missing.lookups) != 2 || connections.Load() != 0 {
		t.Fatal("missing second credential did not stop the entire batch before connecting")
	}
	f := newBoundaryFixture(t, server.URL, server.URL)
	got, err := f.exercise(t, t.Context(), httpio.Send)
	if err != nil || len(got) != 2 || len(events) != 2 || connections.Load() != 2 || redirectConnections.Load() != 0 {
		t.Fatal("expected exactly two loopback requests")
	}
	want := []wireEvent{
		{"GET", "/items/%7Estatus?" + boundaryQuery, "", true},
		{"POST", "/items", boundaryBody, true},
	}
	for i, expected := range want {
		if <-events != expected || !got[i].Started || !got[i].Truncated || got[i].BodyBytes != 8 {
			t.Fatal("wire order, baseline, credential isolation, or response cap did not match")
		}
	}
	wire, err := json.Marshal(got)
	if err != nil || got[0].Status != http.StatusFound || got[1].Status != http.StatusOK ||
		strings.Contains(string(wire), boundaryReader) || strings.Contains(string(wire), boundaryWriter) {
		t.Fatal("observations leaked data or did not preserve received status")
	}
	drop.Store(true)
	f = newBoundaryFixture(t, server.URL, server.URL)
	got, err = f.exercise(t, t.Context(), httpio.Send)
	if err == nil || len(got) != 2 || !got[0].Started || got[0].Status != 0 || got[1].Started ||
		len(events) != 1 || <-events != want[0] || connections.Load() != 3 {
		t.Fatal("transport failure was retried or the batch did not stop")
	}
}
