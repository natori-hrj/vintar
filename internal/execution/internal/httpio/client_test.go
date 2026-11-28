package httpio

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testTimeout = 5 * time.Second

func TestSendRequestTargetAndOptions(t *testing.T) {
	const path = "/a%2fb/%7e//leaf"
	replacement, empty := "b=%2f+a&b=%7e&empty=", ""
	for _, tc := range []struct {
		name, query, want string
		rawQuery          *string
	}{
		{"preserve", "?original=%2F+&x=%41", path + "?original=%2F+&x=%41", nil},
		{"preserve bare question mark", "?", path + "?", nil},
		{"replace", "?original=1", path + "?" + replacement, &replacement},
		{"clear", "?original=1", path, &empty},
		{"clear bare question mark", "?", path, &empty},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const payload = "some bytes\x00\n"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI != tc.want {
					t.Errorf("request-target = %q, want %q", r.RequestURI, tc.want)
				}
				if r.Method != http.MethodPost || r.Proto != "HTTP/1.1" || !r.Close {
					t.Errorf("method/protocol/close = %s/%s/%v", r.Method, r.Proto, r.Close)
				}
				if r.Header.Get("Content-Type") != "application/octet-stream" {
					t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
				}
				if r.Header.Get("Accept-Encoding") != "gzip" || r.Header.Get("Authorization") != "" {
					t.Error("expected gzip negotiation and no implicit authorization header")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != payload {
					t.Errorf("request body = %q, err = %v", body, err)
				}
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, "created")
			}))
			defer srv.Close()

			res, err := Send(context.Background(), Request{
				Method:   http.MethodPost,
				URL:      srv.URL + path + tc.query,
				Headers:  map[string]string{"content-type": "application/octet-stream"},
				Body:     []byte(payload),
				RawQuery: tc.rawQuery,
			}, testTimeout, 64)
			if err != nil || res.Status != http.StatusCreated || string(res.Body) != "created" || res.Truncated || res.Elapsed <= 0 {
				t.Fatalf("Send = %+v, %v", res, err)
			}
		})
	}
}

func TestSendGzipLimitAndMalformedRedirect(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Location", "%bad-escape-%")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusFound)
		body := gzip.NewWriter(w)
		io.WriteString(body, "abcdefgh")
		body.Close()
	}))
	defer srv.Close()
	for i, headers := range []map[string]string{nil, {"Accept-Encoding": "gzip"}} {
		res, err := Send(t.Context(), Request{
			Method: "GET", URL: srv.URL, Headers: headers,
		}, testTimeout, 4)
		if err != nil || res.Status != 302 || string(res.Body) != "abcd" || !res.Truncated || hits.Load() != int32(i+1) {
			t.Fatalf("unexpected response or request count: %+v, %v; requests = %d", res, err, hits.Load())
		}
	}
}

func TestSendGzipMetadataWithoutBody(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNoContent, http.StatusNotModified} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("ETag", `"v1"`)
				w.WriteHeader(status)
			}))
			defer srv.Close()
			res, err := Send(t.Context(), Request{
				Method: "GET", URL: srv.URL,
				Headers: map[string]string{"Accept-Encoding": "gzip", "If-None-Match": `"v1"`},
			}, testTimeout, 4)
			if err != nil || res.Status != status || len(res.Body) != 0 || res.Truncated {
				t.Fatalf("want empty successful response: %+v, %v", res, err)
			}
		})
	}
}

func TestSendDoesNotTreatTruncatedGzipAsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte{0x1f})
	}))
	defer srv.Close()
	if _, err := Send(t.Context(), Request{
		Method: "GET", URL: srv.URL, Headers: map[string]string{"Accept-Encoding": "gzip"},
	}, testTimeout, 4); err == nil {
		t.Fatal("accepted truncated gzip stream")
	}
}

func TestSendDoesNotRetryAResponseThatEndsEarly(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "short")
	}))
	defer srv.Close()
	_, err := Send(t.Context(), Request{Method: "GET", URL: srv.URL}, testTimeout, 100)
	if err == nil || hits.Load() != 1 {
		t.Fatalf("HTTP error = %v, requests = %d; want one failed request", err, hits.Load())
	}
}

func TestSendBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "12345")
	}))
	defer srv.Close()

	for _, tc := range []struct {
		limit     int64
		body      string
		truncated bool
	}{
		{1, "1", true},
		{5, "12345", false},
		{1 << 20, "12345", false},
	} {
		res, err := Send(context.Background(), Request{Method: http.MethodGet, URL: srv.URL}, testTimeout, tc.limit)
		if err != nil || res.Status != http.StatusNotFound || string(res.Body) != tc.body || res.Truncated != tc.truncated {
			t.Errorf("limit %d: Send = %+v, %v", tc.limit, res, err)
		}
	}
}

func TestSendNoEnvironmentProxyOrRedirect(t *testing.T) {
	var proxyHits, redirectHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	// Go's environment proxy helper also bypasses loopback URLs, so zero
	// fixture hits alone would not distinguish ProxyFromEnvironment from nil.
	if newTransport().Proxy != nil {
		t.Fatal("transport has a proxy resolver")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/follow" {
			redirectHits.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Location", "/follow")
		w.WriteHeader(http.StatusFound)
		_, _ = io.WriteString(w, "redirect response")
	}))
	defer srv.Close()

	res, err := Send(context.Background(), Request{Method: http.MethodGet, URL: srv.URL}, testTimeout, 64)
	if err != nil || res.Status != http.StatusFound || string(res.Body) != "redirect response" || res.Truncated {
		t.Fatalf("Send = %+v, %v", res, err)
	}
	if proxyHits.Load() != 0 || redirectHits.Load() != 0 {
		t.Fatalf("proxy hits = %d, redirect hits = %d", proxyHits.Load(), redirectHits.Load())
	}
}

func TestSend429DoesNotReadBody(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusTooManyRequests)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	res, err := Send(context.Background(), Request{Method: http.MethodGet, URL: srv.URL}, testTimeout, 1)
	if err != nil || res.Status != http.StatusTooManyRequests || len(res.Body) != 0 || !res.Truncated {
		t.Fatalf("Send = %+v, %v", res, err)
	}
}

func TestSendRejectsTimeoutAboveLimitBeforeConnecting(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	req := Request{Method: http.MethodGet, URL: srv.URL}
	if _, err := Send(t.Context(), req, 61*time.Second, 1); err == nil || hits.Load() != 0 {
		t.Fatalf("want rejected timeout and zero requests; error = %v, requests = %d", err, hits.Load())
	}
	if _, err := Send(t.Context(), req, 60*time.Second, 1); err != nil || hits.Load() != 1 {
		t.Fatalf("want accepted maximum and one request; error = %v, requests = %d", err, hits.Load())
	}
}

func TestSendTimeoutIncludesBody(t *testing.T) {
	srv, _, release := stalledBodyServer()
	defer srv.Close()
	defer close(release)

	res, err := Send(context.Background(), Request{Method: http.MethodGet, URL: srv.URL}, time.Second, 10)
	if !errors.Is(err, context.DeadlineExceeded) || res.Status != http.StatusOK || len(res.Body) != 0 {
		t.Fatalf("Send = %+v, %v; want status 200 and deadline exceeded during body read", res, err)
	}
}

func TestSendStopsAtBodyLimitWithoutWaitingForEOF(t *testing.T) {
	srv, _, release := stalledBodyServer()
	defer srv.Close()
	defer close(release)

	res, err := Send(context.Background(), Request{Method: http.MethodGet, URL: srv.URL}, testTimeout, 1)
	if err != nil || res.Status != http.StatusOK || string(res.Body) != "1" || !res.Truncated {
		t.Fatalf("Send = %+v, %v", res, err)
	}
}

func TestSendContextCancellation(t *testing.T) {
	srv, flushed, release := stalledBodyServer()
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-flushed:
			cancel()
		case <-ctx.Done():
		}
	}()
	_, err := Send(ctx, Request{Method: http.MethodGet, URL: srv.URL}, testTimeout, 10)
	if err != context.Canceled {
		t.Fatalf("Send error = %v, want unwrapped context.Canceled", err)
	}
}

func stalledBodyServer() (*httptest.Server, <-chan struct{}, chan struct{}) {
	flushed, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "12")
		w.(http.Flusher).Flush()
		close(flushed)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	return srv, flushed, release
}

func TestSendValidationAndErrorScrubbing(t *testing.T) {
	for _, tc := range []struct {
		name, method, target, want string
		timeout                    time.Duration
		limit                      int64
	}{
		{"timeout", "GET", "", "HTTP timeout must be in (0, 60s]", 0, 1},
		{"lower limit", "GET", "", "HTTP body limit must be between 1 and 1048576 bytes", time.Second, 0},
		{"upper limit", "GET", "", "HTTP body limit must be between 1 and 1048576 bytes", time.Second, (1 << 20) + 1},
		{"method", "SECRET", "", "unsupported HTTP method", time.Second, 1},
		{"URL", "GET", "http://user:SECRET@localhost/%zz", "invalid HTTP URL", time.Second, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Send(context.Background(), Request{Method: tc.method, URL: tc.target}, tc.timeout, tc.limit)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("Send error = %v, want %q", err, tc.want)
			}
		})
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached a fixture with an untrusted TLS certificate")
	}))
	defer srv.Close()
	_, err := Send(context.Background(), Request{
		Method:  http.MethodGet,
		URL:     srv.URL + "/secret-path?secret-query",
		Headers: map[string]string{"Authorization": "secret-credential"},
	}, testTimeout, 1)
	if err == nil || err.Error() != "HTTP request failed" || strings.Contains(err.Error(), "secret") {
		t.Fatalf("Send error = %v, want scrubbed TLS error", err)
	}
}
