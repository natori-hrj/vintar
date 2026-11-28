package httpio

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		{"preserve escaped delimiters", "?k%26=%252f%23%40&k%26=%2b&word=%c3%A9#ignored", path + "?k%26=%252f%23%40&k%26=%2b&word=%c3%A9", nil},
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
				if r.Header.Get("Accept-Encoding") != "gzip, deflate" || r.Header.Get("Authorization") != "" {
					t.Error("expected gzip and deflate negotiation and no implicit authorization header")
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

func TestSendNormalizedPort(t *testing.T) {
	const target = "/sample%2fitem?key=%2b+&key=%26"
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Host != r.Context().Value(http.LocalAddrContextKey).(net.Addr).String() || r.RequestURI != target {
			t.Errorf("Host = %q, request-target = %q", r.Host, r.RequestURI)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	base, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	var unicodePort strings.Builder
	for i, c := range port {
		if i%2 == 0 {
			unicodePort.WriteRune('٠' + c - '0')
		} else {
			unicodePort.WriteRune('𝟘' + c - '0')
		}
	}
	validPorts := []string{"+" + port, unicodePort.String(), "+00" + unicodePort.String(), " 0_" + unicodePort.String() + " "}
	for i, spelling := range validPorts {
		res, err := Send(t.Context(), Request{
			Method: http.MethodGet,
			URL:    "HTTP://" + base + ":" + spelling + target + "#ignored",
		}, testTimeout, 4)
		if err != nil || res.Status != http.StatusNoContent || hits.Load() != int32(i+1) {
			t.Fatalf("port %q: Send = %+v, %v; requests = %d", spelling, res, err, hits.Load())
		}
	}
	for _, spelling := range []string{"-" + port, "²", "65536", "%38%30", "+", "1:2", "1__", "1_"} {
		_, err := Send(t.Context(), Request{
			Method: http.MethodGet,
			URL:    "http://" + base + ":" + spelling + target,
		}, testTimeout, 4)
		if err == nil || err.Error() != "invalid HTTP URL" || hits.Load() != int32(len(validPorts)) {
			t.Fatalf("port %q: error = %v; requests = %d", spelling, err, hits.Load())
		}
	}
}

func TestSendRejectsURLCredentialsBeforeConnecting(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	for _, userinfo := range []string{"sample:secret", "sample:p%40ss", "sample"} {
		_, err := Send(t.Context(), Request{
			Method: http.MethodGet,
			URL:    "http://" + userinfo + "@" + strings.TrimPrefix(srv.URL, "http://"),
		}, testTimeout, 4)
		if err == nil || err.Error() != "HTTP URL must be an absolute http or https URL without user information" || hits.Load() != 0 {
			t.Fatalf("Send error = %v, requests = %d; want scrubbed rejection and no request", err, hits.Load())
		}
	}
}

func TestNormalizePortDoesNotRewriteOtherComponents(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"https://[::1]:+٤٤٣/a%2f?x=%3f", "https://[::1]/a%2f?x=%3f"},
		{"http://[::1]:+٨٠٨٠?x=%3a", "http://[::1]:8080?x=%3a"},
		{"http://example.invalid:+080/a%2f?x=%2b", "http://example.invalid/a%2f?x=%2b"},
		{"http://example.invalid:-٠", "http://example.invalid:0"},
		{"http://example.invalid/path:+١?x=://%3a", "http://example.invalid/path:+١?x=://%3a"},
	} {
		if got, ok := normalizePort(tc.raw); !ok || got != tc.want {
			t.Errorf("normalizePort(%q) = %q, %v; want %q", tc.raw, got, ok, tc.want)
		}
	}
}

func TestSendPublicRejectsExplicitZeroPort(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1:0/", "http://127.0.0.1:-0/", "http://127.0.0.1:+0/",
		"http://127.0.0.1: 0_０ /", "https://[::1]:-٠/",
	} {
		_, err := SendPublic(t.Context(), Request{Method: "GET", URL: target}, testTimeout, 10)
		if err == nil || err.Error() != "explicit zero HTTP port is unsupported" {
			t.Errorf("target %q: expected pre-transport zero-port rejection, got %v", target, err)
		}
	}
}

func TestSendPublicRejectsScopedIPv6(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback is unavailable")
	}
	var hits atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()

	scoped := strings.Replace(server.URL, "[::1]", "[::1%25test-zone]", 1)
	if _, err := SendPublic(t.Context(), Request{Method: "GET", URL: scoped}, testTimeout, 10); err == nil ||
		err.Error() != "scoped HTTP destinations are unsupported" || hits.Load() != 0 {
		t.Fatalf("unsafe scope handling: %v, requests = %d", err, hits.Load())
	}
	if _, err := SendPublic(t.Context(), Request{Method: "GET", URL: server.URL}, testTimeout, 10); err != nil || hits.Load() != 1 {
		t.Fatalf("unscoped loopback request failed: %v, requests = %d", err, hits.Load())
	}
}

func TestPublicHostCompatibility(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"例え.テスト", "xn--r8jz45g.xn--zckzah"},
		{"xn--r8jz45g.xn--zckzah", "xn--r8jz45g.xn--zckzah"},
		{"İ.invalid", "xn--i-9bb.invalid"},
		{"127．0．0．1", "127.0.0.1"},
		{"[::1]", "[::1]"},
		{"ｅxample.invalid", ""},
		{"１２７.0.0.1", ""},
		{"127.00.0.1", ""},
		{"%C3%A9.invalid", ""},
	} {
		t.Run(tc.host, func(t *testing.T) {
			raw := "http://" + tc.host + ":8080/fixed"
			target, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			authority, _ := publicTargetParts(raw)
			err = normalizePublicHost(target, authority)
			if tc.want == "" {
				if err == nil {
					t.Fatal("unsupported host was accepted")
				}
			} else if err != nil || target.Host != tc.want+":8080" {
				t.Fatalf("host = %q, %v; want %q", target.Host, err, tc.want)
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

func TestSendStackedEncodings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Content-Encoding", "gzip")
		w.Header().Add("Content-Encoding", "deflate")
		outer := zlib.NewWriter(w)
		inner := gzip.NewWriter(outer)
		io.WriteString(inner, "decoded body")
		inner.Close()
		outer.Close()
	}))
	defer srv.Close()
	res, err := Send(t.Context(), Request{Method: "GET", URL: srv.URL}, testTimeout, 7)
	if err != nil || string(res.Body) != "decoded" || !res.Truncated {
		t.Fatalf("stacked response = %+v, %v", res, err)
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

func TestSendDeflate(t *testing.T) {
	payload := strings.Repeat("abcdefgh", 1024)
	var wrapped, raw bytes.Buffer
	write := func(w io.WriteCloser) {
		t.Helper()
		if _, err := io.WriteString(w, payload); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	write(zlib.NewWriter(&wrapped))
	rawWriter, err := flate.NewWriter(&raw, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	write(rawWriter)

	// A raw stored block can also start with a valid zlib header.
	collision := []byte{0x78, 0x9c, 0x00, 0x63, 0xff}
	collision = append(collision, payload[:156]...)
	collision = append(collision, 0x01, 0x00, 0x00, 0xff, 0xff)
	badChecksum := bytes.Clone(wrapped.Bytes())
	badChecksum[len(badChecksum)-1] ^= 1
	for _, tc := range []struct {
		name      string
		wire      []byte
		limit     int64
		want      string
		truncated bool
		fail      bool
	}{
		{"zlib", wrapped.Bytes(), 8192, payload, false, false},
		{"zlib limited", wrapped.Bytes(), 4, "abcd", true, false},
		{"raw", raw.Bytes(), 8192, payload, false, false},
		{"raw limited", raw.Bytes(), 4, "abcd", true, false},
		{"raw with zlib-like header", collision, 156, payload[:156], false, false},
		{"empty HTTP body", nil, 4, "", false, false},
		{"encoded empty body", []byte{0x78, 0x9c, 0x03, 0x00, 0, 0, 0, 1}, 4, "", false, false},
		{"partial stream", wrapped.Bytes()[:1], 4, "", false, true},
		{"malformed stream", []byte{0x07, 0x00}, 4, "", false, true},
		{"invalid zlib checksum", badChecksum, 8192, "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Header.Get("Accept-Encoding") != "deflate" {
					t.Errorf("accept-encoding = %q", r.Header.Get("Accept-Encoding"))
				}
				w.Header().Set("Content-Encoding", "Deflate")
				w.Write(tc.wire)
			}))
			defer srv.Close()
			res, err := Send(t.Context(), Request{
				Method: http.MethodGet, URL: srv.URL, Headers: map[string]string{"accept-encoding": "deflate"},
			}, testTimeout, tc.limit)
			if tc.fail {
				if err == nil || err.Error() != "HTTP response body read failed" {
					t.Errorf("Send error = %v, want scrubbed decoding error", err)
				}
			} else if err != nil {
				t.Errorf("Send error = %v", err)
			}
			if hits.Load() != 1 || res.Status != http.StatusOK || string(res.Body) != tc.want || res.Truncated != tc.truncated {
				t.Errorf("Send: status = %d, decoded bytes = %d, truncated = %v, requests = %d", res.Status, len(res.Body), res.Truncated, hits.Load())
			}
		})
	}
}

func TestSendDeflateMissingBodyIsNotEmpty(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Encoding", "deflate")
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
	}))
	defer srv.Close()
	_, err := Send(t.Context(), Request{Method: http.MethodGet, URL: srv.URL}, testTimeout, 4)
	if err == nil || err.Error() != "HTTP response body read failed" || hits.Load() != 1 {
		t.Fatalf("Send error = %v, requests = %d; want one failed response", err, hits.Load())
	}
}

func TestSendDeflateStopsAtDecodedLimitWithoutWaitingForEOF(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "deflate")
		compressed := zlib.NewWriter(w)
		if _, err := io.WriteString(compressed, "12345"); err != nil {
			t.Error(err)
			return
		}
		if err := compressed.Flush(); err != nil {
			t.Error(err)
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	res, err := Send(t.Context(), Request{Method: http.MethodGet, URL: srv.URL}, testTimeout, 1)
	if err != nil || res.Status != http.StatusOK || string(res.Body) != "1" || !res.Truncated {
		t.Fatalf("Send = %+v, %v", res, err)
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
		w.Header().Set("Content-Encoding", "deflate")
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
