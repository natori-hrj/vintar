// Package httpio sends single, user-directed HTTP requests.
package httpio

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"
)

const maxBodyLimit = 1 << 20

type Request struct {
	Method, URL string
	Headers     map[string]string
	Body        []byte
	RawQuery    *string // nil preserves the query; a pointer to "" removes it.
}

type Response struct {
	Status    int
	Body      []byte
	Truncated bool
	Elapsed   time.Duration
}

// Send performs one GET or POST. The timeout covers the entire transfer,
// including response body reads. A 429 response is returned without its body.
func Send(ctx context.Context, req Request, timeout time.Duration, limit int64) (res Response, err error) {
	if timeout <= 0 || timeout > 60*time.Second {
		return res, errors.New("HTTP timeout must be in (0, 60s]")
	}
	if limit < 1 || limit > maxBodyLimit {
		return res, errors.New("HTTP body limit must be between 1 and 1048576 bytes")
	}
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		return res, errors.New("unsupported HTTP method")
	}
	if ctx == nil {
		return res, errors.New("HTTP context is required")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return res, err
	}

	out, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return res, errors.New("invalid HTTP URL")
	}
	if (out.URL.Scheme != "http" && out.URL.Scheme != "https") ||
		out.URL.Hostname() == "" || out.URL.Opaque != "" || out.URL.User != nil {
		return res, errors.New("HTTP URL must be an absolute http or https URL without user information")
	}
	if req.RawQuery != nil {
		out.URL.RawQuery = *req.RawQuery
		out.URL.ForceQuery = false
	}
	for _, c := range out.URL.RawQuery {
		if c <= ' ' || c == 0x7f || c == '#' {
			return res, errors.New("HTTP query must be escaped")
		}
	}
	for _, name := range slices.Sorted(maps.Keys(req.Headers)) {
		value := req.Headers[name]
		if strings.EqualFold(name, "Host") {
			out.Host = value
		} else {
			out.Header.Set(name, value)
		}
	}

	transport := newTransport()
	defer transport.CloseIdleConnections()
	start := time.Now()
	defer func() { res.Elapsed = time.Since(start) }()
	// A direct RoundTrip returns redirects as responses, even if their
	// Location header is malformed. It does not interpret that header.
	reply, err := transport.RoundTrip(out)
	if err != nil {
		return res, safeError(ctx, "HTTP request failed")
	}
	defer reply.Body.Close()
	res.Status = reply.StatusCode
	if res.Status == http.StatusTooManyRequests {
		res.Truncated = true
		return res, nil
	}
	// A 101 may expose an upgraded connection rather than an HTTP body.
	if res.Status == http.StatusSwitchingProtocols {
		return res, nil
	}
	var reader io.Reader = reply.Body
	// Transport decodes automatically negotiated gzip, but does not
	// decode it when the caller sets Accept-Encoding explicitly.
	if strings.EqualFold(reply.Header.Get("Content-Encoding"), "gzip") {
		decoded, err := gzip.NewReader(reader)
		if err != nil {
			return res, safeError(ctx, "HTTP response body read failed")
		}
		defer decoded.Close()
		reader = decoded
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return res, safeError(ctx, "HTTP response body read failed")
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if int64(len(body)) > limit {
		res.Truncated = true
		body = body[:limit:limit]
	}
	res.Body = body
	return res, nil
}

func newTransport() *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Transport{
		Proxy:             nil,
		Protocols:         protocols,
		DisableKeepAlives: true,
	}
}

// Transport and body errors can include request data. Only return trusted
// messages or the original context sentinel.
func safeError(ctx context.Context, message string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New(message)
}
