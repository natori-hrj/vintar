// Package httpio sends single, user-directed HTTP requests.
package httpio

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
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
	return send(ctx, req, timeout, limit, false)
}

// SendPublic applies URL compatibility for the user-directed http send
// command. Callers with already-validated request targets use Send.
func SendPublic(ctx context.Context, req Request, timeout time.Duration, limit int64) (Response, error) {
	return send(ctx, req, timeout, limit, true)
}

func send(ctx context.Context, req Request, timeout time.Duration, limit int64, public bool) (res Response, err error) {
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

	target, ok := normalizePort(req.URL)
	if !ok {
		return res, errors.New("invalid HTTP URL")
	}
	out, err := http.NewRequestWithContext(ctx, req.Method, target, bytes.NewReader(req.Body))
	if err != nil {
		return res, errors.New("invalid HTTP URL")
	}
	if (out.URL.Scheme != "http" && out.URL.Scheme != "https") ||
		out.URL.Hostname() == "" || out.URL.Opaque != "" || out.URL.User != nil {
		return res, errors.New("HTTP URL must be an absolute http or https URL without user information")
	}
	if public {
		authority, rawPath := publicTargetParts(target)
		if err := normalizePublicHost(out.URL, authority); err != nil {
			return res, err
		}
		// Use the same authority for dialing and the default HTTP Host.
		// An explicit Host supplied below still overrides the default.
		out.Host = out.URL.Host
		normalizePublicPath(out.URL, rawPath)
	}
	if req.RawQuery != nil {
		out.URL.RawQuery = *req.RawQuery
		out.URL.ForceQuery = false
	} else if public {
		out.URL.RawQuery = escapePublicQuery(out.URL.RawQuery)
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
	if _, explicit := out.Header["Accept-Encoding"]; !explicit {
		out.Header.Set("Accept-Encoding", "gzip, deflate")
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
	// Decode before enforcing the body limit, regardless of how the
	// encoding was negotiated.
	encodings := strings.Split(strings.Join(reply.Header.Values("Content-Encoding"), ","), ",")
	if len(encodings) > 16 {
		return res, errors.New("HTTP response encoding chain is too long")
	}
	for i := len(encodings) - 1; i >= 0; i-- {
		var openDecoder func(io.Reader) (io.ReadCloser, error)
		switch strings.ToLower(strings.TrimSpace(encodings[i])) {
		case "gzip":
			openDecoder = func(r io.Reader) (io.ReadCloser, error) { return gzip.NewReader(r) }
		case "deflate":
			openDecoder = newDeflateReader
		default:
			continue
		}
		decoded, err := openDecoder(reader)
		if err == io.EOF {
			// A response can carry representation metadata without a body.
			return res, ctx.Err()
		}
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

// normalizePort rewrites only an explicit port in the authority. The path,
// query, and fragment are left for net/url to parse as before.
func normalizePort(raw string) (string, bool) {
	scheme, rest, found := strings.Cut(raw, "://")
	defaultPort := 80
	switch {
	case !found:
		return raw, true
	case strings.EqualFold(scheme, "http"):
	case strings.EqualFold(scheme, "https"):
		defaultPort = 443
	default:
		return raw, true
	}
	end := strings.IndexAny(rest, "/?#")
	if end == -1 {
		end = len(rest)
	}
	authority := rest[:end]
	// Leave disallowed user information to the existing URL validation.
	if strings.Contains(authority, "@") {
		return raw, true
	}
	var host, port string
	if strings.HasPrefix(authority, "[") {
		close := strings.IndexByte(authority, ']')
		if close < 0 {
			return raw, true
		}
		host = authority[:close+1]
		port, found = strings.CutPrefix(authority[close+1:], ":")
	} else {
		host, port, found = strings.Cut(authority, ":")
	}
	if !found || port == "" {
		return raw, true
	}
	if host == "" || strings.Contains(port, ":") {
		return raw, false
	}
	digits, negative := strings.CutPrefix(strings.TrimSpace(port), "-")
	if !negative {
		digits = strings.TrimPrefix(digits, "+")
	}
	if digits == "" {
		return raw, false
	}
	number := 0
	afterDigit := false
	for _, r := range digits {
		if r == '_' && afterDigit {
			afterDigit = false
			continue
		}
		digit := decimalDigit(r)
		if digit < 0 {
			return raw, false
		}
		number = number*10 + digit
		if number > 65535 || (negative && number != 0) {
			return raw, false
		}
		afterDigit = true
	}
	if !afterDigit {
		return raw, false
	}
	// In particular, signed zero remains an explicit port, not a
	// request to fall back to a different destination.
	if number != defaultPort {
		host += ":" + strconv.Itoa(number)
	}
	return scheme + "://" + host + rest[end:], true
}

func decimalDigit(r rune) int {
	// Unicode Nd ranges consist of one or more ordered sets of ten.
	for _, block := range unicode.Digit.R16 {
		lo, hi, stride := rune(block.Lo), rune(block.Hi), rune(block.Stride)
		if r >= lo && r <= hi && (r-lo)%stride == 0 {
			return int((r - lo) / stride % 10)
		}
	}
	for _, block := range unicode.Digit.R32 {
		lo, hi, stride := rune(block.Lo), rune(block.Hi), rune(block.Stride)
		if r >= lo && r <= hi && (r-lo)%stride == 0 {
			return int((r - lo) / stride % 10)
		}
	}
	return -1
}

// deflatePrefix retains only a bounded prefix of the compressed body, until
// the zlib decoder produces output. This allows raw deflate fallback on the
// same response even when its first bytes happen to look like a zlib header.
type deflatePrefix struct {
	data []byte
	done bool
}

func (p *deflatePrefix) Write(b []byte) (int, error) {
	if !p.done {
		const replayLimit = 32 << 10
		if len(b) <= replayLimit-len(p.data) {
			p.data = append(p.data, b...)
		} else {
			p.data, p.done = nil, true
		}
	}
	return len(b), nil
}

func newDeflateReader(r io.Reader) (io.ReadCloser, error) {
	source := bufio.NewReader(r)
	if _, err := source.Peek(1); err != nil {
		// Distinguish an empty HTTP body from a prematurely ended
		// transfer, before zlib starts parsing the header.
		return nil, err
	}
	prefix := new(deflatePrefix)
	decoded, err := zlib.NewReader(io.TeeReader(source, prefix))
	if err == nil {
		// Probe for output, not merely a valid zlib header. Once any
		// decoded data exists, a later error cannot switch encodings.
		var first [1]byte
		n, readErr := decoded.Read(first[:])
		if n > 0 || readErr == io.EOF {
			prefix.data, prefix.done = nil, true
			return struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(first[:n]), decoded), decoded}, nil
		}
		decoded.Close()
		err = readErr
	}
	var corrupt flate.CorruptInputError
	if !prefix.done && (err == zlib.ErrHeader || err == zlib.ErrDictionary ||
		err == zlib.ErrChecksum || errors.As(err, &corrupt)) {
		return flate.NewReader(io.MultiReader(bytes.NewReader(prefix.data), source)), nil
	}
	return nil, err
}

func newTransport() *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Transport{
		Proxy:              nil,
		Protocols:          protocols,
		DisableKeepAlives:  true,
		DisableCompression: true,
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
