package casefile

import (
	"net/netip"
	"sort"
	"strings"
)

// storedOrigin is a comparison key for a case declaration. It is neither an
// execution authorization nor a destination that can be passed to a transport.
type storedOrigin struct {
	scheme string
	host   string
	port   int
}

func (v *validator) checkTarget(version Version, r Request) string {
	target, path, ok := splitEndpoint(r.URL, version, false)
	v.require(ok, "invalid case target URL")
	allowed, _, ok := splitEndpoint(r.AllowedOrigin, version, true)
	v.require(ok, "invalid case origin")
	v.require(target == allowed, "case target does not match declared origin")
	return path
}

// splitEndpoint validates a stored URL without resolving its host or
// rewriting its path. The returned path is used for literal v2 approval.
func splitEndpoint(raw string, version Version, originOnly bool) (storedOrigin, string, bool) {
	if raw != strings.TrimSpace(raw) {
		return storedOrigin{}, "", false
	}
	if base, fragment, found := strings.Cut(raw, "#"); found {
		if version == Version1 || fragment != "" {
			return storedOrigin{}, "", false
		}
		raw = base
	}
	if base, query, found := strings.Cut(raw, "?"); found {
		if version == Version1 || !originOnly || query != "" {
			return storedOrigin{}, "", false
		}
		raw = base
	}
	scheme, rest, _ := strings.Cut(raw, "://")
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return storedOrigin{}, "", false
	}
	authority, tail, hasPath := strings.Cut(rest, "/")
	path := ""
	if hasPath {
		path = "/" + tail
	}
	if originOnly && !isOriginPath(path) {
		return storedOrigin{}, "", false
	}
	host, rawPort, ok := storedAuthority(authority, version == Version2 && !originOnly)
	if !ok {
		return storedOrigin{}, "", false
	}
	port := 80
	if scheme == "https" {
		port = 443
	}
	if rawPort != "" {
		number, ok := storedPort(rawPort)
		if !ok || (number == 0 && version == Version1) {
			return storedOrigin{}, "", false
		}
		if number != 0 {
			port = number
		}
	}
	return storedOrigin{scheme, host, port}, path, true
}

func storedAuthority(authority string, v2Request bool) (host, port string, ok bool) {
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		userinfo := authority[:at]
		if v2Request || (userinfo != "" && userinfo != ":") {
			return "", "", false
		}
		authority = authority[at+1:]
	}

	lastClose := strings.LastIndexByte(authority, ']')
	if strings.HasPrefix(authority, "[") && lastClose >= 0 {
		literal := authority[1:lastClose]
		if v2Request {
			// The v2 request grammar checks the first closing bracket
			// and requires a colon before any port. Declared origins
			// and v1 target URLs use the outer literal instead.
			first, suffix, _ := strings.Cut(authority[1:], "]")
			if (suffix != "" && !strings.HasPrefix(suffix, ":")) || !validStoredIPv6(first) {
				return "", "", false
			}
		}
		if !validStoredIPv6(literal) {
			return "", "", false
		}
		port = strings.TrimPrefix(authority[lastClose+1:], ":")
		// The zone is part of the stored spelling. In particular, %25
		// is not decoded to %, nor is a number treated as an interface index.
		return strings.ToLower(literal), port, true
	}
	if v2Request && strings.ContainsAny(authority, "[]") {
		return "", "", false
	}
	rawHost, port, _ := strings.Cut(authority, ":")
	if rawHost == "" {
		return "", "", false
	}
	host, ok = canonicalHostname(quoteStoredASCIIHost(rawHost))
	return host, port, ok
}

func validStoredIPv6(literal string) bool {
	if !asciiHostname(literal) || strings.Count(literal, "%") > 1 {
		return false
	}
	addr, err := netip.ParseAddr(literal)
	return err == nil && addr.Is6()
}

// ASCII registered-name spellings are quoted by the released case origin
// reader; literal percent signs (including existing escapes) remain literal.
func quoteStoredASCIIHost(host string) string {
	if !asciiHostname(host) {
		return host
	}
	const punctuation = "-._~!$&'()*+,;=\"`{}%|\\"
	const hex = "0123456789abcdef"
	var key strings.Builder
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || strings.ContainsRune(punctuation, rune(c)) {
			key.WriteByte(c)
		} else {
			key.WriteByte('%')
			key.WriteByte(hex[c>>4])
			key.WriteByte(hex[c&15])
		}
	}
	return key.String()
}

// storedPort reads the bounded decimal value used for case-origin comparison.
// It accepts the released spelling rules without returning a transport port.
func storedPort(raw string) (int, bool) {
	digits := strings.TrimSpace(raw)
	negative := strings.HasPrefix(digits, "-")
	if negative || strings.HasPrefix(digits, "+") {
		digits = digits[1:]
	}
	value := 0
	afterDigit := false
	for _, r := range digits {
		if r == '_' && afterDigit {
			afterDigit = false
			continue
		}
		digit := storedDecimalDigit(r)
		if digit < 0 {
			return 0, false
		}
		value = value*10 + digit
		if value > 65535 {
			return 0, false
		}
		afterDigit = true
	}
	return value, afterDigit && (!negative || value == 0)
}

func storedDecimalDigit(r rune) int {
	i := sort.Search(len(storedDecimalStarts), func(i int) bool { return storedDecimalStarts[i]+9 >= r })
	if i == len(storedDecimalStarts) || storedDecimalStarts[i] > r {
		return -1
	}
	return int(r - storedDecimalStarts[i])
}

// HTTPX removes literal dot segments before checking the declared origin's
// path. Keep empty segments and leave escapes alone. Request paths still use
// the original bytes for their separate validation.
func isOriginPath(path string) bool {
	if path == "" || path == "/" {
		return true
	}
	segments := strings.Split(path[1:], "/")
	remaining := segments[:0]
	for _, segment := range segments {
		switch segment {
		case ".":
		case "..":
			if len(remaining) > 0 {
				remaining = remaining[:len(remaining)-1]
			}
		default:
			remaining = append(remaining, segment)
		}
	}
	return len(remaining) == 0 || len(remaining) == 1 && remaining[0] == ""
}

func bytePreservedPath(path string) bool {
	if path == "" || path[0] != '/' {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	// The released HTTP URL parser leaves these ASCII path bytes unchanged.
	const punctuation = "!$%&'()*+,-./:;=@[\\]^_|~"
	for _, c := range path {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.ContainsRune(punctuation, c):
		default:
			return false
		}
	}
	return true
}
