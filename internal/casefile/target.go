package casefile

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type origin struct {
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

// splitEndpoint validates an inert URL without resolving its host. Parse the
// authority separately: the released v1 reader accepts paths that would be
// rejected or rewritten by a full net/url parse.
func splitEndpoint(raw string, version Version, originOnly bool) (origin, string, bool) {
	if raw != strings.TrimSpace(raw) {
		return origin{}, "", false
	}
	if base, fragment, found := strings.Cut(raw, "#"); found {
		if version == Version1 || fragment != "" {
			return origin{}, "", false
		}
		raw = base
	}
	if base, query, found := strings.Cut(raw, "?"); found {
		if version == Version1 || !originOnly || query != "" {
			return origin{}, "", false
		}
		raw = base
	}
	scheme, rest, _ := strings.Cut(raw, "://")
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return origin{}, "", false
	}
	authority, tail, hasPath := strings.Cut(rest, "/")
	path := ""
	if hasPath {
		path = "/" + tail
	}
	if originOnly && !isOriginPath(path) {
		return origin{}, "", false
	}
	hostStart := strings.LastIndexByte(authority, '@') + 1
	rawHost := authority[hostStart:]
	parseAuthority := authority
	bracketed := strings.HasPrefix(rawHost, "[")
	if !bracketed {
		rawHost, _, _ = strings.Cut(rawHost, ":")
		if asciiHostname(rawHost) && strings.Contains(rawHost, "%") {
			// Let net/url validate the authority without interpreting the
			// original hostname's literal percent spelling as an escape.
			parseAuthority = authority[:hostStart] + strings.ReplaceAll(rawHost, "%", "%25") + authority[hostStart+len(rawHost):]
		}
	}
	parsed, err := url.Parse(scheme + "://" + parseAuthority)
	if err != nil || parsed.Hostname() == "" {
		return origin{}, "", false
	}
	if parsed.User != nil {
		password, _ := parsed.User.Password()
		if (version == Version2 && !originOnly) || parsed.User.Username() != "" || password != "" {
			return origin{}, "", false
		}
	}
	var host string
	if bracketed {
		literal, _, ok := strings.Cut(rawHost[1:], "]")
		addr, err := netip.ParseAddr(literal)
		if !ok || err != nil || !addr.Is6() || !asciiHostname(literal) || strings.Count(literal, "%") > 1 {
			return origin{}, "", false
		}
		host = strings.ToLower(literal)
	} else {
		var ok bool
		host, ok = canonicalHostname(rawHost)
		if !ok {
			return origin{}, "", false
		}
	}
	port := 80
	if scheme == "https" {
		port = 443
	}
	if text := parsed.Port(); text != "" {
		number, err := strconv.Atoi(text)
		if err != nil || number < 0 || number > 65535 || (number == 0 && version == Version1) {
			return origin{}, "", false
		}
		if number != 0 {
			port = number
		}
	}
	return origin{scheme, host, port}, path, true
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
