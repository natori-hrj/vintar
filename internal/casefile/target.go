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
	if originOnly && path != "" && path != "/" {
		return origin{}, "", false
	}
	parsed, err := url.Parse(scheme + "://" + authority)
	if err != nil || parsed.Hostname() == "" {
		return origin{}, "", false
	}
	if parsed.User != nil {
		password, _ := parsed.User.Password()
		if (version == Version2 && !originOnly) || parsed.User.Username() != "" || password != "" {
			return origin{}, "", false
		}
	}
	rawHost := authority[strings.LastIndexByte(authority, '@')+1:]
	var host string
	if strings.HasPrefix(rawHost, "[") {
		literal, _, ok := strings.Cut(rawHost[1:], "]")
		addr, err := netip.ParseAddr(literal)
		if !ok || err != nil || !addr.Is6() || !asciiHostname(literal) || strings.Count(literal, "%") > 1 {
			return origin{}, "", false
		}
		host = strings.ToLower(literal)
	} else {
		// net/url unescapes non-ASCII octets in hosts. HTTPX leaves
		// percent-escaped ASCII host spellings as literal wire names.
		rawHost, _, _ = strings.Cut(rawHost, ":")
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
