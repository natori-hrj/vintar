package execution

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Origin is a comparable HTTP(S) origin. Its zero value is not a valid origin.
// Use ParseTrustedOrigin to obtain one; parsing alone does not make it trusted.
type Origin struct {
	scheme string
	host   string
	port   uint16
}

// ParseTrustedOrigin parses an origin with no path other than an optional "/".
// It accepts ASCII DNS-style names, strict IPv4 literals, and bracketed IPv6
// literals. Host identity is lexical after ASCII lowercasing: a trailing DNS
// dot and different spellings of an IPv6 address are not collapsed.
// Signed ports, Unicode/IDN names (including A-labels), and zones are unsupported.
func ParseTrustedOrigin(raw string) (Origin, error) {
	for i := 0; i < len(raw); i++ {
		if raw[i] < '!' || raw[i] > '~' {
			return Origin{}, errors.New("origin must use printable ASCII without spaces")
		}
	}
	scheme, authority, ok := strings.Cut(raw, "://")
	scheme = strings.ToLower(scheme)
	if !ok || scheme != "http" && scheme != "https" {
		return Origin{}, errors.New("origin scheme must be HTTP or HTTPS")
	}
	authority = strings.TrimSuffix(authority, "/")
	host, portText, explicitPort, ok := splitOriginAuthority(authority)
	if !ok {
		return Origin{}, errors.New("invalid origin authority")
	}
	port := defaultOriginPort(scheme)
	if explicitPort {
		if !asciiDigits(portText) {
			return Origin{}, errors.New("origin port must be unsigned ASCII decimal")
		}
		n, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || n == 0 {
			return Origin{}, errors.New("origin port must be in 1..65535")
		}
		port = uint16(n)
	}
	return Origin{scheme: scheme, host: strings.ToLower(host), port: port}, nil
}

func splitOriginAuthority(authority string) (host, port string, explicitPort, ok bool) {
	if strings.HasPrefix(authority, "[") {
		host, suffix, found := strings.Cut(authority[1:], "]")
		if !found || strings.Contains(host, "%") {
			return "", "", false, false
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() {
			return "", "", false, false
		}
		if suffix == "" {
			return host, "", false, true
		}
		port, found := strings.CutPrefix(suffix, ":")
		return host, port, true, found
	}
	host, port, explicitPort = strings.Cut(authority, ":")
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is4() {
		return host, port, explicitPort, true
	}
	return host, port, explicitPort, validOriginRegName(strings.ToLower(host))
}

func validOriginRegName(host string) bool {
	name := strings.TrimSuffix(host, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	last := labels[len(labels)-1]
	// Don't accept spellings some URL consumers interpret as nonstandard IPv4.
	if asciiDigits(last) || strings.HasPrefix(last, "0x") && asciiHex(last[2:]) {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' ||
			strings.HasPrefix(label, "xn--") {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func asciiDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func asciiHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func defaultOriginPort(scheme string) uint16 {
	if scheme == "https" {
		return 443
	}
	return 80
}

// RebindApprovedPath constructs a URL only if target exactly matches an entry
// in the independently trusted allowed list. The caller is responsible for
// prior approval of the literal absolute path. The returned URL preserves
// that path's exact bytes, including escape spelling. Authority-like prefixes,
// backslashes, controls, and dot segments are rejected even after one path
// unescape. This function does not resolve origins, infer approvals, or make
// any claims about server-side path interpretation.
func RebindApprovedPath(target Origin, allowed []Origin, approvedPath string) (string, error) {
	if target == (Origin{}) {
		return "", errors.New("target origin must be parsed")
	}
	found := false
	for _, origin := range allowed {
		if target == origin {
			found = true
			break
		}
	}
	if !found {
		return "", errors.New("target origin is not allowed")
	}
	host := target.host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if target.port != defaultOriginPort(target.scheme) {
		host += ":" + strconv.FormatUint(uint64(target.port), 10)
	}
	base := target.scheme + "://" + host
	if parsed, err := ParseTrustedOrigin(base); err != nil || parsed != target {
		return "", errors.New("target origin must be parsed")
	}

	if !strings.HasPrefix(approvedPath, "/") || strings.ContainsAny(approvedPath, "?#") {
		return "", errors.New("approved path must be absolute with no query or fragment")
	}
	decoded, err := url.PathUnescape(approvedPath)
	if err != nil || strings.HasPrefix(decoded, "//") || strings.Contains(decoded, "\\") {
		return "", errors.New("invalid approved path")
	}
	for i := 0; i < len(decoded); i++ {
		if decoded[i] < ' ' || decoded[i] == 0x7f {
			return "", errors.New("approved path contains a control byte")
		}
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return "", errors.New("approved path contains a dot segment")
		}
	}
	pathURL := url.URL{Path: decoded, RawPath: approvedPath}
	if pathURL.EscapedPath() != approvedPath {
		return "", errors.New("approved path does not round trip without escaping")
	}

	return base + approvedPath, nil
}
