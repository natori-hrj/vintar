package httpio

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	publicIDNA     = idna.New(idna.ValidateForRegistration())
	labelSeparator = strings.NewReplacer("\u3002", ".", "\uff0e", ".", "\uff61", ".")
)

func publicTargetParts(raw string) (authority, path string) {
	_, rest, _ := strings.Cut(raw, "://")
	if end := strings.IndexAny(rest, "?#"); end >= 0 {
		rest = rest[:end]
	}
	if start := strings.IndexByte(rest, '/'); start >= 0 {
		return rest[:start], rest[start:]
	}
	return rest, ""
}

func normalizePublicHost(target *url.URL, authority string) error {
	host := target.Hostname()
	// Do not reinterpret an escaped scope as an interface selection.
	if strings.Contains(host, "%") {
		return errors.New("scoped HTTP destinations are unsupported")
	}
	if strings.Contains(authority, "%") {
		return errors.New("escaped HTTP host is unsupported")
	}
	// These Unicode characters delimit labels. Do not apply width or
	// compatibility mappings to the labels themselves.
	asciiHost := labelSeparator.Replace(host)
	if strings.ContainsFunc(asciiHost, func(r rune) bool { return r > 0x7f }) {
		var err error
		asciiHost, err = publicIDNA.ToASCII(cases.Lower(language.Und).String(asciiHost))
		if err != nil {
			return errors.New("invalid internationalized HTTP host")
		}
	}
	if dottedDecimal(asciiHost) {
		if _, err := netip.ParseAddr(asciiHost); err != nil {
			return errors.New("invalid IPv4 HTTP host")
		}
	}
	if asciiHost != host {
		if port := target.Port(); port != "" {
			target.Host = net.JoinHostPort(asciiHost, port)
		} else {
			target.Host = asciiHost
		}
	}
	return nil
}

func dottedDecimal(host string) bool {
	if strings.Count(host, ".") != 3 {
		return false
	}
	for part := range strings.SplitSeq(host, ".") {
		if part == "" || strings.ContainsFunc(part, func(r rune) bool { return r < '0' || r > '9' }) {
			return false
		}
	}
	return true
}

func normalizePublicPath(target *url.URL, raw string) {
	if raw == "" {
		return
	}
	if strings.Contains(raw, ".") {
		var segments []string
		for segment := range strings.SplitSeq(raw[1:], "/") {
			switch segment {
			case ".":
				continue
			case "..":
				if len(segments) > 0 {
					segments = segments[:len(segments)-1]
				}
			default:
				segments = append(segments, segment)
			}
		}
		raw = "/" + strings.Join(segments, "/")
	}
	// NewRequest has already validated existing escapes. Escape only literal
	// bytes here so mixed raw and escaped input never loses escape spelling.
	encoded := escapePublicComponent(raw, func(c byte) bool {
		return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
			strings.IndexByte("/-._~!$&'()*+,;=:@%[]", c) >= 0
	})
	target.Path, _ = url.PathUnescape(encoded)
	target.RawPath = encoded
}

func escapePublicQuery(raw string) string {
	return escapePublicComponent(raw, func(c byte) bool {
		return c < 0x7f && strings.IndexByte(" \"#<>", c) < 0
	})
}

func escapePublicComponent(raw string, safe func(byte) bool) string {
	const hex = "0123456789ABCDEF"
	var escaped strings.Builder
	for i := range len(raw) {
		c := raw[i]
		if !safe(c) {
			escaped.WriteByte('%')
			escaped.WriteByte(hex[c>>4])
			escaped.WriteByte(hex[c&15])
		} else {
			escaped.WriteByte(c)
		}
	}
	return escaped.String()
}
