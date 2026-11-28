package httpio

import (
	"net/url"
	"strings"
)

func normalizePublicPath(target *url.URL) {
	raw := target.EscapedPath()
	if !strings.Contains(raw, ".") {
		return
	}
	var segments []string
	for segment := range strings.SplitSeq(strings.TrimPrefix(raw, "/"), "/") {
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
	normalized := "/" + strings.Join(segments, "/")
	if normalized != raw {
		// EscapedPath and the literal separators guarantee valid escapes.
		target.Path, _ = url.PathUnescape(normalized)
		target.RawPath = normalized
	}
}

func escapePublicQuery(raw string) string {
	const hex = "0123456789ABCDEF"
	var escaped strings.Builder
	for i := range len(raw) {
		c := raw[i]
		switch {
		case c >= 0x7f || strings.IndexByte(" \"#<>", c) >= 0:
			escaped.WriteByte('%')
			escaped.WriteByte(hex[c>>4])
			escaped.WriteByte(hex[c&15])
		default:
			escaped.WriteByte(c)
		}
	}
	return escaped.String()
}
