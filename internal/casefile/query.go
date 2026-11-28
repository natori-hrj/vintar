package casefile

import "strings"

type QueryPair struct {
	Name  string
	Value string
}

// EncodeQuery percent-encodes names and values in their supplied order, using
// RFC 3986 unreserved bytes and retaining repetitions and empty values.
func EncodeQuery(pairs []QueryPair) string {
	var out strings.Builder
	for i, pair := range pairs {
		if i != 0 {
			out.WriteByte('&')
		}
		writeQueryComponent(&out, pair.Name)
		out.WriteByte('=')
		writeQueryComponent(&out, pair.Value)
	}
	return out.String()
}

func writeQueryComponent(out *strings.Builder, s string) {
	const hex = "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			out.WriteByte(c)
		default:
			out.WriteByte('%')
			out.WriteByte(hex[c>>4])
			out.WriteByte(hex[c&15])
		}
	}
}
