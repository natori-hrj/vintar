package strictjson

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize parses data using Parse's limits, then emits compact ASCII JSON,
// sorting keys by Unicode code point and formatting floats as in CPython repr.
// The output can exceed the input limit because non-ASCII characters expand.
func Canonicalize(data []byte) ([]byte, error) {
	value, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return appendValue(nil, value), nil
}

func appendValue(dst []byte, value any) []byte {
	switch v := value.(type) {
	case nil:
		return append(dst, "null"...)
	case bool:
		return strconv.AppendBool(dst, v)
	case json.Number:
		return append(dst, v...)
	case float64:
		return appendFloat(dst, v)
	case string:
		return appendString(dst, v)
	case SurrogateString:
		return append(dst, v.literal...)
	case []any:
		dst = append(dst, '[')
		for i, child := range v {
			if i != 0 {
				dst = append(dst, ',')
			}
			dst = appendValue(dst, child)
		}
		return append(dst, ']')
	case map[string]any:
		return appendObject(dst, v)
	case SurrogateObject:
		return appendSurrogateObject(dst, v)
	default:
		panic("strictjson: unexpected internal value type")
	}
}

func appendObject(dst []byte, obj map[string]any) []byte {
	keys := make([]string, 0, len(obj))
	for key := range obj {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	dst = append(dst, '{')
	for i, key := range keys {
		if i != 0 {
			dst = append(dst, ',')
		}
		dst = appendString(dst, key)
		dst = appendValue(append(dst, ':'), obj[key])
	}
	return append(dst, '}')
}

func appendSurrogateObject(dst []byte, obj SurrogateObject) []byte {
	// Use the private code point encoding for ordering. Canonical literals
	// cannot be sorted directly: the escapes change their relative order.
	keys := make([]string, 0, len(obj.UTF8)+len(obj.LoneSurrogates))
	special := make(map[string]any, len(obj.LoneSurrogates))
	for key := range obj.UTF8 {
		keys = append(keys, key)
	}
	for key, value := range obj.LoneSurrogates {
		p := parser{data: []byte(key.literal)}
		text, _, _ := p.string() // literal was created by appendString
		keys = append(keys, text)
		special[text] = value
	}
	slices.Sort(keys)
	dst = append(dst, '{')
	for i, key := range keys {
		if i != 0 {
			dst = append(dst, ',')
		}
		dst = appendString(dst, key)
		value, ok := obj.UTF8[key]
		if !ok {
			value = special[key]
		}
		dst = appendValue(append(dst, ':'), value)
	}
	return append(dst, '}')
}

func appendFloat(dst []byte, f float64) []byte {
	// strconv supplies the shortest round-tripping digits and a signed
	// exponent of at least two digits. Apply Python's fixed-format cutovers
	// to that shortest scientific representation (including after rounding).
	var scratch [32]byte
	scientific := strconv.AppendFloat(scratch[:0], f, 'e', -1, 64)
	e := bytes.IndexByte(scientific, 'e')
	exp, _ := strconv.Atoi(string(scientific[e+1:]))
	if exp < -4 || exp >= 16 {
		return append(dst, scientific...)
	}
	start := len(dst)
	dst = strconv.AppendFloat(dst, f, 'f', -1, 64)
	if bytes.IndexByte(dst[start:], '.') == -1 {
		dst = append(dst, '.', '0')
	}
	return dst
}

func surrogateString(text string) SurrogateString {
	return SurrogateString{literal: string(appendString(nil, text))}
}

func appendString(dst []byte, text string) []byte {
	dst = append(dst, '"')
	for len(text) != 0 {
		c, size := utf8.DecodeRuneInString(text)
		if c == utf8.RuneError && size == 1 {
			// Only private three-byte encodings of lone surrogates can
			// be invalid UTF-8 here. Escape the original code unit.
			c = rune(text[0]&0xf)<<12 | rune(text[1]&0x3f)<<6 | rune(text[2]&0x3f)
			size = 3
		}
		text = text[size:]
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', byte(c))
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			switch {
			case c >= 0x20 && c <= 0x7e:
				dst = append(dst, byte(c))
			case c <= 0xffff:
				dst = appendCodeUnit(dst, c)
			default:
				high, low := utf16.EncodeRune(c)
				dst = appendCodeUnit(appendCodeUnit(dst, high), low)
			}
		}
	}
	return append(dst, '"')
}

func appendCodeUnit(dst []byte, c rune) []byte {
	const hex = "0123456789abcdef"
	return append(dst, '\\', 'u', hex[c>>12], hex[c>>8&0xf], hex[c>>4&0xf], hex[c&0xf])
}
