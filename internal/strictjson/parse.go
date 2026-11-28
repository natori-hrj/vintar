// Package strictjson parses bounded JSON and produces v0.6.0-compatible
// canonical bytes without performing file or network I/O.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxBytes         = 1 << 20
	maxDepth         = 48
	maxIntegerDigits = 4300
)

// Diagnostics never include input bytes, including in wrapped errors.
var (
	errSize      = errors.New("JSON input exceeds 1048576 bytes. Use a smaller JSON document.")
	errUTF8      = errors.New("JSON input is not valid UTF-8. Encode the document as UTF-8.")
	errSyntax    = errors.New("JSON input is invalid. Use one bounded JSON document with no trailing data.")
	errDepth     = errors.New("JSON nesting exceeds 48. Use a flatter JSON document.")
	errDuplicate = errors.New("JSON contains duplicate object member names. Use each member name once.")
	errInteger   = errors.New("JSON integer is too long. Use a string field for large identifiers.")
	errFinite    = errors.New("JSON number must be finite. Use an integer or a finite JSON number.")
	errFloat     = errors.New("JSON number is outside the finite float range. Use an integer or a finite float within Python's supported range.")
)

// SurrogateString represents a decoded string containing at least one lone
// surrogate. It is comparable and is distinct from all ordinary Go strings.
type SurrogateString struct {
	literal string
}

// JSON returns the value as a quoted, ASCII-escaped JSON string literal.
// The zero SurrogateString, which Parse never returns, yields an empty string
// (no JSON token).
func (s SurrogateString) JSON() string { return s.literal }

// SurrogateObject represents an object with at least one lone-surrogate key.
// UTF8 holds its ordinary string keys; LoneSurrogates holds all other keys.
type SurrogateObject struct {
	UTF8           map[string]any
	LoneSurrogates map[SurrogateString]any
}

// Parse reads one strict UTF-8 JSON value, allowing at most 1 MiB of input, a
// value depth of 48 (root depth 0), and 4300 digits per integer excluding sign.
// It returns nil for null, bool, string, json.Number for exact decimal integers
// (normalizing -0 to 0), float64 for finite floats (preserving signed zero),
// []any for arrays, and map[string]any for objects with UTF-8 keys. Strings
// with escaped lone surrogates are SurrogateString values; objects with such
// keys are SurrogateObject values. Use Canonicalize rather than Go's default
// JSON serialization for the release's output format.
func Parse(data []byte) (any, error) {
	if len(data) > maxBytes {
		return nil, errSize
	}
	if !utf8.Valid(data) {
		return nil, errUTF8
	}
	p := parser{data: data}
	value, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(data) {
		return nil, errSyntax
	}
	return value, nil
}

type parser struct {
	data []byte
	i    int
}

func (p *parser) peek() byte {
	if p.i == len(p.data) {
		return 0
	}
	return p.data[p.i]
}

func (p *parser) space() {
	for {
		switch p.peek() {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) take(b byte) bool {
	if p.peek() != b {
		return false
	}
	p.i++
	return true
}

func (p *parser) literal(s string) bool {
	if !bytes.HasPrefix(p.data[p.i:], []byte(s)) {
		return false
	}
	p.i += len(s)
	return true
}

func (p *parser) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, errDepth
	}
	p.space()
	switch p.peek() {
	case '{':
		return p.object(depth)
	case '[':
		return p.array(depth)
	case '"':
		text, lone, err := p.string()
		if err != nil {
			return nil, err
		}
		if lone {
			return surrogateString(text), nil
		}
		return text, nil
	case 'n':
		if p.literal("null") {
			return nil, nil
		}
	case 't':
		if p.literal("true") {
			return true, nil
		}
	case 'f':
		if p.literal("false") {
			return false, nil
		}
	case 'N', 'I', '-':
		if p.literal("NaN") || p.literal("Infinity") || p.literal("-Infinity") {
			return nil, errFinite
		}
		if p.peek() == '-' {
			return p.number()
		}
	default:
		if digit(p.peek()) {
			return p.number()
		}
	}
	return nil, errSyntax
}

func (p *parser) object(depth int) (any, error) {
	p.i++ // {
	keys := make(map[string]any)
	var special map[SurrogateString]any
	p.space()
	if p.take('}') {
		return keys, nil
	}
	for {
		if p.peek() != '"' {
			return nil, errSyntax
		}
		text, lone, err := p.string()
		if err != nil {
			return nil, err
		}
		var key SurrogateString
		if lone {
			key = surrogateString(text)
			if _, exists := special[key]; exists {
				return nil, errDuplicate
			}
		} else if _, exists := keys[text]; exists {
			return nil, errDuplicate
		}
		p.space()
		if !p.take(':') {
			return nil, errSyntax
		}
		child, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		if lone {
			if special == nil {
				special = make(map[SurrogateString]any)
			}
			special[key] = child
		} else {
			keys[text] = child
		}
		p.space()
		if p.take('}') {
			if special != nil {
				return SurrogateObject{UTF8: keys, LoneSurrogates: special}, nil
			}
			return keys, nil
		}
		if !p.take(',') {
			return nil, errSyntax
		}
		p.space()
	}
}

func (p *parser) array(depth int) ([]any, error) {
	p.i++ // [
	children := []any{}
	p.space()
	if p.take(']') {
		return children, nil
	}
	for {
		child, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
		p.space()
		if p.take(']') {
			return children, nil
		}
		if !p.take(',') {
			return nil, errSyntax
		}
	}
}

// string returns UTF-8 extended privately to encode lone surrogates. This
// gives one byte representation per code point sequence and preserves code
// point order under byte comparison. Such extended bytes never leave the
// package: public lone-surrogate strings store their quoted ASCII literal.
func (p *parser) string() (text string, lone bool, err error) {
	p.i++ // opening quote
	start := p.i
	var decoded []byte
	for p.i < len(p.data) {
		switch b := p.data[p.i]; b {
		case '"':
			raw := p.data[start:p.i]
			p.i++
			if decoded == nil {
				return string(raw), false, nil
			}
			return string(append(decoded, raw...)), lone, nil
		case '\\':
			decoded = append(decoded, p.data[start:p.i]...)
			p.i++
			escape := p.peek()
			switch escape {
			case '"', '\\', '/':
				decoded = append(decoded, escape)
				p.i++
			case 'b', 'f', 'n', 'r', 't':
				decoded = append(decoded, mapEscape(escape))
				p.i++
			case 'u':
				p.i++
				cp, ok := p.codeUnit()
				if !ok {
					return "", false, errSyntax
				}
				if 0xd800 <= cp && cp <= 0xdbff && p.i+2 <= len(p.data) &&
					p.data[p.i] == '\\' && p.data[p.i+1] == 'u' {
					next := p.i
					p.i += 2
					low, ok := p.codeUnit()
					if !ok {
						return "", false, errSyntax
					}
					if 0xdc00 <= low && low <= 0xdfff {
						cp = utf16.DecodeRune(cp, low)
					} else {
						p.i = next
					}
				}
				if utf16.IsSurrogate(cp) {
					lone = true
					decoded = append(decoded, byte(0xe0|cp>>12), byte(0x80|(cp>>6)&0x3f), byte(0x80|cp&0x3f))
				} else {
					decoded = utf8.AppendRune(decoded, cp)
				}
			default:
				return "", false, errSyntax
			}
			start = p.i
		default:
			if b < 0x20 {
				return "", false, errSyntax
			}
			p.i++
		}
	}
	return "", false, errSyntax
}

func mapEscape(b byte) byte {
	switch b {
	case 'b':
		return '\b'
	case 'f':
		return '\f'
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	default: // 't'
		return '\t'
	}
}

func (p *parser) codeUnit() (rune, bool) {
	if len(p.data)-p.i < 4 {
		return 0, false
	}
	var cp rune
	for _, b := range p.data[p.i : p.i+4] {
		cp <<= 4
		switch {
		case digit(b):
			cp |= rune(b - '0')
		case 'a' <= b && b <= 'f':
			cp |= rune(b-'a') + 10
		case 'A' <= b && b <= 'F':
			cp |= rune(b-'A') + 10
		default:
			return 0, false
		}
	}
	p.i += 4
	return cp, true
}

func digit(b byte) bool { return '0' <= b && b <= '9' }

func (p *parser) digits() {
	for digit(p.peek()) {
		p.i++
	}
}

func (p *parser) number() (any, error) {
	start := p.i
	negative := p.take('-')
	digitsStart := p.i
	if p.take('0') {
		if digit(p.peek()) {
			return nil, errSyntax
		}
	} else {
		p.digits()
		if p.i == digitsStart {
			return nil, errSyntax
		}
	}
	whole := p.data[digitsStart:p.i]
	isFloat := p.take('.')
	var fraction, exponent []byte
	if isFloat {
		start := p.i
		p.digits()
		if p.i == start {
			return nil, errSyntax
		}
		fraction = p.data[start:p.i]
	}
	if p.take('e') || p.take('E') {
		isFloat = true
		expStart := p.i
		if !p.take('+') {
			p.take('-')
		}
		digitsStart := p.i
		p.digits()
		if p.i == digitsStart {
			return nil, errSyntax
		}
		exponent = p.data[expStart:p.i]
	}
	if !isFloat {
		if len(whole) > maxIntegerDigits {
			return nil, errInteger
		}
		if whole[0] == '0' {
			return json.Number("0"), nil
		}
		return json.Number(p.data[start:p.i]), nil
	}
	// Ordinary tokens need no normalization. For long tokens, adjust the
	// exponent before strconv can saturate it independently of the mantissa.
	if p.i-start <= 256 {
		return finiteFloat(p.data[start:p.i])
	}
	return longFloat(whole, fraction, exponent, negative)
}

func finiteFloat(source []byte) (float64, error) {
	f, err := strconv.ParseFloat(string(source), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, errFloat
	}
	return f, nil
}

func longFloat(whole, fraction, exponent []byte, negative bool) (float64, error) {
	power := len(whole) - 1
	if whole[0] == '0' {
		for len(fraction) != 0 && fraction[0] == '0' {
			power--
			fraction = fraction[1:]
		}
		if len(fraction) == 0 {
			return floatZero(negative), nil
		}
		power--
		whole, fraction = fraction, nil
	}
	power += exponentValue(exponent)
	switch {
	case power > 308:
		return 0, errFloat
	case power < -324:
		return floatZero(negative), nil
	}

	// Leave the significant digits intact for correct rounding at a binary64
	// midpoint, but place the decimal point after the first nonzero digit.
	normalized := make([]byte, 0, len(whole)+len(fraction)+8)
	if negative {
		normalized = append(normalized, '-')
	}
	normalized = append(normalized, whole[0])
	if len(whole) > 1 || len(fraction) != 0 {
		normalized = append(normalized, '.')
		normalized = append(normalized, whole[1:]...)
		normalized = append(normalized, fraction...)
	}
	normalized = strconv.AppendInt(append(normalized, 'e'), int64(power), 10)
	return finiteFloat(normalized)
}

func exponentValue(exponent []byte) int {
	if len(exponent) == 0 {
		return 0
	}
	negative := exponent[0] == '-'
	if negative || exponent[0] == '+' {
		exponent = exponent[1:]
	}
	value := 0
	for _, b := range exponent {
		value = value*10 + int(b-'0')
		// Beyond this, the mantissa (at most maxBytes) cannot cancel
		// enough of the exponent to produce a finite nonzero binary64.
		if value > 2*maxBytes {
			break
		}
	}
	if negative {
		return -value
	}
	return value
}

func floatZero(negative bool) float64 {
	if negative {
		return math.Copysign(0, -1)
	}
	return 0
}
