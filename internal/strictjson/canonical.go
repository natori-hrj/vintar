package strictjson

import (
	"bytes"
	"encoding/json"
	"io"
	"math/bits"
	"slices"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize parses data using Parse's input limits and emits compact ASCII
// JSON with keys in Unicode code point order and floats as in CPython repr.
func Canonicalize(data []byte) ([]byte, error) {
	var dst bytes.Buffer
	if err := CanonicalizeTo(&dst, data); err != nil {
		return nil, err
	}
	return dst.Bytes(), nil
}

// CanonicalizeTo uses the same input limits and representation as Canonicalize.
func CanonicalizeTo(dst io.Writer, data []byte) error {
	value, err := Parse(data)
	if err != nil {
		return err
	}
	return NewEncoder(dst, nil).Value(value)
}

// Encoder emits canonical JSON from already validated values, without applying
// input parser limits to the representation. A caller can stream a structure
// with Object and Array instead of assembling its expanded value in memory.
// An optional charge function accounts for traversal and comparisons before
// doing work. After an error the caller must discard the partial result.
type Encoder struct {
	dst    io.Writer
	charge func(int) error
	err    error
	text   [4096]byte
	scalar [32]byte
}

func NewEncoder(dst io.Writer, charge func(int) error) *Encoder {
	return &Encoder{dst: dst, charge: charge}
}

func (e *Encoder) spend(n int) error {
	if e.err == nil && e.charge != nil {
		e.err = e.charge(n)
	}
	return e.err
}

func (e *Encoder) write(p []byte) {
	if e.err != nil {
		return
	}
	n, err := e.dst.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	e.err = err
}

func (e *Encoder) literal(s string) {
	if e.err != nil {
		return
	}
	n, err := io.WriteString(e.dst, s)
	if err == nil && n != len(s) {
		err = io.ErrShortWrite
	}
	e.err = err
}

func (e *Encoder) quoted(text string) {
	// Fast path ordinary ASCII runs, and keep all escape output bounded.
	dst := append(e.text[:0], '"')
	for len(text) != 0 && e.err == nil {
		if len(dst) >= len(e.text)-12 {
			e.write(dst)
			dst = e.text[:0]
		}
		dst, text = appendStringPart(dst, text, min(len(text), 256, len(e.text)-len(dst)))
	}
	e.write(append(dst, '"'))
}

func (e *Encoder) Value(value any) error {
	switch v := value.(type) {
	case []any:
		return e.Array(len(v), func(i int) error { return e.Value(v[i]) })
	case map[string]any:
		return e.Map(v, func(key string) error { return e.Value(v[key]) })
	case SurrogateObject:
		// Canonical literals cannot be sorted directly: escapes change their
		// order. Use the parser's private code point representation instead.
		keys := make([]string, 0, len(v.UTF8)+len(v.LoneSurrogates))
		special := make(map[string]any, len(v.LoneSurrogates))
		for key := range v.UTF8 {
			keys = append(keys, key)
		}
		for key, value := range v.LoneSurrogates {
			p := parser{data: []byte(key.literal)}
			text, _, _ := p.string()
			keys = append(keys, text)
			special[text] = value
		}
		return e.object(keys, func(key string) error {
			child, ok := v.UTF8[key]
			if !ok {
				child = special[key]
			}
			return e.Value(child)
		})
	}
	if err := e.spend(1); err != nil {
		return err
	}
	switch v := value.(type) {
	case nil:
		e.literal("null")
	case bool:
		e.write(strconv.AppendBool(e.scalar[:0], v))
	case json.Number: // Parse stores normalized decimal integers in this type.
		e.literal(string(v))
	case float64:
		e.write(appendFloat(e.scalar[:0], v))
	case string:
		e.quoted(v)
	case SurrogateString:
		e.literal(v.literal)
	default:
		return errSyntax
	}
	return e.err
}

func (e *Encoder) Array(n int, item func(int) error) error {
	if err := e.spend(1); err != nil {
		return err
	}
	e.literal("[")
	for i := 0; i < n && e.err == nil; i++ {
		if i != 0 {
			e.literal(",")
		}
		if err := item(i); err != nil {
			return err
		}
	}
	e.literal("]")
	return e.err
}

// Map visits keys in canonical order. A nil include predicate includes all keys.
func (e *Encoder) Map(value map[string]any, member func(string) error) error {
	return e.FilteredMap(value, nil, member)
}

func (e *Encoder) FilteredMap(value map[string]any, include func(string) bool, member func(string) error) error {
	if err := e.spend(len(value)); err != nil {
		return err
	}
	keys := make([]string, 0, len(value))
	for key := range value {
		if include == nil || include(key) {
			keys = append(keys, key)
		}
	}
	return e.object(keys, member)
}

// Object emits members from a caller-supplied set of keys in canonical order.
// It sorts keys in place.
func (e *Encoder) Object(keys []string, member func(string) error) error {
	return e.object(keys, member)
}

func (e *Encoder) object(keys []string, member func(string) error) error {
	if err := e.spend(1); err != nil {
		return err
	}
	if e.charge != nil && len(keys) > 1 {
		longest, second := 0, 0
		for _, key := range keys {
			if n := len(key); n >= longest {
				longest, second = n, longest
			} else {
				second = max(second, n)
			}
		}
		// Deterministic conservative comparison cost, independent of the
		// map's iteration order. Distinct keys cannot compare more than
		// the second-longest key's bytes. The precharge is chunked by key
		// to keep it in range on 32-bit systems.
		perKey := 8 * bits.Len(uint(len(keys))) * (1 + second)
		for range keys {
			if err := e.spend(perKey); err != nil {
				return err
			}
		}
	}
	slices.Sort(keys)
	e.literal("{")
	for i, key := range keys {
		if e.spend(1+len(key)) != nil { // key lookup and punctuation
			return e.err
		}
		if i != 0 {
			e.literal(",")
		}
		e.quoted(key)
		e.literal(":")
		if e.err != nil {
			return e.err
		}
		if err := member(key); err != nil {
			return err
		}
	}
	e.literal("}")
	return e.err
}

func appendFloat(dst []byte, f float64) []byte {
	// Apply Python's fixed-format cutovers to the rounded, shortest digits.
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
	dst := []byte{'"'}
	for len(text) != 0 {
		dst, text = appendStringPart(dst, text, len(text))
	}
	return SurrogateString{literal: string(append(dst, '"'))}
}

// Append an unescaped ASCII run, or one complete escape sequence.
func appendStringPart(dst []byte, text string, limit int) ([]byte, string) {
	i := 0
	for i < limit {
		c := text[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			break
		}
		i++
	}
	if i != 0 {
		return append(dst, text[:i]...), text[i:]
	}
	c, size := utf8.DecodeRuneInString(text)
	if c == utf8.RuneError && size == 1 && len(text) >= 3 {
		// Parser-private three-byte representation of a lone surrogate.
		c = rune(text[0]&0xf)<<12 | rune(text[1]&0x3f)<<6 | rune(text[2]&0x3f)
		size = 3
	}
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
		if c <= 0xffff {
			dst = appendCodeUnit(dst, c)
		} else {
			high, low := utf16.EncodeRune(c)
			dst = appendCodeUnit(appendCodeUnit(dst, high), low)
		}
	}
	return dst, text[size:]
}

func appendCodeUnit(dst []byte, c rune) []byte {
	const hex = "0123456789abcdef"
	return append(dst, '\\', 'u', hex[c>>12], hex[c>>8&0xf], hex[c>>4&0xf], hex[c&0xf])
}
