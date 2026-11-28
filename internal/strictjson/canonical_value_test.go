package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestCanonicalizeValueMatchesCanonicalize(t *testing.T) {
	for _, input := range []string{
		`[null,true,false,1,1.0,-0,-0.0,-1e-9999,5e-324,1.7976931348623157e308,1e-5,1e-4,1e15,1e16,9007199254740993]`,
		"{\"界\":\"<>&\u2028\u2029\",\"a\":[\"\\u0001\\n\",{\"𝄞\":\"é\"},[],{}]}",
		`{"𐀀":1,"\ue000":2,"\udfff":3,"\ud800":{"\ud801":"\ud802"},"�":5,"a":6}`,
		`-` + strings.Repeat("9", maxIntegerDigits),
	} {
		want, err := Canonicalize([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		v, err := Parse([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		got, err := CanonicalizeValue(v)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("assembled encoding differs: got %q, want %q, err=%v", got, want, err)
		}
	}
}

func TestCanonicalizeValueBudget(t *testing.T) {
	// Charge the quotes and decoded text, not its sixfold ASCII expansion.
	const quotes = 2
	v := strings.Repeat("\x01", maxBytes-quotes)
	got, err := CanonicalizeValue(v)
	if err != nil || len(got) != quotes+6*len(v) || cap(got) > 6*maxBytes {
		t.Fatalf("at byte budget: length=%d, capacity=%d, err=%v", len(got), cap(got), err)
	}
	if _, err := Canonicalize(got); !errors.Is(err, errSize) {
		t.Fatalf("byte input limit changed: %v", err)
	}

	shared := map[string]any{"key": strings.Repeat("x", maxBytes/2)}
	var depth any = nil
	for i := 0; i < maxDepth; i++ {
		depth = []any{depth}
	}
	if _, err := CanonicalizeValue(depth); err != nil {
		t.Fatalf("at depth limit: %v", err)
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	for _, tc := range []struct {
		name  string
		value any
		want  error
	}{
		{"over size", v + "x", errSize},
		{"shared expansion", []any{shared, shared}, errSize},
		{"key and structure", map[string]any{strings.Repeat("x", maxBytes-8): nil}, errSize},
		{"depth", []any{depth}, errDepth},
		{"cycle", cycle, errDepth},
		{"large integer", json.Number(strings.Repeat("9", maxIntegerDigits+1)), errInteger},
		{"malformed integer", json.Number("01"), errSyntax},
		{"floating token in integer type", json.Number("1.0"), errSyntax},
		{"nonfinite infinity", math.Inf(1), errFinite},
		{"nonfinite NaN", math.NaN(), errFinite},
		{"unsupported", []any{int(1)}, errSyntax},
		{"invalid UTF-8 value", "\xff", errUTF8},
		{"invalid UTF-8 key", map[string]any{"\xff": nil}, errUTF8},
		{"zero surrogate key", SurrogateObject{LoneSurrogates: map[SurrogateString]any{{}: nil}}, errSyntax},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := CanonicalizeValue(tc.value); got != nil || !errors.Is(err, tc.want) {
				t.Fatalf("returned %d bytes, error %v; want nil, %v", len(got), err, tc.want)
			}
		})
	}
}
