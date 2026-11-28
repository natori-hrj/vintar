package strictjson_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/natori-hrj/vintar/internal/strictjson"
)

func TestContractDigests(t *testing.T) {
	// docs/migration/v0.7.0-compatibility.md, from v0.6.0.
	for _, tc := range []struct{ source, canonical, sha string }{
		{`{"é":1.0,"b":"<"}`, `{"b":"<","\u00e9":1.0}`, "4059700a09ba87c8cccbabfe931027238356fb0c43fc8e444a973783dcdd8d87"},
		{`{"\ud800":-0.0,"v":1e-7}`, `{"v":1e-07,"\ud800":-0.0}`, "50852f2f2cea7a2c37c452f0e5caafa1088c801b56292c8ce3a2779393ccc8d6"},
	} {
		got := checkCanonical(t, tc.source, tc.canonical)
		sum := sha256.Sum256(got)
		if digest := hex.EncodeToString(sum[:]); digest != tc.sha {
			t.Fatalf("SHA-256 = %s, want %s", digest, tc.sha)
		}
	}
}

func TestCanonical(t *testing.T) {
	for _, tc := range []struct{ name, source, canonical string }{
		// Scalar and ordering vectors from v0.6.0 tests/test_json_body.py.
		{"null", `null`, `null`},
		{"true", `true`, `true`},
		{"false", `false`, `false`},
		{"zero", `0`, `0`},
		{"negative integer", `-42`, `-42`},
		{"text", `"text"`, `"text"`},
		{"tenth", `0.1`, `0.1`},
		{"small", `1e-7`, `1e-07`},
		{"float one", `1.0e0`, `1.0`},
		{"trim zero", `1.50`, `1.5`},
		{"negative float zero", `-0.0`, `-0.0`},
		{"exponent to integral float", `2.5e1`, `25.0`},
		{"sort", `{"界":"値","a":[1,2.00]}`, `{"a":[1,2.0],"\u754c":"\u5024"}`},
		{"whitespace and scalar types", " \t[true, 1,\n1.0,\rfalse,-0] \r", `[true,1,1.0,false,0]`},
		{"escapes", `"\"\\\/\b\f\n\r\t\u001F <>&` + "\x7f" + `é𝄞"`, `"\"\\/\b\f\n\r\t\u001f <>&\u007f\u00e9\ud834\udd1e"`},
		{"code point order", `{"𐀀":1,"\ue000":2,"\udfff":3,"\ud800":4,"�":5,"a":6}`, `{"a":6,"\ud800":4,"\udfff":3,"\ue000":2,"\ufffd":5,"\ud800\udc00":1}`},
		{"surrogate sequences", `["\uD800x\uDC00","\ud800\ud800\udc00","\ud800\\udc00","\uFFFD"]`, `["\ud800x\udc00","\ud800\ud800\udc00","\ud800\\udc00","\ufffd"]`},
		{"cutovers", `[1E-5,1E-4,1E15,1E16,-1E20,1.234567890123456e15]`, `[1e-05,0.0001,1000000000000000.0,1e+16,-1e+20,1234567890123456.0]`},
		{"cutovers after rounding", `[9.9999999999999999e-5,9.9999999999999999e15]`, `[0.0001,1e+16]`},
		{"binary64 rounding", `[9007199254740993,9007199254740993.0,1.7976931348623157e308,5e-324,2e-324,-1e-9999,2.2250738585072014e-308]`, `[9007199254740993,9007199254740992.0,1.7976931348623157e+308,5e-324,0.0,-0.0,2.2250738585072014e-308]`},
		{"large mantissa", `1` + strings.Repeat("0", 100001) + `e-100001`, `1.0`},
		{"long leading fraction", `-0.` + strings.Repeat("0", 100001) + `15e+100002`, `-1.5`},
		{"huge zero exponent", `-0e` + strings.Repeat("9", 1000), `-0.0`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCanonical(t, tc.source, tc.canonical)
			checkCanonical(t, string(got), tc.canonical)
		})
	}
}

func TestUnderflowMidpoint(t *testing.T) {
	// 2^-1075 is exactly halfway between zero and the first subnormal.
	// A nonzero digit well beyond that midpoint must still round up.
	digits := new(big.Int).Exp(big.NewInt(5), big.NewInt(1075), nil).String()
	half := "0." + strings.Repeat("0", 1075-len(digits)) + digits
	checkCanonical(t, half, "0.0")
	checkCanonical(t, "-"+half, "-0.0")
	checkCanonical(t, half+strings.Repeat("0", 1000)+"1", "5e-324")
}

func TestParseTypes(t *testing.T) {
	got, err := strictjson.Parse([]byte(`{"a":[1,1.0,-0,-0e0,null,true,"\ud834\udd1e","\ud800","\\ud800",[],{}]}`))
	if err != nil {
		t.Fatal(err)
	}
	obj, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("object has type %T", got)
	}
	arr, ok := obj["a"].([]any)
	if !ok || len(arr) != 11 {
		t.Fatalf("unexpected array: %#v", obj["a"])
	}
	if arr[0] != json.Number("1") || arr[1] != float64(1) || arr[2] != json.Number("0") ||
		arr[4] != nil || arr[5] != true || arr[6] != "𝄞" || arr[8] != `\ud800` {
		t.Fatalf("unexpected types or values: %#v", arr)
	}
	if f, ok := arr[3].(float64); !ok || f != 0 || !math.Signbit(f) {
		t.Fatalf("negative zero not preserved: %#v", arr[3])
	}
	if s, ok := arr[7].(strictjson.SurrogateString); !ok || s.JSON() != `"\ud800"` {
		t.Fatalf("lone surrogate not preserved: %#v", arr[7])
	}
	if a, ok := arr[9].([]any); !ok || a == nil || len(a) != 0 {
		t.Fatalf("empty array not preserved: %#v", arr[9])
	}
	if m, ok := arr[10].(map[string]any); !ok || m == nil || len(m) != 0 {
		t.Fatalf("empty object not preserved: %#v", arr[10])
	}

	got, err = strictjson.Parse([]byte(`{"\ud800":1,"\\ud800":2,"�":3}`))
	if err != nil {
		t.Fatal(err)
	}
	special, ok := got.(strictjson.SurrogateObject)
	if !ok || len(special.LoneSurrogates) != 1 || len(special.UTF8) != 2 ||
		special.UTF8[`\ud800`] != json.Number("2") || special.UTF8["�"] != json.Number("3") {
		t.Fatalf("unexpected surrogate object: %#v", got)
	}
	for key, value := range special.LoneSurrogates {
		if key.JSON() != `"\ud800"` || value != json.Number("1") {
			t.Fatalf("unexpected lone-surrogate member: %s: %v", key.JSON(), value)
		}
	}
}

func TestReject(t *testing.T) {
	for _, tc := range []struct{ name, source, diagnostic string }{
		// Duplicate, trailing, UTF-8, and finite-number vectors from v0.6.0.
		{"duplicate", `{"a":1,"a":2}`, "duplicate object member"},
		{"nested duplicate", `{"a":{"b":1,"b":2}}`, "duplicate object member"},
		{"trailing", `{} trailing`, "trailing data"},
		{"invalid utf8", "\xff", "UTF-8"},
		{"positive overflow", `1e400`, "finite float range"},
		{"negative overflow", `-1e400`, "finite float range"},
		{"nan", `NaN`, "must be finite"},
		{"infinity", `Infinity`, "must be finite"},
		{"negative infinity", `-Infinity`, "must be finite"},
		{"escaped duplicate", `{"PRIVATE-SENTINEL":null,"\u0050RIVATE-SENTINEL":1}`, "duplicate object member"},
		{"astral duplicate", `{"𝄞":0,"\ud834\uDD1E":1}`, "duplicate object member"},
		{"surrogate duplicate", `{"\uD800":false,"\ud800":true}`, "duplicate object member"},
		{"unescaped surrogate bytes", "\"\xed\xa0\x80\"", "UTF-8"},
		{"bom", "\xef\xbb\xbf{}", "invalid"},
		{"non-JSON whitespace", "\u00a0true", "invalid"},
		{"empty", "", "invalid"},
		{"second value", `true false`, "trailing data"},
		{"trailing secret", `{} PRIVATE-SENTINEL`, "trailing data"},
		{"raw control", "\"\n\"", "invalid"},
		{"invalid escape", `"\xPRIVATE-SENTINEL"`, "invalid"},
		{"bad hex", `"\ud80x"`, "invalid"},
		{"bad second unit", `"\ud800\uaax0"`, "invalid"},
		{"truncated string", `"abc\`, "invalid"},
		{"array trailing comma", `[1,]`, "invalid"},
		{"object trailing comma", `{"a":1,}`, "invalid"},
		{"missing colon", `{"a" 1}`, "invalid"},
		{"unquoted key", `{a:1}`, "invalid"},
		{"leading zero", `01`, "invalid"},
		{"explicit plus", `+1`, "invalid"},
		{"bare minus", `-`, "invalid"},
		{"missing integer part", `.1`, "invalid"},
		{"missing fraction", `1.`, "invalid"},
		{"missing exponent", `1e+`, "invalid"},
		{"huge overflowing exponent", `1e` + strings.Repeat("9", 1000), "finite float range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkReject(t, tc.source, tc.diagnostic)
		})
	}
}

func TestBounds(t *testing.T) {
	const bytes = 1 << 20
	const depth = 48
	digits := strings.Repeat("9", 4300)
	for _, sign := range []string{"", "-"} {
		checkCanonical(t, sign+digits, sign+digits)
		checkReject(t, sign+digits+"0", "integer is too long")
	}
	// v0.6.0's maximum-sized document containing maximum-width integers.
	count := (bytes - 2) / (len(digits) + 1)
	body := "[" + strings.Repeat(digits+",", count-1) + digits + "]"
	padded := body + strings.Repeat(" ", bytes-len(body))
	checkCanonical(t, padded, body)
	checkReject(t, padded+" ", "exceeds 1048576 bytes")

	// The budget is bytes, not Unicode code points.
	utf8Body := `"` + strings.Repeat("é", (bytes-2)/2) + `"`
	checkCanonical(t, utf8Body, `"`+strings.Repeat(`\u00e9`, (bytes-2)/2)+`"`)
	checkReject(t, utf8Body+" ", "exceeds 1048576 bytes")

	for _, brackets := range [][2]string{{`[`, `]`}, {`{"a":`, `}`}} {
		for _, leaf := range []string{`0`, `[]`, `{}`} {
			atLimit := strings.Repeat(brackets[0], depth) + leaf + strings.Repeat(brackets[1], depth)
			checkCanonical(t, atLimit, atLimit)
			checkReject(t, brackets[0]+atLimit+brackets[1], "nesting exceeds 48")
		}
	}
}

func checkCanonical(t *testing.T, source, want string) []byte {
	t.Helper()
	got, err := strictjson.Canonicalize([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.Valid(got) || !json.Valid(got) {
		t.Fatal("canonical result is not valid UTF-8 JSON")
	}
	if string(got) != want {
		t.Fatalf("canonical result (len %d): %.120q, want (len %d): %.120q", len(got), got, len(want), want)
	}
	return got
}

func checkReject(t *testing.T, source, diagnostic string) {
	t.Helper()
	parsed, parseErr := strictjson.Parse([]byte(source))
	out, canonicalErr := strictjson.Canonicalize([]byte(source))
	if parsed != nil || out != nil {
		t.Fatal("returned a partial result on invalid input")
	}
	for _, err := range []error{parseErr, canonicalErr} {
		if err == nil || !strings.Contains(err.Error(), diagnostic) || strings.Contains(err.Error(), "PRIVATE-SENTINEL") {
			t.Fatalf("expected a sanitized error containing %q, got %v", diagnostic, err)
		}
	}
}
