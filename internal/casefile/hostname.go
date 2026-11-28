package casefile

import (
	"iter"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

const (
	hostValid = 1 << iota
	hostContextJ
	hostContextO
	hostMark
	hostVirama
	hostCased
	hostCaseIgnorable
	hostGreek
	hostHebrew
	hostJapanese
)

const hostText = 1 << 17 // Beyond the packed Bidi and joining classes.

const (
	directionL = iota + 1
	directionR
	directionAL
	directionAN
	directionEN
	directionES
	directionCS
	directionET
	directionON
	directionBN
	directionNSM
)

const (
	joiningL = iota + 1
	joiningR
	joiningD
	joiningT
)

const (
	acePrefix          = "xn--"
	maxIDNALabelBytes  = 63
	maxIDNADomainBytes = 253
)

type hostRange struct {
	first, last rune
	value       int32
}

func hostValue(table []hostRange, r rune) int32 {
	i := sort.Search(len(table), func(i int) bool { return table[i].last >= r })
	if i == len(table) || r < table[i].first {
		return 0
	}
	return table[i].value
}

func hostPropertiesOf(r rune) int32 { return hostValue(hostProperties[:], r) }

func (v *validator) endpointText(raw any) string {
	text := v.text(raw, 1, 2048, false)
	for _, r := range text {
		if hostPropertiesOf(r)&hostText == 0 {
			v.require(false, "non-text character in case URL or origin")
			break
		}
	}
	return text
}

var idnaSeparators = strings.NewReplacer("。", ".", "．", ".", "｡", ".")

// canonicalHostname produces a comparison key for a previously parsed,
// non-IP-literal hostname. It does not rewrite the stored URL or resolve it.
// The released HTTPX parser lowercases first and uses IDNA2008 without UTS #46
// mappings. An ordinary ASCII hostname bypasses IDNA in that parser.
func canonicalHostname(host string) (string, bool) {
	if asciiHostname(host) {
		host = strings.ToLower(host)
	} else {
		var ok bool
		host, ok = asciiIDNADomain(idnaSeparators.Replace(lowerHostname(host)))
		if !ok {
			return "", false
		}
	}
	if looksLikeIPv4(host) {
		addr, err := netip.ParseAddr(host)
		return host, err == nil && addr.Is4()
	}
	if !strings.HasPrefix(host, acePrefix) {
		return host, true
	}
	if len(host) > maxIDNADomainBytes+1 {
		return "", false
	}
	// HTTPX's public host accessor decodes the entire domain when its
	// first label starts with ACE. AllowedOrigin then reparses this
	// decoded name, including the lowercase-before-IDNA step.
	unicodeHost, ok := idnaDomain(host, decodeIDNALabel)
	if !ok {
		return "", false
	}
	return asciiIDNADomain(lowerHostname(unicodeHost))
}

func asciiHostname(host string) bool {
	for i := 0; i < len(host); i++ {
		if host[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func looksLikeIPv4(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
	}
	return true
}

func lowerHostname(host string) string {
	input := []rune(host)
	var lower strings.Builder
	lower.Grow(len(host))
	precededByCased := false
	for i, r := range input {
		switch {
		case r == 'Σ' && precededByCased && !followedByCased(input[i+1:]):
			lower.WriteRune('ς')
		case hostLowerExpansions[r] != "":
			lower.WriteString(hostLowerExpansions[r])
		default:
			lower.WriteRune(r + hostValue(hostLowerDeltas[:], r))
		}
		properties := hostPropertiesOf(r)
		if properties&hostCaseIgnorable == 0 {
			precededByCased = properties&hostCased != 0
		}
	}
	return lower.String()
}

func followedByCased(rest []rune) bool {
	for _, r := range rest {
		properties := hostPropertiesOf(r)
		if properties&hostCaseIgnorable == 0 {
			return properties&hostCased != 0
		}
	}
	return false
}

func asciiIDNADomain(host string) (string, bool) {
	// The Python IDNA encoder initially allows up to 254 code points,
	// then enforces the length of the actual ASCII domain.
	if utf8.RuneCountInString(host) > maxIDNADomainBytes+1 {
		return "", false
	}
	wire, ok := idnaDomain(host, asciiIDNALabel)
	return wire, ok && len(strings.TrimSuffix(wire, ".")) <= maxIDNADomainBytes
}

func idnaDomain(host string, convertLabel func(string) (string, bool)) (string, bool) {
	name, trailingDot := strings.CutSuffix(host, ".")
	labels := strings.Split(name, ".")
	for i, label := range labels {
		converted, ok := convertLabel(label)
		if !ok {
			return "", false
		}
		labels[i] = converted
	}
	result := strings.Join(labels, ".")
	if trailingDot {
		result += "."
	}
	return result, true
}

func asciiIDNALabel(label string) (string, bool) {
	if asciiHostname(label) && strings.HasPrefix(label, acePrefix) {
		_, ok := decodeIDNALabel(label)
		return label, ok
	}
	if !validIDNALabel(label) {
		return "", false
	}
	// Use only the codec; the lookup and registration profiles apply
	// different UTS #46 validity/mapping rules from the released parser.
	wire, err := idna.Punycode.ToASCII(label)
	return wire, err == nil && len(wire) <= maxIDNALabelBytes
}

func decodeIDNALabel(wire string) (string, bool) {
	if len(wire) > maxIDNALabelBytes {
		return "", false
	}
	if !strings.HasPrefix(wire, acePrefix) {
		return wire, validIDNALabel(wire)
	}
	decoded, err := idna.Punycode.ToUnicode(wire)
	if err != nil || asciiHostname(decoded) || !validIDNALabel(decoded) {
		return "", false
	}
	roundTrip, err := idna.Punycode.ToASCII(decoded)
	return decoded, err == nil && roundTrip == wire
}

func validIDNALabel(label string) bool {
	if label == "" || label[0] == '-' || label[len(label)-1] == '-' || !utf8.ValidString(label) {
		return false
	}
	runes := []rune(label)
	if len(runes) >= 4 && runes[2] == '-' && runes[3] == '-' {
		return false
	}
	properties := make([]int32, len(runes))
	for i, r := range runes {
		properties[i] = hostPropertiesOf(r)
		if properties[i]&(hostValid|hostContextJ|hostContextO) == 0 {
			return false
		}
	}
	if properties[0]&hostMark != 0 || !isNFCLabel(label) || !validBidiLabel(properties) {
		return false
	}
	for i, p := range properties {
		if p&hostContextJ != 0 && !validJoiner(runes[i], properties, i) {
			return false
		}
		if p&hostContextO != 0 && !validContextO(runes, properties, i) {
			return false
		}
	}
	return true
}

func validJoiner(r rune, properties []int32, i int) bool {
	if i > 0 && properties[i-1]&hostVirama != 0 {
		return true
	}
	// A ZWJ requires Virama. A ZWNJ additionally permits the joining
	// context described in RFC 5892, Appendix A.1.
	return r == '\u200c' &&
		joinsNext(slices.Backward(properties[:i]), joiningL) &&
		joinsNext(slices.All(properties[i+1:]), joiningR)
}

func joinsNext(properties iter.Seq2[int, int32], direction int32) bool {
	for _, p := range properties {
		joining := (p >> 14) & 7
		if joining != joiningT {
			return joining == joiningD || joining == direction
		}
	}
	return false
}

func validContextO(runes []rune, properties []int32, i int) bool {
	switch r := runes[i]; {
	case r == '\u00b7':
		return i > 0 && i+1 < len(runes) && runes[i-1] == 'l' && runes[i+1] == 'l'
	case r == '\u0375':
		return i+1 < len(runes) && properties[i+1]&hostGreek != 0
	case r == '\u05f3' || r == '\u05f4':
		return i > 0 && properties[i-1]&hostHebrew != 0
	case r == '\u30fb':
		for j, p := range properties {
			if runes[j] != '\u30fb' && p&hostJapanese != 0 {
				return true
			}
		}
		return false
	case '\u0660' <= r && r <= '\u0669':
		return !slices.ContainsFunc(runes, func(r rune) bool { return '\u06f0' <= r && r <= '\u06f9' })
	case '\u06f0' <= r && r <= '\u06f9':
		return !slices.ContainsFunc(runes, func(r rune) bool { return '\u0660' <= r && r <= '\u0669' })
	default:
		return false
	}
}

func hostDirection(p int32) int32 { return (p >> 10) & 15 }

func validBidiLabel(properties []int32) bool {
	const (
		rtl     = 1<<directionR | 1<<directionAL | 1<<directionAN
		allowed = rtl | 1<<directionEN | 1<<directionES | 1<<directionCS |
			1<<directionET | 1<<directionON | 1<<directionBN | 1<<directionNSM
		endings = rtl | 1<<directionEN
	)
	if !slices.ContainsFunc(properties, func(p int32) bool { return 1<<hostDirection(p)&rtl != 0 }) {
		return true
	}
	first := hostDirection(properties[0])
	if first != directionR && first != directionAL {
		return false
	}
	var directions int
	var last int32
	for _, p := range properties {
		direction := hostDirection(p)
		directions |= 1 << direction
		if direction != directionNSM {
			last = direction
		}
	}
	const digitKinds = 1<<directionAN | 1<<directionEN
	return directions&^allowed == 0 && directions&digitKinds != digitKinds && 1<<last&endings != 0
}

func isNFCLabel(label string) bool {
	if norm.NFC.IsNormalString(label) {
		return true
	}
	// x/text normally enforces stream safety by inserting a CGJ after
	// a long run of non-starters. IDNA tests NFC, not stream-safe NFC.
	// Use its canonical decomposition and pair composition on this path.
	type part struct {
		r   rune
		ccc uint8
	}
	var parts []part
	for _, r := range label {
		for _, d := range norm.NFD.String(string(r)) {
			parts = append(parts, part{d, norm.NFD.PropertiesString(string(d)).CCC()})
		}
	}
	for i := 0; i < len(parts); {
		if parts[i].ccc == 0 {
			i++
		}
		end := i
		for end < len(parts) && parts[end].ccc != 0 {
			end++
		}
		slices.SortStableFunc(parts[i:end], func(a, b part) int { return int(a.ccc) - int(b.ccc) })
		i = end
	}
	var result []rune
	starter := -1
	var lastCCC uint8
	for _, p := range parts {
		if starter >= 0 && (lastCCC == 0 || lastCCC < p.ccc) {
			composed := norm.NFC.String(string(result[starter]) + string(p.r))
			if r, size := utf8.DecodeRuneInString(composed); size == len(composed) {
				result[starter] = r
				continue
			}
		}
		if p.ccc == 0 {
			starter = len(result)
		}
		result = append(result, p.r)
		lastCCC = p.ccc
	}
	return string(result) == label
}
