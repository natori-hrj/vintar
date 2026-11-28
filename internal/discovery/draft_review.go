package discovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/natori-hrj/vintar/internal/strictjson"
	"github.com/pelletier/go-toml/v2"
)

var (
	errDraftStale       = errors.New("Draft is stale or incompatible. Rerun discovery and re-confirm the input.")
	errReviewCandidate  = errors.New("Baseline pointer is not a supported explicit local baseline candidate. Supply a pointer to a declared example, default, or single-value enum, or provide a value.")
	errReviewRefLimit   = errors.New("Reference work limit exceeded. Simplify or split the spec.")
	errReviewRefCycle   = errors.New("Cyclic baseline reference. Break the recursive reference chain.")
	errReviewRefMissing = errors.New("Baseline reference target is missing or invalid. Point to an existing declaration.")
	errReviewRefLocal   = errors.New("Unsupported baseline reference. Bundle the spec and use a local JSON Pointer.")
)

type draftReviewReport struct {
	Verdict       string                         `json:"expected_verdict"`
	InputID       string                         `json:"input_id"`
	Parameters    map[string]draftReviewDecision `json:"parameters"`
	ReportType    string                         `json:"report_type"`
	SchemaVersion int                            `json:"schema_version"`
	Source        Source                         `json:"source"`
}

type draftReviewDecision struct {
	Source any    `json:"source,omitempty"` // "reviewer" or spec provenance
	Status string `json:"status"`
	Digest string `json:"value_sha256,omitempty"`
}

// BuildDraftReview validates one exported draft against the current OpenAPI
// inventory and produces an inert review report. source is the caller-resolved
// cwd-relative slash label. Inputs are bytes; this function performs no I/O.
// Baseline scalars are used for digests only, never returned or diagnosed.
func BuildDraftReview(specJSON []byte, source string, draftTOML, answersJSON []byte) (report []byte, inputID string, err error) {
	if !utf8.ValidString(source) || path.IsAbs(source) || source == "." || source == ".." ||
		strings.HasPrefix(source, "../") || strings.ContainsRune(source, 0) || path.Clean(source) != source {
		return nil, "", errors.New("Spec is outside the current working directory. Run from a directory containing the spec.")
	}
	inventory, err := BuildInventory(specJSON, source)
	if err != nil {
		return nil, "", errors.New("Cannot inventory the spec. Check its format, declarations, and references, then rerun discovery.")
	}
	var draft map[string]any
	if len(draftTOML) > 1<<20 || !utf8.Valid(draftTOML) || toml.Unmarshal(draftTOML, &draft) != nil {
		return nil, "", errors.New("Cannot read the draft. Supply a UTF-8 draft exported by discover.")
	}
	id, _ := draft["input_id"].(string)
	operation, item := findReviewInput(inventory, id)
	if item == nil {
		return nil, "", errors.New("Draft input is missing or stale. Rerun discovery and review the current input.")
	}
	query := make([]Input, 0, len(operation.Inputs))
	for _, input := range operation.Inputs {
		if input.Location == "query" {
			query = append(query, input)
		}
	}
	if !operation.Compatible || !item.Compatible || item.IgnoredReason != nil ||
		!currentReviewDraft(draftTOML, source, *operation, *item, query) {
		return nil, "", errDraftStale
	}

	parsed, err := strictjson.Parse(answersJSON)
	if err != nil {
		return nil, "", errors.New("Cannot read review answers. Supply a bounded UTF-8 JSON file with unique keys.")
	}
	config, ok := parsed.(map[string]any)
	_, hasVerdict := config["expected_verdict"]
	_, hasParameters := config["parameters"]
	if !ok || len(config) != 3 || config["version"] != json.Number("1") || !hasVerdict || !hasParameters {
		return nil, "", errors.New("Invalid review answers. Set version to 1 and provide only expected_verdict and parameters.")
	}
	verdict, _ := config["expected_verdict"].(string)
	switch verdict {
	case "not_detected", "inconclusive", "vulnerable":
	default:
		return nil, "", errors.New("Expected verdict is missing or invalid. Explicitly set expected_verdict to not_detected, inconclusive, or vulnerable.")
	}
	parameters, ok := config["parameters"].(map[string]any)
	known := 0
	for _, input := range query {
		if _, ok := parameters[input.Name]; ok {
			known++
		}
	}
	if !ok || len(parameters) != known {
		return nil, "", errors.New("Answers contain unknown parameters or an invalid parameters object. Use only declared query names from the draft.")
	}
	result := draftReviewReport{
		Verdict: verdict, InputID: item.ID, Parameters: make(map[string]draftReviewDecision, len(query)),
		ReportType: "discovery_draft_review", SchemaVersion: 1, Source: item.Source,
	}
	candidates := draftReviewCandidates{spec: specJSON, targets: make(map[string]referenceTarget), digests: make(map[string]string)}
	for _, input := range query {
		decision, err := candidates.decision(input, parameters[input.Name])
		if err != nil {
			return nil, "", err
		}
		result.Parameters[input.Name] = decision
	}
	report, err = encodeDraftReviewReport(result)
	if err != nil {
		return nil, "", err
	}
	return report, item.ID, nil
}

func findReviewInput(inventory Inventory, id string) (*InventoryOperation, *Input) {
	var operation *InventoryOperation
	var input *Input
	for i := range inventory.Operations {
		op := &inventory.Operations[i]
		for j := range op.Inputs {
			if op.Inputs[j].ID != id {
				continue
			}
			if input != nil {
				return nil, nil // An ambiguous identity is not reviewable.
			}
			operation, input = op, &op.Inputs[j]
		}
	}
	return operation, input
}

// The release treats a draft as an exact export, not as editable TOML. Check
// both the released spelling and Go discover's spelling of U+2028/U+2029.
func currentReviewDraft(data []byte, source string, operation InventoryOperation, item Input, query []Input) bool {
	const decisions = `["route mapping and baseline query values", "trusted target, authorization, and any credential requirements", "reviewed check configuration and probe inputs", "expected verdict", "trusted limits and required Schema v1 case fields"]`
	const header = "kind = \"vintar_review_draft\"\ndraft_version = 1\nid = %s\ninput_id = %s\nmethod = %s\npath = %s\nquery_parameter = %s\nmissing_decisions = %s\n\n[source]\nfile = %s\noperation = %s\noperation_definition = %s\ndeclaration = %s\ndefinition = %s\n"
	if len(data) > 65536 {
		return false
	}
	releaseEscapes := strings.NewReplacer(`\\`, `\\`, `\u2028`, "\u2028", `\u2029`, "\u2029")
	for _, released := range []bool{false, true} {
		quote := func(s string) string {
			var b strings.Builder
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(s)
			text := strings.ReplaceAll(strings.TrimSuffix(b.String(), "\n"), "\x7f", `\u007f`)
			if released {
				return releaseEscapes.Replace(text)
			}
			return text
		}
		var expected bytes.Buffer
		fmt.Fprintf(&expected, header, quote("case-"+strings.TrimPrefix(item.ID, "input-")), quote(item.ID),
			quote(operation.Method), quote(operation.Path), quote(item.Name), decisions, quote(source),
			quote(operation.Source.Pointer), quote(operation.Definition.Pointer), quote(item.Source.Pointer), quote(item.Definition.Pointer))
		for _, param := range query {
			fmt.Fprintf(&expected, "\n[[query_parameters]]\nname = %s\nrequired = %t\n", quote(param.Name), param.Required)
			if expected.Len() > len(data) {
				break
			}
		}
		if bytes.Equal(data, expected.Bytes()) {
			return true
		}
	}
	return false
}

type draftReviewCandidates struct {
	spec    []byte
	root    map[string]any
	targets map[string]referenceTarget
	digests map[string]string
	work    int
}

func (c *draftReviewCandidates) decision(input Input, raw any) (draftReviewDecision, error) {
	answer, ok := raw.(map[string]any)
	if !ok {
		return draftReviewDecision{}, errors.New("Missing or invalid baseline decision. Add value, pointer, or omit to --answers.")
	}
	if len(answer) == 1 && answer["omit"] == true {
		if input.Required {
			return draftReviewDecision{}, errors.New("Required parameters cannot be omitted. Supply a value or baseline pointer.")
		}
		return draftReviewDecision{Status: "omitted"}, nil
	}
	var provenance any = "reviewer"
	value, hasValue := answer["value"]
	pointer, hasPointer := answer["pointer"]
	claimed, hasDigest := answer["value_sha256"]
	var canonical string
	switch {
	case len(answer) == 1 && hasValue:
	case hasPointer && (len(answer) == 1 || len(answer) == 2 && hasDigest):
		text, ok := pointer.(string)
		if !ok || !strings.HasPrefix(text, "/") {
			return draftReviewDecision{}, errReviewCandidate
		}
		var err error
		canonical, value, err = c.candidate(input, text)
		if err != nil {
			return draftReviewDecision{}, err
		}
		provenance = Source{File: input.Source.File, Pointer: canonical}
	default:
		return draftReviewDecision{}, errors.New("Invalid decision keys. Use value, pointer with optional value_sha256, or omit: true.")
	}
	digest, ok := c.digests[canonical]
	if !ok {
		var err error
		digest, err = reviewScalarDigest(value)
		if err != nil {
			return draftReviewDecision{}, err
		}
		if canonical != "" {
			c.digests[canonical] = digest
		}
	}
	if hasDigest && claimed != digest {
		return draftReviewDecision{}, errors.New("Stale baseline digest. Rerun discovery and re-confirm the input in --answers.")
	}
	return draftReviewDecision{Source: provenance, Status: "resolved", Digest: digest}, nil
}

func reviewScalarDigest(value any) (string, error) {
	var literal string
	switch value := value.(type) {
	case nil:
		return "", errors.New("Baseline query inputs require concrete non-null values. Supply a concrete value or omit the parameter if optional.")
	case string:
		literal = identityString(value)
	case strictjson.SurrogateString:
		literal = value.JSON()
	case bool:
		literal = strconv.FormatBool(value)
	case json.Number:
		literal = value.String()
	case float64:
		// Preserve the integer/float distinction, including signed zero,
		// before strictjson applies the release's float formatting rules.
		literal = strconv.FormatFloat(value, 'g', -1, 64)
		if !strings.ContainsAny(literal, ".eE") {
			literal += ".0"
		}
		canonical, err := strictjson.Canonicalize([]byte(literal))
		if err != nil {
			return "", errors.New("Invalid baseline number. Supply a finite scalar value.")
		}
		literal = string(canonical)
	default:
		return "", errors.New("Baseline query input is not a scalar. Supply a concrete scalar value.")
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(literal))), nil
}

type reviewExampleRef struct {
	prefix   string
	token    string
	value    map[string]any
	selected bool
}

func (c *draftReviewCandidates) candidate(input Input, pointer string) (string, any, error) {
	if c.root == nil {
		// BuildInventory has already validated this document. Parse only if a
		// decision actually needs access to the original scalar candidates.
		parsed, err := strictjson.Parse(c.spec)
		if err != nil {
			return "", nil, errReviewCandidate
		}
		c.root, _ = parsed.(map[string]any)
	}
	// Inventory pointers are plain RFC 6901 strings rather than URI
	// fragments; protect literal '%' before reusing fragment traversal.
	definition := input.Definition.Pointer
	value, _, err := lookupPointerFragment(c.root, strings.ReplaceAll(definition, "%", "%25"))
	parameter, ok := value.(map[string]any)
	if err != nil || !ok {
		return "", nil, errReviewCandidate
	}
	var refs []reviewExampleRef
	pointerTarget, selectsValue := strings.CutSuffix(pointer, "/value")
	checkExamples := func(node map[string]any, site string) (any, bool) {
		if pointer == site+"/example" {
			if value, ok := node["example"]; ok {
				return value, true
			}
		}
		examples, _ := node["examples"].(map[string]any)
		prefix := site + "/examples/"
		suffix, underExamples := strings.CutPrefix(pointer, prefix)
		key, valuePointer := strings.CutSuffix(suffix, "/value")
		for name, value := range examples {
			example, ok := value.(map[string]any)
			if !ok {
				continue
			}
			token := escapeToken.Replace(name)
			atValue := underExamples && valuePointer && key == token
			if raw, hasRef := example["$ref"]; hasRef {
				text, ok := raw.(string)
				fragment, local := strings.CutPrefix(text, "#")
				selected := atValue || underExamples && suffix == token
				valid := false
				if ok && local {
					target, validTarget := reviewPointerFragment(fragment)
					valid = validTarget
					selected = selected || valid && selectsValue && pointerTarget == target
				}
				if selected || valid {
					refs = append(refs, reviewExampleRef{prefix: prefix, token: token, value: example, selected: selected})
				}
				continue
			}
			if atValue {
				value, hasValue := example["value"]
				if _, external := example["externalValue"]; hasValue && !external {
					return value, true
				}
			}
		}
		return nil, false
	}
	if value, ok := checkExamples(parameter, definition); ok {
		return pointer, value, nil
	}
	if raw, ok := parameter["schema"]; ok {
		resolved, site, err := c.resolve(raw, definition+"/schema")
		if err != nil {
			return "", nil, err
		}
		schema, _ := resolved.(map[string]any) // OpenAPI 3.1 boolean schemas have no candidates.
		if value, ok := checkExamples(schema, site); ok {
			return pointer, value, nil
		}
		if token, ok := strings.CutPrefix(pointer, site+"/examples/"); ok && canonicalDecimal(token) {
			list, _ := schema["examples"].([]any)
			if index, err := strconv.Atoi(token); err == nil && index < len(list) {
				return pointer, list[index], nil
			}
		}
		if value, ok := schema["default"]; ok && pointer == site+"/default" {
			return pointer, value, nil
		}
		if list, ok := schema["enum"].([]any); ok && len(list) == 1 && pointer == site+"/enum/0" {
			return pointer, list[0], nil
		}
	}
	// Try references explicitly selected at their declaration or first
	// target before scanning other references for a matching final target.
	slices.SortFunc(refs, func(a, b reviewExampleRef) int {
		if a.selected != b.selected {
			if a.selected {
				return -1
			}
			return 1
		}
		if a.prefix == b.prefix {
			return strings.Compare(a.token, b.token)
		}
		if suffix, ok := strings.CutPrefix(a.prefix, b.prefix); ok {
			return strings.Compare(suffix+a.token, b.token)
		}
		if suffix, ok := strings.CutPrefix(b.prefix, a.prefix); ok {
			return strings.Compare(a.token, suffix+b.token)
		}
		return strings.Compare(a.prefix, b.prefix)
	})
	for _, ref := range refs {
		declaration := ref.prefix + ref.token
		resolved, site, err := c.resolve(ref.value, declaration)
		example, ok := resolved.(map[string]any)
		if err == nil && !ok {
			err = errReviewRefMissing
		}
		if err != nil {
			if ref.selected || err == errReviewRefLimit {
				return "", nil, err
			}
			continue
		}
		if pointer != declaration && (!selectsValue || pointerTarget != declaration && pointerTarget != site) {
			continue
		}
		value, hasValue := example["value"]
		if _, external := example["externalValue"]; !hasValue || external {
			return "", nil, errors.New("The selected example has no usable local value. Inline a scalar value or provide a value in --answers.")
		}
		return site + "/value", value, nil
	}
	return "", nil, errReviewCandidate
}

// This only checks the fragment's spelling, not whether its target exists.
// Unselected malformed examples must not consume resolution work.
func reviewPointerFragment(fragment string) (string, bool) {
	decoded, err := url.PathUnescape(fragment)
	if err != nil || !utf8.ValidString(decoded) || decoded != "" && !strings.HasPrefix(decoded, "/") {
		return "", false
	}
	for i := 0; i < len(decoded); i++ {
		if decoded[i] == '~' {
			i++
			if i == len(decoded) || decoded[i] != '0' && decoded[i] != '1' {
				return "", false
			}
		}
	}
	return decoded, true
}

func (c *draftReviewCandidates) resolve(value any, site string) (any, string, error) {
	var trail [24]string
	for hops := 0; ; hops++ {
		node, ok := value.(map[string]any)
		if !ok {
			return value, site, nil
		}
		raw, hasRef := node["$ref"]
		if !hasRef {
			return node, site, nil
		}
		c.work++
		if c.work > 4096 || hops == len(trail) {
			return nil, "", errReviewRefLimit
		}
		text, ok := raw.(string)
		fragment, local := strings.CutPrefix(text, "#")
		if !ok || !local {
			return nil, "", errReviewRefLocal
		}
		target, cached := c.targets[text]
		if !cached {
			next, pointer, err := lookupPointerFragment(c.root, fragment)
			if err != nil {
				return nil, "", errReviewRefMissing
			}
			target = referenceTarget{next, pointer}
			c.targets[text] = target
		}
		if target.pointer == site || slices.Contains(trail[:hops], target.pointer) {
			return nil, "", errReviewRefCycle
		}
		trail[hops] = site
		value, site = target.value, target.pointer
	}
}

func encodeDraftReviewReport(result draftReviewReport) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		return nil, errors.New("Cannot encode the review report.")
	}
	// Go already sorted the keys. Escape remaining non-ASCII runes to match
	// the released ensure_ascii format, without reparsing the report as input.
	if bytes.IndexFunc(b.Bytes(), func(r rune) bool { return r >= 0x7f }) < 0 {
		return b.Bytes(), nil
	}
	var ascii bytes.Buffer
	for _, r := range b.String() {
		switch {
		case r < 0x7f:
			ascii.WriteByte(byte(r))
		case r <= 0xffff:
			fmt.Fprintf(&ascii, `\u%04x`, r)
		default:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&ascii, `\u%04x\u%04x`, hi, lo)
		}
	}
	return ascii.Bytes(), nil
}
