package discovery

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf16"

	"github.com/natori-hrj/vintar/internal/strictjson"
)

type Source struct {
	File    string `json:"file"`
	Pointer string `json:"pointer"`
}

type Held struct {
	Source     Source  `json:"source"`
	Definition *Source `json:"definition"`
	Reason     string  `json:"reason"`
}

type Input struct {
	ID            string  `json:"id"`
	Location      string  `json:"location"`
	Name          string  `json:"name"`
	Required      bool    `json:"required"`
	Compatible    bool    `json:"compatible"`
	Selected      bool    `json:"selected"`
	Source        Source  `json:"source"`
	Definition    Source  `json:"definition"`
	IgnoredReason *string `json:"ignored_reason"`
}

type InventoryOperation struct {
	ID                   string  `json:"id"`
	Method               string  `json:"method"`
	Path                 string  `json:"path"`
	Source               Source  `json:"source"`
	Definition           Source  `json:"definition"`
	Inputs               []Input `json:"inputs"`
	Compatible           bool    `json:"compatible"`
	CompatibilityBlocker *Held   `json:"compatibility_blocker,omitempty"`
	CompatibilityStatus  string  `json:"compatibility_status,omitempty"`
}

type Inventory struct {
	Version       string               `json:"version"`
	Source        Source               `json:"source"`
	Operations    []InventoryOperation `json:"operations"`
	Held          []Held               `json:"held"`
	SchemaVersion int                  `json:"schema_version"`
	ReportType    string               `json:"report_type"`
}

const scalarQueryHold = "Parameter is outside the v1 scalar query model. Review it separately."
const booleanSchemaHold = "Boolean schema is unsupported for compatibility. Review this input separately or use a schema object."
const referenceSiblingHold = "Reference sibling is unsupported. Move it into the referenced declaration."

var errInventoryInput = errors.New("unsupported or invalid OpenAPI inventory input")

// BuildInventory builds provenance and parameter metadata without constructing
// requests or supplying any test values.
func BuildInventory(data []byte, source string) (Inventory, error) {
	value, err := strictjson.Parse(data)
	if err != nil {
		return Inventory{}, errInventoryInput
	}
	root, ok := value.(map[string]any)
	if !ok || !validDiscoveryDocument(root) {
		return Inventory{}, errInventoryInput
	}
	version, ok := root["openapi"].(string)
	if !ok || !(strings.HasPrefix(version, "3.0.") || strings.HasPrefix(version, "3.1.")) ||
		len(version) == 4 || strings.ContainsFunc(version[4:], func(r rune) bool { return r < '0' || r > '9' }) {
		return Inventory{}, errInventoryInput
	}
	paths, mapPaths := root["paths"].(map[string]any)
	if _, hasPaths := root["paths"]; !mapPaths && (hasPaths || strings.HasPrefix(version, "3.0.")) {
		return Inventory{}, errInventoryInput
	}
	out := Inventory{
		Version: version, Source: Source{File: source},
		SchemaVersion: 1, ReportType: "discovery_inventory",
		Operations: []InventoryOperation{}, Held: []Held{},
	}
	if _, has := root["webhooks"]; has {
		out.Held = append(out.Held, Held{Source: Source{source, "/webhooks"}, Reason: "Webhooks are outside the inventory model. Review them separately."})
	}
	work := 0
	resolver := inventoryReferences{root: root, targets: make(map[string]referenceTarget), held: &out.Held, work: &work}
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		if strings.HasPrefix(path, "x-") {
			continue
		}
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\\") {
			return Inventory{}, errInventoryInput
		}
		declared := Source{source, "/paths/" + escapeToken.Replace(path)}
		startHolds := len(out.Held)
		resolved, pathDefinition, _, err := resolver.resolve(paths[path], declared, nil)
		pathItem, ok := resolved.(map[string]any)
		if err != nil || !ok {
			return Inventory{}, errInventoryInput
		}
		var pathBlocker *Held
		for _, hold := range out.Held[startHolds:] {
			if strings.HasSuffix(hold.Source.Pointer, "/parameters") {
				pathBlocker = &hold
				break
			}
		}
		inherited, blockers, err := inventoryParameters(&resolver, pathItem, pathDefinition, version)
		if err != nil {
			return Inventory{}, err
		}
		for key := range pathItem {
			if !slices.Contains(methods[:], key) && !slices.Contains([]string{"summary", "description", "servers", "parameters"}, key) && !strings.HasPrefix(key, "x-") {
				if !resolver.hold(pathDefinition, key, "Unsupported path item field. Review it separately.") {
					return Inventory{}, errInventoryInput
				}
			}
		}
		for _, method := range methods {
			raw, found := pathItem[method]
			if !found {
				continue
			}
			operation, ok := raw.(map[string]any)
			if !ok || len(out.Operations) == 512 {
				return Inventory{}, errInventoryInput
			}
			definition := Source{source, pathDefinition.Pointer + "/" + method}
			declaration := declared
			if declared == pathDefinition {
				declaration = definition
			}
			row := Operation{Method: method, Path: path, Pointer: definition.Pointer}
			item, err := inventoryOperation(&out, &resolver, row, operation, inherited, blockers, declaration, definition, pathBlocker)
			if err != nil {
				return Inventory{}, err
			}
			out.Operations = append(out.Operations, item)
		}
	}
	slices.SortFunc(out.Operations, func(a, b InventoryOperation) int {
		if a.Method != b.Method {
			return strings.Compare(a.Method, b.Method)
		}
		return strings.Compare(a.Path, b.Path)
	})
	slices.SortFunc(out.Held, func(a, b Held) int {
		if a.Source.Pointer != b.Source.Pointer {
			return strings.Compare(a.Source.Pointer, b.Source.Pointer)
		}
		return strings.Compare(a.Reason, b.Reason)
	})
	out.Held = slices.CompactFunc(out.Held, func(a, b Held) bool {
		if a.Source != b.Source || a.Reason != b.Reason {
			return false
		}
		if a.Definition == nil || b.Definition == nil {
			return a.Definition == b.Definition
		}
		return *a.Definition == *b.Definition
	})
	return out, nil
}

func inventoryOperation(out *Inventory, refs *inventoryReferences, row Operation, operation map[string]any, inherited map[parameterKey]Input, blockers []parameterBlocker, declaration, definition Source, blocker *Held) (InventoryOperation, error) {
	body, hasBody := operation["requestBody"]
	params := maps.Clone(inherited)
	override, _, err := inventoryParameters(refs, operation, definition, out.Version)
	if err != nil {
		return InventoryOperation{}, err
	}
	if blocker == nil {
		for _, entry := range blockers {
			if _, replaced := override[entry.key]; !replaced {
				blocker = &entry.held
				break
			}
		}
	}
	for key, input := range override {
		params[key] = input
	}
	*refs.work += len(params)
	if *refs.work > 8192 {
		return InventoryOperation{}, errInventoryInput
	}
	method := strings.ToUpper(row.Method)
	item := InventoryOperation{
		Method: method, Path: row.Path, Source: declaration, Definition: definition,
		ID: shortID("op-", method+" "+row.Path), Inputs: []Input{},
		CompatibilityBlocker: blocker,
	}
	if blocker != nil {
		item.CompatibilityStatus = "unverified"
	}
	if row.Method != "get" {
		out.Held = append(out.Held, Held{Source: definition, Reason: "Method is outside the v1 GET model. Review it separately."})
	}
	if _, has := operation["callbacks"]; has {
		out.Held = append(out.Held, Held{Source: Source{definition.File, row.Pointer + "/callbacks"}, Reason: "Callbacks are outside the inventory model. Review them separately."})
	}
	anyCompatible, allRequiredCompatible := false, true
	for key, input := range params {
		input.Compatible = row.Method == "get" && !hasBody && blocker == nil && input.Compatible
		input.ID = shortID("input-", "["+identityString(item.ID)+", "+identityString(key.location)+", "+identityString(key.name)+"]")
		item.Inputs = append(item.Inputs, input)
		anyCompatible = anyCompatible || input.Compatible
		allRequiredCompatible = allRequiredCompatible && (input.IgnoredReason != nil || !input.Required || input.Compatible)
	}
	if hasBody {
		inventoryBody := bodyInventory{refs: refs, operationID: item.ID, version: out.Version}
		fields, err := inventoryBody.inputs(body, Source{definition.File, row.Pointer + "/requestBody"})
		if err != nil {
			return InventoryOperation{}, err
		}
		item.Inputs = append(item.Inputs, fields...)
	}
	item.Compatible = anyCompatible && allRequiredCompatible
	slices.SortStableFunc(item.Inputs, func(a, b Input) int {
		if a.Location != b.Location {
			return strings.Compare(a.Location, b.Location)
		}
		return strings.Compare(a.Name, b.Name)
	})
	return item, nil
}

type parameterKey struct{ location, name string }

type parameterBlocker struct {
	key  parameterKey
	held Held
}

func inventoryParameters(refs *inventoryReferences, object map[string]any, source Source, version string) (map[parameterKey]Input, []parameterBlocker, error) {
	result := make(map[parameterKey]Input)
	var blockers []parameterBlocker
	value, has := object["parameters"]
	if !has {
		return result, nil, nil
	}
	values, ok := value.([]any)
	if !ok || len(values) > 8192-*refs.work {
		return nil, nil, errInventoryInput
	}
	*refs.work += len(values)
	for i, value := range values {
		declared := Source{source.File, fmt.Sprintf("%s/parameters/%d", source.Pointer, i)}
		startHolds := len(*refs.held)
		resolved, definition, trail, err := refs.resolve(value, declared, nil)
		parameter, ok := resolved.(map[string]any)
		if err != nil || !ok {
			return nil, nil, errInventoryInput
		}
		location, locationOK := parameter["in"].(string)
		name, nameOK := parameter["name"].(string)
		if !locationOK || !nameOK || location == "" || name == "" {
			return nil, nil, errInventoryInput
		}
		key := parameterKey{location, name}
		if location == "header" {
			key.name = strings.ToLower(name)
		}
		if _, found := result[key]; found {
			return nil, nil, errInventoryInput
		}
		required, validBool := parameter["required"].(bool)
		if _, explicit := parameter["required"]; explicit && !validBool || location == "path" && !required {
			return nil, nil, errInventoryInput
		}
		item := Input{Location: location, Name: name, Required: required, Source: declared, Definition: definition}
		if location == "header" && slices.Contains([]string{"accept", "content-type", "authorization"}, key.name) {
			reason := "OpenAPI ignores this header parameter. Remove the parameter declaration."
			item.IgnoredReason = &reason
		} else {
			schema := map[string]any{}
			if raw, hasSchema := parameter["schema"]; hasSchema {
				schema, _, _, err = refs.schema(raw, Source{definition.File, definition.Pointer + "/schema"}, trail, version)
				if err != nil {
					return nil, nil, err
				}
			}
			item.Compatible = len(*refs.held) == startHolds && scalarQuery(schema, parameter, location)
			switch {
			case !slices.Contains([]string{"path", "query", "header", "cookie"}, location):
				*refs.held = append(*refs.held, Held{Source: Source{source.File, definition.Pointer + "/in"}, Reason: "Unknown parameter location. Use path, query, header, or cookie."})
			case !item.Compatible && schema != nil:
				*refs.held = append(*refs.held, Held{Source: declared, Reason: scalarQueryHold})
			}
			for _, held := range (*refs.held)[startHolds:] {
				if required || strings.HasSuffix(held.Source.Pointer, "/required") {
					blockers = append(blockers, parameterBlocker{key, held})
					break
				}
			}
		}
		result[key] = item
	}
	return result, blockers, nil
}

func scalarQuery(schema, parameter map[string]any, location string) bool {
	style, hasStyle := parameter["style"]
	reserved, hasReserved := parameter["allowReserved"]
	_, hasContent := parameter["content"]
	kind, _ := schema["type"].(string)
	return location == "query" && slices.Contains([]string{"string", "integer", "number", "boolean"}, kind) &&
		(!hasStyle || style == "form") && (!hasReserved || reserved == false) && !hasContent
}

func shortID(prefix, input string) string {
	sum := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%s%x", prefix, sum[:16])
}

func identityString(s string) string {
	var quoted strings.Builder
	encoder := json.NewEncoder(&quoted)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(s)
	var ascii strings.Builder
	for _, r := range strings.TrimSuffix(quoted.String(), "\n") {
		switch {
		case r < 0x7f:
			ascii.WriteRune(r)
		case r <= 0xffff:
			fmt.Fprintf(&ascii, `\u%04x`, r)
		default:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&ascii, `\u%04x\u%04x`, hi, lo)
		}
	}
	return ascii.String()
}

func (r *Inventory) Select(ids []string) error {
	wanted := make(map[string]bool, len(ids))
	for _, id := range ids {
		if wanted[id] {
			return errors.New("duplicate selection ID")
		}
		wanted[id] = true
	}
	var selected []*Input
	for i := range r.Operations {
		op := &r.Operations[i]
		for j := range op.Inputs {
			input := &op.Inputs[j]
			if !wanted[input.ID] {
				continue
			}
			if !op.Compatible || !input.Compatible || input.IgnoredReason != nil {
				return errors.New("selected input is not compatible")
			}
			selected = append(selected, input)
			delete(wanted, input.ID)
		}
	}
	if len(wanted) != 0 {
		return errors.New("selection includes an unknown or stale input ID")
	}
	for _, input := range selected {
		input.Selected = true
	}
	return nil
}
