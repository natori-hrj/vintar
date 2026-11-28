package discovery

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

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

var errInventoryInput = errors.New("unsupported or invalid OpenAPI inventory input")

// BuildInventory builds provenance and parameter metadata without constructing
// requests or supplying any test values.
func BuildInventory(data []byte, source string) (Inventory, error) {
	list, err := ListOperations(data)
	if err != nil || len(list) > 512 {
		return Inventory{}, errInventoryInput
	}
	value, err := strictjson.Parse(data)
	if err != nil {
		return Inventory{}, errInventoryInput
	}
	root, ok := value.(map[string]any)
	if !ok {
		return Inventory{}, errInventoryInput
	}
	out := Inventory{
		Version: root["openapi"].(string), Source: Source{File: source},
		SchemaVersion: 1, ReportType: "discovery_inventory",
		Operations: []InventoryOperation{}, Held: []Held{},
	}
	if _, has := root["webhooks"]; has {
		out.Held = append(out.Held, Held{Source: Source{source, "/webhooks"}, Reason: "Webhooks are outside the inventory model. Review them separately."})
	}
	work := 0
	for _, row := range list {
		if strings.HasPrefix(row.Path, "//") || strings.ContainsAny(row.Path, "?#\\") {
			return Inventory{}, errInventoryInput
		}
		definition := Source{source, row.Pointer}
		declaration := Source{source, "/paths/" + escapeToken.Replace(row.Path)}
		if declaration.Pointer+"/"+row.Method == row.Pointer {
			declaration = definition
		}
		container := row.Pointer[:strings.LastIndexByte(row.Pointer, '/')]
		pathItem, err := inventoryObject(root, container)
		if err != nil {
			return Inventory{}, err
		}
		operation, err := inventoryObject(root, row.Pointer)
		if err != nil {
			return Inventory{}, err
		}
		body, hasBody := operation["requestBody"]
		params, err := inventoryParameters(root, pathItem, Source{source, container}, &out.Held, &work)
		if err != nil {
			return Inventory{}, err
		}
		override, err := inventoryParameters(root, operation, definition, &out.Held, &work)
		if err != nil {
			return Inventory{}, err
		}
		var blocker *Held
		for key, input := range params {
			if _, replaced := override[key]; !replaced && input.Required && !input.Compatible && input.IgnoredReason == nil {
				held := Held{Source: input.Source, Reason: scalarQueryHold}
				if blocker == nil || held.Source.Pointer < blocker.Source.Pointer {
					blocker = &held
				}
			}
		}
		for key, input := range override {
			params[key] = input
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
			out.Held = append(out.Held, Held{Source: Source{source, row.Pointer + "/callbacks"}, Reason: "Callbacks are outside the inventory model. Review them separately."})
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
			inventoryBody := bodyInventory{root: root, held: &out.Held, work: &work, operationID: item.ID, version: out.Version}
			fields, err := inventoryBody.inputs(body, Source{source, row.Pointer + "/requestBody"})
			if err != nil {
				return Inventory{}, err
			}
			item.Inputs = append(item.Inputs, fields...)
		}
		item.Compatible = anyCompatible && allRequiredCompatible
		slices.SortFunc(item.Inputs, func(a, b Input) int {
			if a.Location != b.Location {
				return strings.Compare(a.Location, b.Location)
			}
			return strings.Compare(a.Name, b.Name)
		})
		out.Operations = append(out.Operations, item)
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
	out.Held = slices.Compact(out.Held)
	return out, nil
}

func inventoryObject(root map[string]any, pointer string) (map[string]any, error) {
	fragment := (&url.URL{Fragment: pointer}).EscapedFragment()
	value, _, err := lookupLocalPointer(root, "#"+fragment)
	object, ok := value.(map[string]any)
	if err != nil || !ok {
		return nil, errInventoryInput
	}
	return object, nil
}

type parameterKey struct{ location, name string }

func inventoryParameters(root, object map[string]any, source Source, held *[]Held, work *int) (map[parameterKey]Input, error) {
	result := make(map[parameterKey]Input)
	value, has := object["parameters"]
	if !has {
		return result, nil
	}
	values, ok := value.([]any)
	if !ok || len(values) > 8192-*work {
		return nil, errInventoryInput
	}
	*work += len(values)
	for i, value := range values {
		declared := Source{source.File, fmt.Sprintf("%s/parameters/%d", source.Pointer, i)}
		parameter, definition, err := resolveParameter(root, value, declared)
		if err != nil {
			return nil, err
		}
		location, locationOK := parameter["in"].(string)
		name, nameOK := parameter["name"].(string)
		if !locationOK || !nameOK || location == "" || name == "" {
			return nil, errInventoryInput
		}
		key := parameterKey{location, name}
		if location == "header" {
			key.name = strings.ToLower(name)
		}
		if _, found := result[key]; found {
			return nil, errInventoryInput
		}
		required, validBool := parameter["required"].(bool)
		if _, explicit := parameter["required"]; explicit && !validBool || location == "path" && !required {
			return nil, errInventoryInput
		}
		item := Input{Location: location, Name: name, Required: required, Source: declared, Definition: definition}
		if location == "header" && slices.Contains([]string{"accept", "content-type", "authorization"}, key.name) {
			reason := "OpenAPI ignores this header parameter. Remove the parameter declaration."
			item.IgnoredReason = &reason
		} else {
			compatible, err := scalarQuery(root, parameter, definition, location)
			if err != nil {
				return nil, err
			}
			item.Compatible = compatible
			switch {
			case !slices.Contains([]string{"path", "query", "header", "cookie"}, location):
				*held = append(*held, Held{Source: Source{source.File, definition.Pointer + "/in"}, Reason: "Unknown parameter location. Use path, query, header, or cookie."})
			case !compatible:
				*held = append(*held, Held{Source: declared, Reason: scalarQueryHold})
			}
		}
		result[key] = item
	}
	return result, nil
}

func resolveParameter(root map[string]any, value any, definition Source) (map[string]any, Source, error) {
	seen := map[string]bool{definition.Pointer: true}
	for i := 0; i <= 24; i++ {
		item, ok := value.(map[string]any)
		if !ok {
			break
		}
		ref, has := item["$ref"]
		if !has {
			return item, definition, nil
		}
		text, ok := ref.(string)
		if !ok || len(item) != 1 {
			break
		}
		next, pointer, err := lookupLocalPointer(root, text)
		if err != nil || seen[pointer] {
			break
		}
		seen[pointer] = true
		value, definition.Pointer = next, pointer
	}
	return nil, Source{}, errInventoryInput
}

func scalarQuery(root, parameter map[string]any, definition Source, location string) (bool, error) {
	value, has := parameter["schema"]
	if !has {
		return false, nil
	}
	schema, _, err := resolveParameter(root, value, Source{definition.File, definition.Pointer + "/schema"})
	if err != nil {
		return false, err
	}
	style, hasStyle := parameter["style"]
	reserved, hasReserved := parameter["allowReserved"]
	_, hasContent := parameter["content"]
	kind, _ := schema["type"].(string)
	return location == "query" && slices.Contains([]string{"string", "integer", "number", "boolean"}, kind) &&
		(!hasStyle || style == "form") && (!hasReserved || reserved == false) && !hasContent, nil
}

func shortID(prefix, input string) string {
	sum := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%s%x", prefix, sum[:16])
}

func identityString(s string) string {
	raw, _ := json.Marshal(s)
	encoded, _ := strictjson.Canonicalize(raw)
	return string(encoded)
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
