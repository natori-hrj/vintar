package discovery

import (
	"maps"
	"slices"
	"strings"
)

type bodyInventory struct {
	refs        *inventoryReferences
	operationID string
	version     string
}

func (b bodyInventory) inputs(raw any, declared Source) ([]Input, error) {
	*b.refs.held = append(*b.refs.held, Held{Source: declared, Reason: "Request bodies are outside the v1 query model. Review this body separately."})
	resolved, definition, trail, err := b.refs.resolve(raw, declared, nil)
	body, ok := resolved.(map[string]any)
	if err != nil || !ok {
		return nil, errInventoryInput
	}
	content, ok := body["content"].(map[string]any)
	if !ok {
		return nil, errInventoryInput
	}
	required, ok := body["required"].(bool)
	if _, explicit := body["required"]; explicit && !ok {
		return nil, errInventoryInput
	}
	var fields []Input
	for _, media := range slices.Sorted(maps.Keys(content)) {
		descriptor, ok := content[media].(map[string]any)
		if !ok || !b.consume() {
			return nil, errInventoryInput
		}
		site := Source{definition.File, definition.Pointer + "/content/" + escapeToken.Replace(media)}
		path := [][2]string{{"media", media}}
		fields = append(fields, b.field(media, required, declared, site, path))
		if schema, has := descriptor["schema"]; has {
			site.Pointer += "/schema"
			if err := b.schema(schema, site, media, "", false, path, trail, &fields); err != nil {
				return nil, err
			}
		}
	}
	return fields, nil
}

func (b bodyInventory) consume() bool {
	(*b.refs.work)++
	return *b.refs.work <= 8192
}

func (b bodyInventory) schema(raw any, declared Source, media, name string, required bool, path [][2]string, trail []string, fields *[]Input) error {
	if len(path)-1 > 48 || !b.consume() {
		return errInventoryInput
	}
	schema, definition, trail, err := b.refs.schema(raw, declared, trail, b.version)
	if err != nil {
		return err
	}
	if name != "" {
		*fields = append(*fields, b.field(media+"#"+name, required, declared, definition, path))
	}
	for _, key := range []string{"allOf", "anyOf", "oneOf", "additionalProperties", "$dynamicRef", "$id"} {
		if _, has := schema[key]; has {
			*b.refs.held = append(*b.refs.held, Held{Source: Source{definition.File, definition.Pointer + "/" + key}, Reason: "Body schema construct is unsupported. Review its declarations separately."})
		}
	}
	if _, has := schema["$id"]; has {
		return nil
	}
	if _, has := schema["$dynamicRef"]; has {
		return nil
	}
	var requiredNames []string
	if value, has := schema["required"]; has {
		names, ok := value.([]any)
		if !ok {
			return errInventoryInput
		}
		for _, value := range names {
			name, ok := value.(string)
			if !ok {
				return errInventoryInput
			}
			requiredNames = append(requiredNames, name)
		}
	}
	if value, has := schema["properties"]; has {
		props, ok := value.(map[string]any)
		if !ok {
			return errInventoryInput
		}
		for _, key := range slices.Sorted(maps.Keys(props)) {
			token := escapeToken.Replace(key)
			site := Source{definition.File, definition.Pointer + "/properties/" + token}
			if err := b.schema(props[key], site, media, name+"/"+token, slices.Contains(requiredNames, key), append(path, [2]string{"property", key}), trail, fields); err != nil {
				return err
			}
		}
	}
	if items, has := schema["items"]; has {
		site := Source{definition.File, definition.Pointer + "/items"}
		return b.schema(items, site, media, name+"/*", false, append(path, [2]string{"items", ""}), trail, fields)
	}
	return nil
}

func (b bodyInventory) field(name string, required bool, source, definition Source, path [][2]string) Input {
	tokens := make([]string, len(path))
	for i, part := range path {
		tokens[i] = "[" + identityString(part[0]) + ", " + identityString(part[1]) + "]"
	}
	id := shortID("input-", "["+identityString(b.operationID)+", \"body\", ["+strings.Join(tokens, ", ")+"]]")
	return Input{ID: id, Location: "body", Name: name, Required: required, Source: source, Definition: definition}
}
