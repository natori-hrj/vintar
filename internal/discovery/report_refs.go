package discovery

import (
	"maps"
	"slices"
	"strings"
)

type referenceTarget struct {
	value   any
	pointer string
}

type inventoryReferences struct {
	root       map[string]any
	targets    map[string]referenceTarget
	held       *[]Held
	work       *int
	references int
}

func (r *inventoryReferences) resolve(value any, source Source, trail []string) (any, Source, []string, error) {
	for {
		node, ok := value.(map[string]any)
		if !ok {
			return value, source, trail, nil
		}
		ref, has := node["$ref"]
		if !has {
			return node, source, trail, nil
		}
		r.references++
		if r.references > 4096 || len(trail) >= 24 {
			return nil, Source{}, nil, errInventoryInput
		}
		text, ok := ref.(string)
		fragment, local := strings.CutPrefix(text, "#")
		if !ok || !local {
			return nil, Source{}, nil, errInventoryInput
		}
		target, cached := r.targets[text]
		if !cached {
			next, pointer, err := lookupPointerFragment(r.root, fragment)
			if err != nil {
				return nil, Source{}, nil, errInventoryInput
			}
			target = referenceTarget{next, pointer}
			r.targets[text] = target
		}
		if target.pointer == source.Pointer || slices.Contains(trail, target.pointer) {
			return nil, Source{}, nil, errInventoryInput
		}
		// Each traversal owns its trail so sibling schema references can be
		// visited independently.
		trail = append(trail[:len(trail):len(trail)], target.pointer)
		for _, key := range slices.Sorted(maps.Keys(node)) {
			switch key {
			case "$ref", "summary", "description":
				continue
			}
			if !r.hold(source, key, referenceSiblingHold) {
				return nil, Source{}, nil, errInventoryInput
			}
		}
		value, source.Pointer = target.value, target.pointer
	}
}

func (r *inventoryReferences) hold(source Source, key, reason string) bool {
	(*r.work)++
	if *r.work > 8192 {
		return false
	}
	source.Pointer += "/" + escapeToken.Replace(key)
	*r.held = append(*r.held, Held{Source: source, Reason: reason})
	return true
}

func (r *inventoryReferences) schema(raw any, source Source, trail []string, version string) (map[string]any, Source, []string, error) {
	value, definition, trail, err := r.resolve(raw, source, trail)
	if err != nil {
		return nil, Source{}, nil, err
	}
	if node, ok := value.(map[string]any); ok {
		return node, definition, trail, nil
	}
	if _, ok := value.(bool); ok && strings.HasPrefix(version, "3.1.") {
		*r.held = append(*r.held, Held{Source: source, Definition: &definition, Reason: booleanSchemaHold})
		return nil, definition, trail, nil
	}
	return nil, Source{}, nil, errInventoryInput
}
