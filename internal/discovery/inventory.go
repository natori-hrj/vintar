// Package discovery inventories operations from offline OpenAPI JSON documents.
package discovery

import (
	"errors"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/natori-hrj/vintar/internal/strictjson"
)

// Operation identifies an operation under paths. Method is the lowercase
// OpenAPI key. Pointer is a JSON pointer to the operation's definition in the
// document, which may differ from its inventory Path when a path item uses $ref.
type Operation struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	Pointer string `json:"pointer"`
}

const maxPathItemRefs = 32

var (
	errDocument     = errors.New("OpenAPI document must be a JSON object")
	errVersion      = errors.New("OpenAPI version must be 3.0.x or 3.1.x")
	errPaths        = errors.New("OpenAPI paths must be an object with slash-prefixed path keys")
	errPathsAbsent  = errors.New("OpenAPI document without paths requires components or webhooks, each an object if present")
	errPathItem     = errors.New("OpenAPI path item has an invalid structure")
	errPathItemRef  = errors.New("OpenAPI path item reference must be a resolvable local JSON pointer")
	errPathItemLoop = errors.New("OpenAPI path item reference cycle")
	errPathItemHops = errors.New("OpenAPI path item reference chain exceeds 32 hops")

	methods       = [...]string{"delete", "get", "head", "options", "patch", "post", "put", "trace"}
	escapeToken   = strings.NewReplacer("~", "~0", "/", "~1")
	unescapeToken = strings.NewReplacer("~0", "~", "~1", "/")
)

// ListOperations returns the operations in lexicographic path, then method,
// order. It accepts bounded OpenAPI JSON with a 3.0.x or 3.1.x numeric version,
// and validates the inventoried structure, not the full OpenAPI schema.
// Only path item references are followed, and only within the input document.
// A referenced path item cannot also declare non-extension sibling fields.
func ListOperations(data []byte) ([]Operation, error) {
	value, err := strictjson.Parse(data)
	if err != nil {
		return nil, err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, errDocument
	}
	version, ok := root["openapi"].(string)
	if !ok || !supportedVersion(version) {
		return nil, errVersion
	}
	pathsValue, hasPaths := root["paths"]
	if !hasPaths && strings.HasPrefix(version, "3.1.") {
		// In 3.1, a document can describe only webhooks or components.
		hasOther := false
		for _, key := range [...]string{"webhooks", "components"} {
			if value, present := root[key]; present {
				if _, ok := value.(map[string]any); !ok {
					return nil, errPathsAbsent
				}
				hasOther = true
			}
		}
		if hasOther {
			return []Operation{}, nil
		}
		return nil, errPathsAbsent
	}
	paths, ok := pathsValue.(map[string]any)
	if !ok {
		return nil, errPaths
	}
	names := make([]string, 0, len(paths))
	for name := range paths {
		if strings.HasPrefix(name, "x-") {
			continue
		}
		if !strings.HasPrefix(name, "/") {
			return nil, errPaths
		}
		names = append(names, name)
	}
	sort.Strings(names)

	resolver := pathItemResolver{root: root, targets: make(map[string]*pathItem)}
	result := []Operation{}
	for _, path := range names {
		item, err := inspectPathItem(paths[path], "/paths/"+escapeToken.Replace(path))
		if err != nil {
			return nil, err
		}
		item, err = resolver.resolve(item)
		if err != nil {
			return nil, err
		}
		for _, operation := range item.operations {
			operation.Path = path
			result = append(result, operation)
		}
	}
	return result, nil
}

func supportedVersion(version string) bool {
	if !strings.HasPrefix(version, "3.0.") && !strings.HasPrefix(version, "3.1.") {
		return false
	}
	return canonicalDecimal(version[4:])
}

type pathItem struct {
	ref        string
	next       *pathItem
	operations []Operation // Shared with all paths that reference this item; Path is set on copy.
}

func inspectPathItem(value any, pointer string) (*pathItem, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errPathItem
	}
	item := &pathItem{}
	ref, hasRef := object["$ref"]
	for key, field := range object {
		if key == "$ref" || strings.HasPrefix(key, "x-") {
			continue
		}
		if hasRef {
			return nil, errPathItem
		}
		switch key {
		case "summary", "description":
			if _, ok := field.(string); !ok {
				return nil, errPathItem
			}
		case "servers", "parameters":
			if _, ok := field.([]any); !ok {
				return nil, errPathItem
			}
		default:
			if _, ok := field.(map[string]any); !ok || !slices.Contains(methods[:], key) {
				return nil, errPathItem
			}
		}
	}
	if hasRef {
		item.ref, ok = ref.(string)
		if !ok || item.ref == "" {
			return nil, errPathItemRef
		}
	}
	for _, method := range methods {
		if _, present := object[method]; present {
			item.operations = append(item.operations, Operation{
				Method: method, Pointer: pointer + "/" + escapeToken.Replace(method),
			})
		}
	}
	return item, nil
}

type pathItemResolver struct {
	root map[string]any

	// Cache inspected targets by reference spelling. A cached item also
	// retains its next hop so shared chains need not rehash long references.
	targets map[string]*pathItem
}

func (r *pathItemResolver) resolve(item *pathItem) (*pathItem, error) {
	if item.ref == "" {
		return item, nil
	}
	seen := make(map[*pathItem]bool)
	for hops := 0; item.ref != ""; hops++ {
		if seen[item] {
			return nil, errPathItemLoop
		}
		if hops == maxPathItemRefs {
			return nil, errPathItemHops
		}
		seen[item] = true
		if item.next == nil {
			target, ok := r.targets[item.ref]
			if !ok {
				value, pointer, err := lookupLocalPointer(r.root, item.ref)
				if err != nil {
					return nil, err
				}
				target, err = inspectPathItem(value, pointer)
				if err != nil {
					return nil, err
				}
				r.targets[item.ref] = target
			}
			item.next = target
		}
		item = item.next
	}
	return item, nil
}

func lookupLocalPointer(root map[string]any, ref string) (any, string, error) {
	if !strings.HasPrefix(ref, "#") {
		return nil, "", errPathItemRef
	}
	fragment := ref[1:]
	if fragment == "" {
		return nil, "", errPathItemRef
	}
	// Require a URI fragment: non-ASCII and characters outside RFC 3986's
	// fragment grammar must be percent-encoded.
	for i := 0; i < len(fragment); i++ {
		b := fragment[i]
		if !('a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' ||
			strings.ContainsRune("-._~!$&'()*+,;=:@/?%", rune(b))) {
			return nil, "", errPathItemRef
		}
	}
	return lookupPointerFragment(root, fragment)
}

func lookupPointerFragment(root map[string]any, fragment string) (any, string, error) {
	if fragment == "" {
		return root, "", nil
	}
	pointer, err := url.PathUnescape(fragment)
	if err != nil || !utf8.ValidString(pointer) || !strings.HasPrefix(pointer, "/") {
		return nil, "", errPathItemRef
	}
	var value any = root
	rest := pointer[1:]
	for {
		raw, next, more := strings.Cut(rest, "/")
		for i := 0; i < len(raw); i++ {
			if raw[i] == '~' {
				i++
				if i == len(raw) || (raw[i] != '0' && raw[i] != '1') {
					return nil, "", errPathItemRef
				}
			}
		}
		token := unescapeToken.Replace(raw)
		switch node := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = node[token]
			if !ok {
				return nil, "", errPathItemRef
			}
		case []any:
			if !canonicalDecimal(token) {
				return nil, "", errPathItemRef
			}
			index, err := strconv.Atoi(token)
			if err != nil || index >= len(node) {
				return nil, "", errPathItemRef
			}
			value = node[index]
		default:
			return nil, "", errPathItemRef
		}
		if !more {
			return value, pointer, nil
		}
		rest = next
	}
}

func canonicalDecimal(token string) bool {
	if token == "" || (len(token) > 1 && token[0] == '0') {
		return false
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return false
		}
	}
	return true
}
