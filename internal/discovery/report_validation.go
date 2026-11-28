package discovery

import "encoding/json"

// Count values rather than object keys. strictjson preserves lone UTF-16
// surrogates for other callers; they are not Unicode scalars in OpenAPI.
func validDiscoveryDocument(root map[string]any) bool {
	remaining := 8192
	var visit func(any) bool
	visit = func(value any) bool {
		remaining--
		if remaining < 0 {
			return false
		}
		switch x := value.(type) {
		case map[string]any:
			for _, child := range x {
				if !visit(child) {
					return false
				}
			}
		case []any:
			for _, child := range x {
				if !visit(child) {
					return false
				}
			}
		case bool, string, json.Number, nil:
		default:
			return false
		}
		return true
	}
	return visit(root)
}
