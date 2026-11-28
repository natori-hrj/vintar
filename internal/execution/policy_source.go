package execution

import (
	"errors"

	"github.com/natori-hrj/vintar/internal/execution/internal/policyfile"
)

// LoadRuntimePolicy reads only the operator configuration selected by lookup.
// Presence of inline JSON, even empty or invalid, prevents file fallback.
func LoadRuntimePolicy(lookup func(string) (string, bool)) (*RuntimePolicy, error) {
	if lookup == nil {
		return nil, errors.New("trusted runtime policy is required")
	}
	if inline, ok := lookup("VINTAR_RUNTIME_POLICY_JSON"); ok {
		return ParseRuntimePolicy([]byte(inline))
	}
	path, ok := lookup("VINTAR_RUNTIME_POLICY_FILE")
	if !ok {
		return nil, errors.New("trusted runtime policy is required")
	}
	if path == "" {
		return nil, errors.New("runtime policy file path is empty")
	}
	data, err := policyfile.Read(path, maxRuntimePolicyBytes)
	if err != nil {
		return nil, err
	}
	return ParseRuntimePolicy(data)
}
