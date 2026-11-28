package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/natori-hrj/vintar/internal/discovery"
)

func TestPostJSONResourceFailureDoesNotPublish(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) string {
		t.Helper()
		filename := filepath.Join(dir, name)
		if err := os.WriteFile(filename, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		return filename
	}
	var spec strings.Builder
	spec.WriteString(`{"openapi":"3.1.2","components":{"schemas":{"Shared":{"type":"string","description":"`)
	spec.WriteString(strings.Repeat("a", 950_000))
	spec.WriteString(`"}}},"paths":{`)
	for i := range 20 {
		if i > 0 {
			spec.WriteByte(',')
		}
		fmt.Fprintf(&spec, `"/op-%d":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Shared"}}}}}}`, i)
	}
	spec.WriteString("}}")
	specPath := write("openapi.json", spec.String())
	inventory := write("inventory.json", `{"schema_version":2,"report_type":"openapi_post_json_inventory"}`)
	// Only the input shape is examined before recomputing the current spec.
	answer, err := json.Marshal(map[string]any{
		"version": 1, "candidate_id": "synthetic", "identity_id": "test",
		"operation_definition_sha256": "", "schema_pointer": "",
		"schema_definition_pointer": "", "baseline": nil, "concrete_pointer": "",
		"operation_approved": true, "side_effect": nil, "environment": nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	answers := write("answers.json", string(answer))
	for _, command := range []string{"inventory-post-json", "review-post-json"} {
		t.Run(command, func(t *testing.T) {
			output := filepath.Join(dir, command+".json")
			args := []string{command, "--spec", specPath, "--output", output}
			if command == "review-post-json" {
				args = append(args, "--inventory", inventory, "--answers", answers)
			}
			check := func(ctx context.Context, wantCode int, message string) {
				t.Helper()
				var stdout, stderr bytes.Buffer
				if code := Run(ctx, args, &stdout, &stderr); code != wantCode ||
					stdout.Len() != 0 || !strings.Contains(stderr.String(), message) {
					t.Fatalf("exit %d, stdout=%q, stderr=%q", code, &stdout, &stderr)
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatalf("output exists or could not be inspected: %v", err)
				}
			}
			check(t.Context(), 2, discovery.ErrPostDefinitionLimit.Error())

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			check(&cancelAtCheck{Context: ctx, cancel: cancel, remaining: 180}, 130, "interrupted")
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("unexpected files after rejected commands: %v, %v", entries, err)
	}
}

// Cancel deterministically while the first operation is being hashed.
type cancelAtCheck struct {
	context.Context
	cancel    context.CancelFunc
	remaining int
}

func (c *cancelAtCheck) Err() error {
	c.remaining--
	if c.remaining == 0 {
		c.cancel()
	}
	return c.Context.Err()
}
