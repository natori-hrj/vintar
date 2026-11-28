package discovery

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/natori-hrj/vintar/internal/strictjson"
)

const (
	postDefinitionReferences = 16_384
	postDefinitionRefDepth   = 128
	postDefinitionBytes      = 16 << 20
	postDefinitionWork       = 32 << 20
	postDigestBuffer         = 8 << 10
)

var ErrPostDefinitionLimit = errors.New("POST JSON operation definitions exceed the resource limit. Split the spec or simplify shared references.")

// All operation digests in one inventory (including a review's recomputation)
// share the same budget. A use of a cached reference still consumes work.
type postDefinitionBudget struct {
	ctx        context.Context
	references int
	bytes      int
	work       int
}

func newPostDefinitionBudget(ctx context.Context) postDefinitionBudget {
	return postDefinitionBudget{ctx, postDefinitionReferences, postDefinitionBytes, postDefinitionWork}
}

func (b *postDefinitionBudget) spend(n int) error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	if n > b.work {
		return ErrPostDefinitionLimit
	}
	b.work -= n
	return nil
}

type postDigestWriter struct {
	ctx       context.Context
	dst       io.Writer
	remaining *int
	limit     error
}

func (w postDigestWriter) Write(p []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > *w.remaining {
		return 0, w.limit
	}
	n, err := w.dst.Write(p)
	*w.remaining -= n
	return n, err
}

type postDefinition struct {
	doc    *postDocument
	out    *strictjson.Encoder
	active map[string]bool
}

func (d *postDocument) operationDigest(operation map[string]any, pointer string, pathItem map[string]any, pathPointer string, trail []string) (string, error) {
	budget := &d.definitions
	sum := sha256.New()
	dst := bufio.NewWriterSize(postDigestWriter{budget.ctx, sum, &budget.bytes, ErrPostDefinitionLimit}, postDigestBuffer)
	out := strictjson.NewEncoder(dst, budget.spend)
	b := postDefinition{doc: d, out: out, active: make(map[string]bool, len(trail))}
	for _, p := range trail {
		if err := budget.spend(1 + len(p)); err != nil {
			return "", err
		}
		b.active[p] = true
	}
	keys := []string{"operation", "path_parameters", "path_servers", "path_extensions"}
	err := out.Object(keys, func(key string) error {
		switch key {
		case "operation":
			return b.value(operation, pointer, postDefinitionShape{postOperationDef, 0})
		case "path_parameters":
			if params, ok := pathItem["parameters"]; ok {
				return b.child(params, pathPointer, "parameters", postDefinitionShape{postParameterDef, 'a'})
			}
			return out.Value([]any{})
		case "path_servers":
			if servers, ok := pathItem["servers"]; ok {
				return out.Value(servers)
			}
			return out.Value([]any{})
		default: // path_extensions
			return out.FilteredMap(pathItem, postPathExtension, func(k string) error {
				shape := postDefinitionShape{postPathDef, 0}
				if strings.HasPrefix(k, "x-") {
					shape = postDefinitionShape{}
				}
				return b.child(pathItem[k], pathPointer, k, shape)
			})
		}
	})
	if err != nil {
		return "", err
	}
	if err := dst.Flush(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sum.Sum(nil)), nil
}

func postPathExtension(key string) bool {
	return strings.HasPrefix(key, "x-") || strings.HasPrefix(key, "X-")
}

func (b *postDefinition) child(raw any, pointer, key string, shape postDefinitionShape) error {
	if shape.kind == postOpaque {
		return b.out.Value(raw)
	}
	if err := b.doc.definitions.spend(len(pointer) + 2*len(key) + 1); err != nil {
		return err
	}
	return b.value(raw, postChild(pointer, key), shape)
}

func (b *postDefinition) value(raw any, pointer string, shape postDefinitionShape) error {
	if shape.collection == 'a' {
		list, ok := raw.([]any)
		if !ok {
			return b.out.Value(raw)
		}
		return b.out.Array(len(list), func(i int) error {
			return b.child(list[i], pointer, strconv.Itoa(i), postDefinitionShape{shape.kind, 0})
		})
	}
	node, ok := raw.(map[string]any)
	if !ok {
		return b.out.Value(raw)
	}
	if shape.collection != 0 {
		return b.out.Map(node, func(key string) error {
			if shape.collection == 'x' && strings.HasPrefix(key, "x-") {
				return b.out.Value(node[key])
			}
			return b.child(node[key], pointer, key, postDefinitionShape{shape.kind, 0})
		})
	}
	_, hasRef := node["$ref"]
	hasRef = hasRef && shape.kind != postOperationDef // Operation Objects are not Reference Objects.
	if !hasRef {
		return b.members(node, pointer, shape.kind, nil)
	}
	return b.out.Object([]string{"$ref_target", "siblings"}, func(key string) error {
		if key == "$ref_target" {
			return b.reference(node["$ref"], pointer, shape)
		}
		return b.members(node, pointer, shape.kind, func(k string) bool { return k != "$ref" })
	})
}

func (b *postDefinition) members(node map[string]any, pointer string, kind postDefinitionKind, include func(string) bool) error {
	return b.out.FilteredMap(node, include, func(key string) error {
		shape := postDefinitionChildren[kind][key]
		switch {
		case strings.HasPrefix(key, "x-"):
			shape = postDefinitionShape{}
		case kind == postPathDef && slices.Contains(methods[:], strings.ToLower(key)):
			shape = postDefinitionShape{postOperationDef, 0}
		case kind == postCallbackDef:
			shape = postDefinitionShape{postPathDef, 0}
		}
		return b.child(node[key], pointer, key, shape)
	})
}

func (b *postDefinition) reference(raw any, pointer string, shape postDefinitionShape) error {
	text, ok := raw.(string)
	if !ok || text == "" {
		return errPostInput
	}
	budget := &b.doc.definitions
	if budget.references == 0 {
		return ErrPostDefinitionLimit
	}
	budget.references--
	if err := budget.spend(1 + len(pointer) + 4*len(text)); err != nil {
		return err
	}
	target, err := b.doc.target(text)
	if err != nil {
		return err
	}
	if target.pointer == pointer || b.active[target.pointer] {
		if shape.kind != postSchemaDef {
			return errPostRecursive
		}
		return b.out.Object([]string{"$ref"}, func(string) error {
			return b.out.Value("#" + target.pointer)
		})
	}
	if len(b.active) >= postDefinitionRefDepth {
		return ErrPostDefinitionLimit
	}
	b.active[target.pointer] = true
	defer delete(b.active, target.pointer)
	return b.value(target.value, target.pointer, shape)
}
