package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"unicode/utf8"

	"github.com/natori-hrj/vintar/internal/strictjson"
	"go.yaml.in/yaml/v3"
)

const (
	maxYAMLBytes = 1 << 20
	maxYAMLDepth = 48
	maxYAMLNodes = 8192
)

var (
	errYAMLSize      = errors.New("YAML input exceeds 1048576 bytes. Use a smaller document.")
	errYAMLUTF8      = errors.New("YAML input is not valid UTF-8. Encode the document as UTF-8.")
	errYAMLSyntax    = errors.New("Invalid YAML. Supply one UTF-8 document with JSON-compatible values.")
	errYAMLEmpty     = errors.New("YAML is empty. Supply one document.")
	errYAMLMultiple  = errors.New("Multiple YAML documents are unsupported. Supply one document.")
	errYAMLDepth     = errors.New("YAML nesting exceeds 48. Use a flatter document.")
	errYAMLNodes     = errors.New("YAML document node limit exceeded. Use a smaller document.")
	errYAMLAnchor    = errors.New("YAML anchors are unsupported. Write the value explicitly.")
	errYAMLAlias     = errors.New("YAML aliases are unsupported. Write the value explicitly.")
	errYAMLTag       = errors.New("Explicit YAML tags are unsupported. Use JSON-compatible values.")
	errYAMLKey       = errors.New("Non-string YAML mapping key. Use a quoted string key.")
	errYAMLMerge     = errors.New("YAML merge keys are unsupported. Write the entries explicitly.")
	errYAMLDuplicate = errors.New("Duplicate YAML key. Keep one declaration.")
	errYAMLNumber    = errors.New("YAML number is too large or outside the finite range. Use a smaller number or quote it.")
	errYAMLEncoding  = errors.New("YAML value cannot be represented as JSON.")

	yamlJSONNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
)

// ListYAMLOperations inventories a restricted YAML OpenAPI document with the
// same OpenAPI validation, JSON bounds and ordering as ListOperations.
func ListYAMLOperations(data []byte) ([]Operation, error) {
	encoded, err := DecodeYAML(data)
	if err != nil {
		return nil, err
	}
	return ListOperations(encoded)
}

// DecodeYAML converts one restricted UTF-8 YAML document to deterministic JSON
// without resolving references or validating OpenAPI structure. It accepts at
// most 1 MiB of YAML, a value depth of 48 (root depth 0), and 8192 values
// (mapping keys are not counted). On error it returns no JSON.
func DecodeYAML(data []byte) ([]byte, error) {
	value, err := decodeYAML(data, false)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, errYAMLEncoding
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func decodeYAMLValue(data []byte) (any, error) {
	return decodeYAML(data, true)
}

func decodeYAML(data []byte, normalizeNumbers bool) (any, error) {
	if len(data) > maxYAMLBytes {
		return nil, errYAMLSize
	}
	if !utf8.Valid(data) {
		return nil, errYAMLUTF8
	}
	// Decode only into the parser's node tree, without expanding aliases or
	// constructing Go values from YAML map merges or inferred scalar tags.
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if err == io.EOF {
			return nil, errYAMLEmpty
		}
		// Do not expose input values from the YAML library's diagnostics.
		return nil, errYAMLSyntax
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, errYAMLSyntax
	}
	normalizer := yamlNormalizer{marks: indexYAMLMarks(data), normalizeNumbers: normalizeNumbers}
	value, err := normalizer.value(document.Content[0], 0)
	if err != nil {
		return nil, err
	}
	var next yaml.Node
	switch err := decoder.Decode(&next); err {
	case nil:
		return nil, errYAMLMultiple
	case io.EOF:
	default:
		return nil, errYAMLSyntax
	}

	return value, nil
}

type yamlNormalizer struct {
	marks            yamlSourceMarks
	nodes            int
	normalizeNumbers bool
}

func (n *yamlNormalizer) checkNode(node *yaml.Node) error {
	switch {
	case node.Kind == yaml.AliasNode:
		return errYAMLAlias
	case node.Anchor != "":
		return errYAMLAnchor
	case node.Style&yaml.TaggedStyle != 0 || n.marks.bangAt(node.Line, node.Column):
		return errYAMLTag
	default:
		return nil
	}
}

func (n *yamlNormalizer) value(node *yaml.Node, depth int) (any, error) {
	if depth > maxYAMLDepth {
		return nil, errYAMLDepth
	}
	n.nodes++
	if n.nodes > maxYAMLNodes {
		return nil, errYAMLNodes
	}
	if err := n.checkNode(node); err != nil {
		return nil, err
	}
	switch node.Kind {
	case yaml.ScalarNode:
		if !utf8.ValidString(node.Value) {
			return nil, errYAMLUTF8
		}
		if node.Style == 0 {
			switch node.Value {
			case "null":
				return nil, nil
			case "true":
				return true, nil
			case "false":
				return false, nil
			}
			if yamlJSONNumber.MatchString(node.Value) {
				// Share the strict JSON numeric limits, including for long
				// mantissas and exponents, but keep the JSON number spelling.
				value, err := strictjson.Parse([]byte(node.Value))
				if err != nil {
					return nil, errYAMLNumber
				}
				if n.normalizeNumbers {
					return value, nil
				}
				return json.Number(node.Value), nil
			}
		}
		return node.Value, nil
	case yaml.SequenceNode:
		items := make([]any, 0, min(len(node.Content), maxYAMLNodes-n.nodes))
		for _, child := range node.Content {
			item, err := n.value(child, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	case yaml.MappingNode:
		object := make(map[string]any, min(len(node.Content)/2, maxYAMLNodes-n.nodes))
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if err := n.checkNode(key); err != nil {
				return nil, err
			}
			if key.Kind != yaml.ScalarNode {
				return nil, errYAMLKey
			}
			if !utf8.ValidString(key.Value) {
				return nil, errYAMLUTF8
			}
			if key.Style == 0 {
				switch key.Value {
				case "<<":
					return nil, errYAMLMerge
				case "null", "true", "false":
					return nil, errYAMLKey
				}
				if yamlJSONNumber.MatchString(key.Value) {
					return nil, errYAMLKey
				}
			}
			if _, exists := object[key.Value]; exists {
				return nil, errYAMLDuplicate
			}
			item, err := n.value(node.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			object[key.Value] = item
		}
		return object, nil
	default:
		return nil, errYAMLSyntax
	}
}

// yaml.v3's node builder omits TaggedStyle for the non-specific tag "!". A
// node's start mark still points to its first token (including its tag, if
// given), so consult the original source there. The index uses one byte per
// rune to match the parser's columns, and the parser's YAML line breaks.
type yamlSourceMarks struct {
	columns []byte
	starts  []int
}

func indexYAMLMarks(data []byte) yamlSourceMarks {
	if bytes.IndexByte(data, '!') < 0 {
		return yamlSourceMarks{}
	}
	// The initial UTF-8 BOM is consumed before scanning starts.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	m := yamlSourceMarks{columns: make([]byte, 0, len(data)), starts: []int{0}}
	for len(data) > 0 {
		r, width := utf8.DecodeRune(data)
		data = data[width:]
		switch r {
		case '\r':
			if len(data) > 0 && data[0] == '\n' {
				data = data[1:]
			}
			fallthrough
		case '\n', '\u0085', '\u2028', '\u2029':
			m.starts = append(m.starts, len(m.columns))
		case '!':
			m.columns = append(m.columns, '!')
		default:
			m.columns = append(m.columns, 0)
		}
	}
	return m
}

func (m yamlSourceMarks) bangAt(line, column int) bool {
	if line < 1 || line > len(m.starts) || column < 1 {
		return false
	}
	end := len(m.columns)
	if line < len(m.starts) {
		end = m.starts[line]
	}
	pos := m.starts[line-1] + column - 1
	return pos < end && m.columns[pos] == '!'
}
