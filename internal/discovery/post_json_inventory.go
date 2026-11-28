package discovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/natori-hrj/vintar/internal/strictjson"
)

const (
	postMaxReport     = 2 << 20 // Released writer limit; review input stays bounded by strictjson.
	postMaxReferences = 4096
	postMaxWork       = 8192
	postBodyBlock     = "request_body_case_generation_unsupported"
	postInventoryType = "openapi_post_json_inventory"
)

var (
	// ErrPostArtifactSize distinguishes a generated artifact above its writer limit.
	ErrPostArtifactSize = errors.New("generated POST JSON artifact exceeds its size limit")
	errPostInput        = errors.New("Invalid POST JSON inventory input. Supply a bounded OpenAPI 3.0 or 3.1 document with valid declarations.")
	errPostExternal     = errors.New("external_ref_unsupported")
	errPostRecursive    = errors.New("recursive_ref_unsupported")
	errPostRefLimit     = errors.New("reference_limit_exceeded")
	errPostWork         = errors.New("POST JSON inventory exceeds its work or size limit. Supply a smaller spec.")
)

type postCounts struct {
	Operations      int `json:"operations"`
	CaseGeneratable int `json:"case_generatable"`
	Fields          int `json:"fields"`
	Injectable      int `json:"injectable_fields"`
	Unsupported     int `json:"unsupported_inputs"`
	Diagnostics     int `json:"diagnostics"`
	WithoutJSON     int `json:"post_operations_without_application_json"`
}

type postInventory struct {
	SchemaVersion int             `json:"schema_version"`
	ReportType    string          `json:"report_type"`
	Counts        postCounts      `json:"counts"`
	Operations    []postOperation `json:"operations"`
}

type postOperation struct {
	Path        string           `json:"path"`
	OperationID *string          `json:"operation_id"`
	Operation   string           `json:"operation_pointer"`
	Body        string           `json:"request_body_pointer"`
	Generation  string           `json:"case_generation"`
	Reasons     []string         `json:"blocking_reasons"`
	Auth        postAuth         `json:"auth"`
	Fields      []postField      `json:"fields"`
	Diagnostics []postDiagnostic `json:"diagnostics"`
	Candidates  []postCandidate  `json:"review_candidates"`
}

type postField struct {
	Pointer    string   `json:"json_pointer"`
	Schema     string   `json:"schema_pointer"`
	Definition string   `json:"schema_definition_pointer"`
	Types      []string `json:"types"`
	Required   bool     `json:"required"`
	Stars      []int    `json:"literal_star_positions,omitempty"`
	Injectable bool     `json:"injectable"`
	Reasons    []string `json:"reasons"`
}

type postDiagnostic struct {
	Reason     string  `json:"reason"`
	Schema     string  `json:"schema_pointer"`
	Definition *string `json:"schema_definition_pointer"`
}

type postCandidate struct {
	ID     string `json:"candidate_id"`
	Status string `json:"approval"`
	Digest string `json:"operation_definition_sha256"`
}

type postScheme struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type postAlternative struct {
	Schemes []postScheme `json:"schemes"`
}

type postAuth struct {
	Source       string            `json:"source"`
	Public       bool              `json:"public"`
	Alternatives []postAlternative `json:"alternatives"`
}

type postDocument struct {
	root       map[string]any
	version    string
	targets    map[string]referenceTarget
	references int
	work       int
	metadata   int
}

// BuildPostJSONInventory describes declared POST JSON inputs without creating any
// requests or runnable cases. The v2 inventory has no source-file member.
func BuildPostJSONInventory(specJSON []byte, source string) (report []byte, summary string, err error) {
	inventory, _, err := analyzePostJSON(specJSON)
	if err != nil {
		return nil, "", err
	}
	report, err = marshalPostArtifact(inventory, postMaxReport)
	if err != nil {
		return nil, "", err
	}
	c := inventory.Counts
	return report, fmt.Sprintf("POST JSON inventory: %d operations; %d case-generatable; %d fields; %d injectable; %d diagnostics.\n",
		c.Operations, c.CaseGeneratable, c.Fields, c.Injectable, c.Diagnostics), nil
}

func analyzePostJSON(data []byte) (postInventory, *postDocument, error) {
	value, err := strictjson.Parse(data)
	if err != nil {
		return postInventory{}, nil, err
	}
	root, ok := value.(map[string]any)
	if !ok || !validDiscoveryDocument(root) {
		return postInventory{}, nil, errPostInput
	}
	version, _ := root["openapi"].(string)
	if len(version) <= 4 || !(strings.HasPrefix(version, "3.0.") || strings.HasPrefix(version, "3.1.")) ||
		strings.ContainsFunc(version[4:], func(r rune) bool { return r < '0' || r > '9' }) {
		return postInventory{}, nil, errPostInput
	}
	paths, ok := root["paths"].(map[string]any)
	if _, present := root["paths"]; !ok && (present || strings.HasPrefix(version, "3.0.")) {
		return postInventory{}, nil, errPostInput
	}
	d := &postDocument{root: root, version: version, targets: make(map[string]referenceTarget)}
	schemes, err := postSecuritySchemes(root)
	if err != nil {
		return postInventory{}, nil, err
	}
	out := postInventory{SchemaVersion: 2, ReportType: postInventoryType, Operations: []postOperation{}}
	for _, path := range slices.Sorted(maps.Keys(paths)) {
		if strings.HasPrefix(path, "x-") {
			continue
		}
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\\") {
			return postInventory{}, nil, errPostInput
		}
		item, without, err := d.operation(path, paths[path], schemes)
		if err != nil {
			return postInventory{}, nil, err
		}
		if without {
			out.Counts.WithoutJSON++
		}
		if item == nil {
			continue
		}
		out.Operations = append(out.Operations, *item)
		out.Counts.Fields += len(item.Fields)
		out.Counts.Diagnostics += len(item.Diagnostics)
	}
	out.Counts.Operations = len(out.Operations)
	out.Counts.Unsupported = out.Counts.Fields
	return out, d, nil
}

func postChild(pointer, token string) string {
	return pointer + "/" + escapeToken.Replace(token)
}

func (d *postDocument) target(ref string) (referenceTarget, error) {
	if target, ok := d.targets[ref]; ok {
		return target, nil
	}
	fragment, ok := strings.CutPrefix(ref, "#")
	if !ok {
		return referenceTarget{}, errPostExternal
	}
	decoded, err := url.PathUnescape(fragment)
	if err != nil || !utf8.ValidString(decoded) {
		return referenceTarget{}, errPostInput
	}
	if decoded != "" && !strings.HasPrefix(decoded, "/") {
		return referenceTarget{}, errPostExternal
	}
	value, pointer, err := lookupPointerFragment(d.root, fragment)
	if err != nil {
		return referenceTarget{}, errPostInput
	}
	target := referenceTarget{value: value, pointer: pointer}
	d.targets[ref] = target
	return target, nil
}

func (d *postDocument) resolve(value any, pointer string, trail []string, siblings func(string, string) error) (any, string, []string, error) {
	for {
		node, _ := value.(map[string]any)
		raw, has := node["$ref"]
		if !has {
			return value, pointer, trail, nil
		}
		if siblings != nil {
			for _, key := range slices.Sorted(maps.Keys(node)) {
				if key != "$ref" {
					if err := siblings(pointer, key); err != nil {
						return nil, "", nil, err
					}
				}
			}
		}
		d.references++
		if d.references > postMaxReferences || len(trail) >= 24 {
			return nil, "", nil, errPostRefLimit
		}
		ref, ok := raw.(string)
		if !ok || ref == "" {
			return nil, "", nil, errPostInput
		}
		target, err := d.target(ref)
		if err != nil {
			return nil, "", nil, err
		}
		if target.pointer == pointer || slices.Contains(trail, target.pointer) {
			return nil, "", nil, errPostRecursive
		}
		trail = append(trail[:len(trail):len(trail)], target.pointer)
		value, pointer = target.value, target.pointer
	}
}

func (d *postDocument) operation(path string, raw any, schemes map[string]postScheme) (*postOperation, bool, error) {
	value, pathPointer, pathTrail, err := d.resolve(raw, postChild("/paths", path), nil, nil)
	if err != nil {
		return nil, false, postDefinitionError(err)
	}
	pathItem, ok := value.(map[string]any)
	if !ok {
		return nil, false, errPostInput
	}
	raw, present := pathItem["post"]
	if !present {
		return nil, false, nil
	}
	op, ok := raw.(map[string]any)
	if !ok {
		return nil, false, errPostInput
	}
	raw, present = op["requestBody"]
	if !present {
		return nil, true, nil
	}
	pointer := postChild(pathPointer, "post")
	bodySite := postChild(pointer, "requestBody")
	item := &postOperation{
		Path: path, Operation: pointer, Body: bodySite, Generation: "unsupported",
		Reasons: []string{"post_method_unsupported", postBodyBlock},
		Fields:  []postField{}, Diagnostics: []postDiagnostic{}, Candidates: []postCandidate{},
	}
	bodyValue, bodyPointer, bodyTrail, err := d.resolve(raw, bodySite, pathTrail, nil)
	if err != nil {
		if !isPostRefDiagnostic(err) {
			return nil, false, err
		}
		if err := d.diagnostic(item, err.Error(), bodySite, nil); err != nil {
			return nil, false, err
		}
	} else {
		body, _ := bodyValue.(map[string]any)
		content, ok := body["content"].(map[string]any)
		if !ok {
			return nil, false, errPostInput
		}
		key := postJSONMedia(content)
		if key == "" {
			return nil, true, nil
		}
		item.Body = postChild(postChild(bodyPointer, "content"), key)
		media, ok := content[key].(map[string]any)
		if !ok {
			return nil, false, errPostInput
		}
		if schema, present := media["schema"]; present {
			required, valid := body["required"].(bool)
			if _, has := body["required"]; has && !valid {
				return nil, false, errPostInput
			}
			err = d.walkSchema(item, schema, postChild(item.Body, "schema"), bodyTrail, "", required, nil, 0)
		} else {
			err = d.diagnostic(item, "missing_schema", item.Body, nil)
		}
		if err != nil {
			return nil, false, err
		}
	}
	if id, present := op["operationId"]; present {
		text, ok := id.(string)
		if !ok || text == "" {
			return nil, false, errPostInput
		}
		if err := d.spendMetadata(text); err != nil {
			return nil, false, err
		}
		item.OperationID = &text
	}
	item.Auth, err = d.auth(op, schemes)
	if err != nil {
		return nil, false, err
	}
	if err := d.spendMetadata(path, pointer, item.Body); err != nil {
		return nil, false, err
	}
	slices.SortStableFunc(item.Fields, func(a, b postField) int {
		if cmp := strings.Compare(a.Pointer, b.Pointer); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Schema, b.Schema)
	})
	slices.SortFunc(item.Diagnostics, comparePostDiagnostics)
	item.Diagnostics = slices.CompactFunc(item.Diagnostics, func(a, b postDiagnostic) bool {
		return comparePostDiagnostics(a, b) == 0
	})
	if len(item.Diagnostics) == 0 {
		digest, err := d.operationDigest(op, pointer, pathItem, pathPointer, pathTrail)
		if err != nil {
			return nil, false, postDefinitionError(err)
		}
		for _, field := range item.Fields {
			if len(field.Types) != 1 || field.Types[0] != "string" {
				continue
			}
			id, err := postCandidateID(path, field)
			if err != nil {
				return nil, false, err
			}
			item.Candidates = append(item.Candidates, postCandidate{id, "unapproved", digest})
		}
		slices.SortFunc(item.Candidates, func(a, b postCandidate) int { return strings.Compare(a.ID, b.ID) })
	}
	return item, false, nil
}

func postJSONMedia(content map[string]any) string {
	if _, exact := content["application/json"]; exact {
		return "application/json"
	}
	for _, key := range slices.Sorted(maps.Keys(content)) {
		base, _, _ := strings.Cut(key, ";")
		if strings.ToLower(strings.TrimSpace(base)) == "application/json" {
			return key
		}
	}
	return ""
}

func isPostRefDiagnostic(err error) bool {
	return err == errPostExternal || err == errPostRecursive || err == errPostRefLimit
}

func postDefinitionError(err error) error {
	if isPostRefDiagnostic(err) {
		return errPostInput
	}
	return err
}

func comparePostDiagnostics(a, b postDiagnostic) int {
	if cmp := strings.Compare(a.Schema, b.Schema); cmp != 0 {
		return cmp
	}
	var x, y string
	if a.Definition != nil {
		x = *a.Definition
	}
	if b.Definition != nil {
		y = *b.Definition
	}
	if cmp := strings.Compare(x, y); cmp != 0 {
		return cmp
	}
	return strings.Compare(a.Reason, b.Reason)
}

func (d *postDocument) spendMetadata(values ...string) error {
	for _, s := range values {
		d.metadata += len(s)
		if d.metadata > postMaxReport {
			return errPostWork
		}
	}
	return nil
}

func (d *postDocument) diagnostic(item *postOperation, reason, schema string, definition *string) error {
	pointers := []string{reason, schema}
	if definition != nil {
		pointers = append(pointers, *definition)
	}
	if err := d.spendMetadata(pointers...); err != nil {
		return err
	}
	item.Diagnostics = append(item.Diagnostics, postDiagnostic{reason, schema, definition})
	return nil
}

var postSchemaReasons = map[string]string{
	"allOf": "all_of_unsupported", "anyOf": "any_of_unsupported", "oneOf": "one_of_unsupported",
	"additionalProperties": "additional_properties_unsupported", "$dynamicRef": "dynamic_ref_unsupported",
	"$id": "schema_id_scope_unsupported",
}

func (d *postDocument) walkSchema(item *postOperation, raw any, site string, trail []string, pointer string, required bool, stars []int, depth int) error {
	d.work++
	if d.work > postMaxWork || depth > 72 {
		return errPostWork
	}
	value, definition, trail, err := d.resolve(raw, site, trail, func(refSite, key string) error {
		annotation := key == "summary" || key == "description"
		if strings.HasPrefix(d.version, "3.1.") {
			annotation = annotation || slices.Contains([]string{
				"$comment", "default", "deprecated", "examples", "readOnly", "title", "writeOnly",
			}, key)
		}
		if annotation {
			return nil
		}
		return d.diagnostic(item, "reference_sibling_unsupported", postChild(refSite, key), nil)
	})
	if isPostRefDiagnostic(err) {
		return d.diagnostic(item, err.Error(), site, nil)
	}
	if err != nil {
		return err
	}
	if _, boolean := value.(bool); boolean && strings.HasPrefix(d.version, "3.1.") {
		return d.diagnostic(item, "boolean_schema_unsupported", site, &definition)
	}
	node, ok := value.(map[string]any)
	if !ok {
		return errPostInput
	}
	for _, key := range slices.Sorted(maps.Keys(postSchemaReasons)) {
		if _, has := node[key]; has {
			if err := d.diagnostic(item, postSchemaReasons[key], postChild(definition, key), nil); err != nil {
				return err
			}
		}
	}
	types, err := postSchemaTypes(node)
	if err != nil {
		return err
	}
	scalarRoot := pointer == "" && len(types) != 0 && !slices.Contains(types, "array") && !slices.Contains(types, "object")
	if pointer != "" || scalarRoot || len(types) > 1 {
		if err := d.spendMetadata(pointer, site, definition); err != nil {
			return err
		}
		item.Fields = append(item.Fields, postField{Pointer: pointer, Schema: site, Definition: definition,
			Types: types, Required: required, Stars: stars, Reasons: []string{postBodyBlock}})
	}
	_, hasID := node["$id"]
	_, hasDynamic := node["$dynamicRef"]
	if scalarRoot || hasID || hasDynamic {
		return nil
	}
	props, ok := node["properties"].(map[string]any)
	if _, has := node["properties"]; has && !ok {
		return errPostInput
	}
	requiredNames := map[string]bool{}
	if raw, has := node["required"]; has {
		list, ok := raw.([]any)
		if !ok {
			return errPostInput
		}
		for _, name := range list {
			name, ok := name.(string)
			if !ok {
				return errPostInput
			}
			requiredNames[name] = true
		}
	}
	for _, key := range slices.Sorted(maps.Keys(props)) {
		childStars := stars
		if key == "*" {
			childStars = append(stars[:len(stars):len(stars)], depth)
		}
		err := d.walkSchema(item, props[key], postChild(postChild(definition, "properties"), key),
			trail, postChild(pointer, key), requiredNames[key], childStars, depth+1)
		if err != nil {
			return err
		}
	}
	if child, present := node["items"]; present {
		return d.walkSchema(item, child, postChild(definition, "items"), trail, pointer+"/*", false, stars, depth+1)
	}
	return nil
}

func postSchemaTypes(node map[string]any) ([]string, error) {
	raw, present := node["type"]
	out := []string{}
	if !present {
		return out, nil
	}
	list, ok := raw.([]any)
	if _, stringType := raw.(string); stringType {
		list, ok = []any{raw}, true
	}
	if !ok || len(list) == 0 || len(list) > 7 {
		return nil, errPostInput
	}
	for _, typ := range list {
		text, ok := typ.(string)
		if !ok || !slices.Contains([]string{"array", "boolean", "integer", "null", "number", "object", "string"}, text) ||
			slices.Contains(out, text) {
			return nil, errPostInput
		}
		out = append(out, text)
	}
	slices.Sort(out)
	return out, nil
}

func postSecuritySchemes(root map[string]any) (map[string]postScheme, error) {
	components, ok := root["components"].(map[string]any)
	if _, has := root["components"]; has && !ok {
		return nil, errPostInput
	}
	schemes, ok := components["securitySchemes"].(map[string]any)
	if _, has := components["securitySchemes"]; has && !ok {
		return nil, errPostInput
	}
	out := make(map[string]postScheme, len(schemes))
	for name, raw := range schemes {
		scheme, _ := raw.(map[string]any)
		if _, has := scheme["$ref"]; has {
			return nil, errPostInput
		}
		kind, _ := scheme["type"].(string)
		if !slices.Contains([]string{"apiKey", "http", "oauth2", "openIdConnect", "mutualTLS"}, kind) {
			return nil, errPostInput
		}
		out[name] = postScheme{name, kind}
	}
	return out, nil
}

func (d *postDocument) auth(op map[string]any, schemes map[string]postScheme) (postAuth, error) {
	auth := postAuth{Source: "none", Public: true, Alternatives: []postAlternative{}}
	raw, has := op["security"]
	if has {
		auth.Source = "operation"
	} else if raw, has = d.root["security"]; has {
		auth.Source = "global"
	} else {
		return auth, nil
	}
	list, ok := raw.([]any)
	if !ok || len(list) > postMaxWork-d.work {
		return postAuth{}, errPostInput
	}
	d.work += len(list)
	auth.Public = len(list) == 0
	for _, raw := range list {
		requirement, ok := raw.(map[string]any)
		if !ok || len(requirement) > postMaxWork-d.work {
			return postAuth{}, errPostInput
		}
		d.work += len(requirement)
		alt := postAlternative{Schemes: []postScheme{}}
		for _, key := range slices.Sorted(maps.Keys(requirement)) {
			scheme, known := schemes[key]
			scopes, ok := requirement[key].([]any)
			if !known || !ok || len(scopes) > postMaxWork-d.work {
				return postAuth{}, errPostInput
			}
			d.work += len(scopes)
			for _, scope := range scopes {
				if _, ok := scope.(string); !ok {
					return postAuth{}, errPostInput
				}
			}
			if err := d.spendMetadata(key); err != nil {
				return postAuth{}, err
			}
			alt.Schemes = append(alt.Schemes, scheme)
		}
		auth.Public = auth.Public || len(alt.Schemes) == 0
		auth.Alternatives = append(auth.Alternatives, alt)
	}
	compare := func(a, b postAlternative) int {
		return slices.CompareFunc(a.Schemes, b.Schemes, func(x, y postScheme) int {
			return strings.Compare(x.Name, y.Name)
		})
	}
	slices.SortFunc(auth.Alternatives, compare)
	auth.Alternatives = slices.CompactFunc(auth.Alternatives, func(a, b postAlternative) bool { return compare(a, b) == 0 })
	return auth, nil
}

func postCandidateID(path string, field postField) (string, error) {
	identity := []any{"POST", path, field.Pointer}
	if len(field.Stars) != 0 {
		identity = append(identity, field.Stars)
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		return "", errPostInput
	}
	canonical, err := strictjson.Canonicalize(raw)
	if err != nil {
		return "", errPostWork
	}
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("post-json-candidate-%x", sum[:16]), nil
}

// marshalPostArtifact uses the reference writer's ASCII JSON and ordering.
func marshalPostArtifact(value any, limit int) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, errPostInput
	}
	// Convert only the internally generated report to maps so the writer
	// sorts members even when the Go inventory uses structs. This does not
	// impose the smaller strict input limit on the released output format.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var shaped any
	if err := decoder.Decode(&shaped); err != nil {
		return nil, errPostInput
	}
	report, err := encodeOfflineJSON(shaped)
	if err != nil {
		return nil, err
	}
	if len(report) > limit {
		return nil, ErrPostArtifactSize
	}
	return report, nil
}

type postDefinitionKind string

const (
	postOpaque       postDefinitionKind = ""
	postOperationDef postDefinitionKind = "operation"
	postPathDef      postDefinitionKind = "path item"
	postSchemaDef    postDefinitionKind = "schema"
	postParameterDef postDefinitionKind = "parameter"
	postBodyDef      postDefinitionKind = "request body"
	postMediaDef     postDefinitionKind = "media"
	postExampleDef   postDefinitionKind = "example"
	postEncodingDef  postDefinitionKind = "encoding"
	postResponseDef  postDefinitionKind = "response"
	postHeaderDef    postDefinitionKind = "header"
	postLinkDef      postDefinitionKind = "link"
	postCallbackDef  postDefinitionKind = "callback"
)

type postDefinitionShape struct {
	kind       postDefinitionKind
	collection byte // 'a': array, 'm': map, 'x': map with opaque extensions
}

// Resolve only positions that are reference or schema objects in OpenAPI.
// Instances and annotations (including an instance's literal "$ref") stay opaque.
var postDefinitionChildren = map[postDefinitionKind]map[string]postDefinitionShape{
	postOperationDef: {"parameters": {postParameterDef, 'a'}, "requestBody": {postBodyDef, 0},
		"responses": {postResponseDef, 'x'}, "callbacks": {postCallbackDef, 'm'}},
	postPathDef: {"parameters": {postParameterDef, 'a'}},
	postSchemaDef: {
		"properties": {postSchemaDef, 'm'}, "patternProperties": {postSchemaDef, 'm'},
		"dependentSchemas": {postSchemaDef, 'm'}, "$defs": {postSchemaDef, 'm'}, "definitions": {postSchemaDef, 'm'},
		"allOf": {postSchemaDef, 'a'}, "anyOf": {postSchemaDef, 'a'}, "oneOf": {postSchemaDef, 'a'}, "prefixItems": {postSchemaDef, 'a'},
		"items": {postSchemaDef, 0}, "additionalProperties": {postSchemaDef, 0}, "unevaluatedProperties": {postSchemaDef, 0},
		"contains": {postSchemaDef, 0}, "propertyNames": {postSchemaDef, 0}, "if": {postSchemaDef, 0}, "then": {postSchemaDef, 0},
		"else": {postSchemaDef, 0}, "not": {postSchemaDef, 0}, "unevaluatedItems": {postSchemaDef, 0},
	},
	postParameterDef: {"schema": {postSchemaDef, 0}, "content": {postMediaDef, 'm'}, "examples": {postExampleDef, 'm'}},
	postHeaderDef:    {"schema": {postSchemaDef, 0}, "content": {postMediaDef, 'm'}, "examples": {postExampleDef, 'm'}},
	postBodyDef:      {"content": {postMediaDef, 'm'}},
	postMediaDef:     {"schema": {postSchemaDef, 0}, "examples": {postExampleDef, 'm'}, "encoding": {postEncodingDef, 'm'}},
	postEncodingDef:  {"headers": {postHeaderDef, 'm'}},
	postResponseDef:  {"headers": {postHeaderDef, 'm'}, "content": {postMediaDef, 'm'}, "links": {postLinkDef, 'm'}},
}

type postDefinition struct {
	doc       *postDocument
	remaining int
}

func (d *postDocument) operationDigest(operation map[string]any, pointer string, pathItem map[string]any, pathPointer string, trail []string) (string, error) {
	b := postDefinition{doc: d, remaining: postMaxWork}
	op, err := b.value(operation, pointer, trail, postDefinitionShape{postOperationDef, 0}, 0)
	if err != nil {
		return "", err
	}
	params, has := pathItem["parameters"]
	if !has {
		params = []any{}
	}
	params, err = b.value(params, postChild(pathPointer, "parameters"), trail, postDefinitionShape{postParameterDef, 'a'}, 0)
	if err != nil {
		return "", err
	}
	servers, has := pathItem["servers"]
	if !has {
		servers = []any{}
	}
	extensions := map[string]any{}
	for _, k := range slices.Sorted(maps.Keys(pathItem)) {
		if strings.HasPrefix(strings.ToLower(k), "x-") {
			v := pathItem[k]
			if !strings.HasPrefix(k, "x-") {
				v, err = b.value(v, postChild(pathPointer, k), trail, postDefinitionShape{postPathDef, 0}, 0)
				if err != nil {
					return "", err
				}
			}
			extensions[k] = v
		}
	}
	return postDigest(map[string]any{"operation": op, "path_parameters": params,
		"path_servers": servers, "path_extensions": extensions})
}

func (b *postDefinition) value(raw any, pointer string, trail []string, shape postDefinitionShape, depth int) (any, error) {
	if shape.kind == postOpaque {
		return raw, nil
	}
	b.remaining--
	if b.remaining < 0 || depth > 72 {
		return nil, errPostWork
	}
	childShape := postDefinitionShape{kind: shape.kind}
	if shape.collection == 'a' {
		list, ok := raw.([]any)
		if !ok {
			return raw, nil
		}
		out := make([]any, len(list))
		for i, child := range list {
			var err error
			out[i], err = b.value(child, postChild(pointer, strconv.Itoa(i)), trail, childShape, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	node, ok := raw.(map[string]any)
	if !ok {
		return raw, nil
	}
	if shape.collection != 0 {
		out := make(map[string]any, len(node))
		for _, key := range slices.Sorted(maps.Keys(node)) {
			child := node[key]
			if shape.collection != 'x' || !strings.HasPrefix(key, "x-") {
				var err error
				child, err = b.value(child, postChild(pointer, key), trail, childShape, depth+1)
				if err != nil {
					return nil, err
				}
			}
			out[key] = child
		}
		return out, nil
	}
	ref, hasRef := node["$ref"]
	if shape.kind == postOperationDef {
		hasRef = false // an Operation Object is not a Reference Object
	}
	var resolved any
	if hasRef {
		text, ok := ref.(string)
		if !ok || text == "" {
			return nil, errPostInput
		}
		target, err := b.doc.target(text)
		if err != nil {
			return nil, err
		}
		if target.pointer == pointer || slices.Contains(trail, target.pointer) {
			if shape.kind != postSchemaDef {
				return nil, errPostRecursive
			}
			resolved = map[string]any{"$ref": "#" + target.pointer}
		} else {
			if len(trail) >= 24 {
				return nil, errPostRefLimit
			}
			next := append(trail[:len(trail):len(trail)], target.pointer)
			resolved, err = b.value(target.value, target.pointer, next, shape, depth+1)
			if err != nil {
				return nil, err
			}
		}
	}
	out := make(map[string]any, len(node))
	for _, key := range slices.Sorted(maps.Keys(node)) {
		if hasRef && key == "$ref" {
			continue
		}
		child := node[key]
		childShape := postDefinitionChildren[shape.kind][key]
		switch {
		case strings.HasPrefix(key, "x-"):
			childShape = postDefinitionShape{}
		case shape.kind == postPathDef && slices.Contains(methods[:], strings.ToLower(key)):
			childShape = postDefinitionShape{postOperationDef, 0}
		case shape.kind == postCallbackDef:
			childShape = postDefinitionShape{postPathDef, 0}
		}
		child, err := b.value(child, postChild(pointer, key), trail, childShape, depth+1)
		if err != nil {
			return nil, err
		}
		out[key] = child
	}
	if hasRef {
		return map[string]any{"$ref_target": resolved, "siblings": out}, nil
	}
	return out, nil
}

// postDigest hashes bounded assembled values without imposing the input
// limit on their ASCII representation or losing strictjson's number types.
func postDigest(value any) (string, error) {
	canonical, err := strictjson.CanonicalizeValue(value)
	if err != nil {
		return "", errPostWork
	}
	return fmt.Sprintf("%x", sha256.Sum256(canonical)), nil
}
