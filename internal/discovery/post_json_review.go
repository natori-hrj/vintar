package discovery

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/natori-hrj/vintar/internal/strictjson"
)

const (
	postReviewLimit   = 262144
	postBaselineLimit = 1 << 20 // v0.6.0's limit on the normalized JsonBody input
)

var (
	errPostStaleInventory = errors.New("POST JSON inventory is stale or was edited. Regenerate it with vintar inventory-post-json and review the new candidate.")
	errPostInventoryMatch = errors.New("POST JSON inventory does not match the spec. Regenerate it with vintar inventory-post-json.")
	errPostChanged        = errors.New("the operation definition changed since review; review side effects again")
	errPostReviewJSON     = errors.New("Cannot read JSON input. Supply a bounded UTF-8 JSON file with unique keys.")
	errPostAnswers        = errors.New("Review answers are invalid. Use version 1 and only the documented review decisions.")
	errPostBaseline       = errors.New("Baseline decision is invalid. Supply value or one explicit bundled example pointer plus body_sha256.")
	errPostBaselineDigest = errors.New("Baseline body digest does not match. Recompute body_sha256 from the complete canonical JSON body and confirm it before reviewing.")
	errPostExample        = errors.New(`Baseline pointer is not an allowed request-body example. Use requestBody.content["application/json"].example or requestBody.content["application/json"].examples[name].value.`)
	errPostConcrete       = errors.New("Concrete JSON Pointer is invalid. Use the candidate pattern with each array wildcard replaced by an explicit index.")
	errPostIndex          = errors.New("Concrete JSON Pointer has an invalid array selection. Use a canonical non-negative decimal index.")
	errPostLeaf           = errors.New("Concrete JSON Pointer does not select an existing leaf. Use an explicit index and an existing string field.")

	postIdentityLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	postEnvLabel      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

// BuildPostJSONReview produces only redacted review metadata. The recorded
// confirmations are assertions from the answers, not execution authority.
func BuildPostJSONReview(specJSON []byte, source string, inventoryJSON, answersJSON []byte) (report []byte, candidateID string, err error) {
	return buildPostJSONReview(context.Background(), specJSON, "", source, inventoryJSON, answersJSON)
}

// BuildPostJSONReviewContext reviews a candidate against a JSON or YAML spec.
func BuildPostJSONReviewContext(ctx context.Context, spec []byte, source string, inventoryJSON, answersJSON []byte) (report []byte, candidateID string, err error) {
	return buildPostJSONReview(ctx, spec, source, source, inventoryJSON, answersJSON)
}

func buildPostJSONReview(ctx context.Context, spec []byte, formatSource, source string, inventoryJSON, answersJSON []byte) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	supplied, err := strictjson.Parse(inventoryJSON)
	if err != nil || len(answersJSON) > postReviewLimit {
		return nil, "", errPostReviewJSON
	}
	root, ok := supplied.(map[string]any)
	if !ok || root["schema_version"] != json.Number("2") || root["report_type"] != postInventoryType {
		return nil, "", errPostStaleInventory
	}
	answerValue, err := strictjson.Parse(answersJSON)
	if err != nil {
		return nil, "", errPostReviewJSON
	}
	answer, _ := answerValue.(map[string]any)
	if !postExactKeys(answer, "version", "candidate_id", "identity_id", "operation_definition_sha256",
		"schema_pointer", "schema_definition_pointer", "baseline", "concrete_pointer", "operation_approved",
		"side_effect", "environment") || answer["version"] != json.Number("1") {
		return nil, "", errPostAnswers
	}
	id, ok := answer["candidate_id"].(string)
	if !ok {
		return nil, "", errPostAnswers
	}
	inventory, d, err := analyzePostSpec(ctx, spec, formatSource)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, ErrPostDefinitionLimit) {
			return nil, "", err
		}
		return nil, "", errPostStaleInventory
	}
	operation, field, candidate, err := matchPostReviewCandidate(inventory, id)
	if err != nil {
		return nil, "", err
	}
	if answer["operation_definition_sha256"] != candidate.Digest {
		return nil, "", errPostChanged
	}
	if !matchingSuppliedPostReview(root, operation, field, candidate) ||
		answer["schema_pointer"] != field.Schema || answer["schema_definition_pointer"] != field.Definition {
		return nil, "", errPostInventoryMatch
	}
	identity, ok := answer["identity_id"].(string)
	if !ok || !postIdentityLabel.MatchString(identity) {
		return nil, "", errors.New("Identity label is invalid. Name one explicit runtime identity using a bounded symbolic label.")
	}
	environment, err := postReviewConfirmations(answer)
	if err != nil {
		return nil, "", err
	}
	baseline, body, err := d.reviewBaseline(operation.Body, source, answer["baseline"], answersJSON)
	if err != nil {
		return nil, "", err
	}
	concrete, ok := answer["concrete_pointer"].(string)
	if !ok {
		return nil, "", errPostConcrete
	}
	if err := validatePostReviewLeaf(field, concrete, body); err != nil {
		return nil, "", err
	}
	fieldReport := map[string]any{
		"json_pointer_pattern": field.Pointer, "concrete_json_pointer": concrete,
		"schema_pointer": field.Schema, "schema_definition_pointer": field.Definition,
		"types": field.Types,
	}
	if len(field.Stars) != 0 {
		fieldReport["literal_star_positions"] = field.Stars
	}
	report, err := marshalPostArtifact(map[string]any{
		"schema_version": 2, "report_type": "post_json_discovery_review", "candidate_id": id, "identity_id": identity,
		"operation": map[string]any{"approved": true, "method": "POST", "path": operation.Path,
			"operation_pointer": operation.Operation, "request_body_pointer": operation.Body,
			"operation_definition_sha256": candidate.Digest},
		"field": fieldReport, "baseline": baseline,
		"side_effect": map[string]any{"class": "no_side_effect", "confirmed": true},
		"environment": map[string]any{"class": environment, "confirmed": true},
	}, postReviewLimit)
	if err != nil {
		return nil, "", err
	}
	return report, id, nil
}

// Match the selected claim to the current spec. The rest of the inventory
// may describe other operations, and does not authorize or affect this review.
func matchingSuppliedPostReview(root map[string]any, operation postOperation, field postField, candidate postCandidate) bool {
	operations, ok := root["operations"].([]any)
	if !ok {
		return false
	}
	matches := 0
	for _, rawOperation := range operations {
		row, ok := rawOperation.(map[string]any)
		if !ok {
			return false
		}
		claims, ok := row["review_candidates"].([]any)
		if !ok {
			return false
		}
		for _, rawClaim := range claims {
			claim, _ := rawClaim.(map[string]any)
			if claim["candidate_id"] != candidate.ID {
				continue
			}
			matches++
			if !postExactKeys(claim, "candidate_id", "approval", "operation_definition_sha256") ||
				claim["approval"] != candidate.Status || claim["operation_definition_sha256"] != candidate.Digest ||
				row["path"] != operation.Path || row["operation_pointer"] != operation.Operation ||
				row["request_body_pointer"] != operation.Body || !matchingSuppliedPostField(row["fields"], field) {
				return false
			}
		}
	}
	return matches == 1
}

func matchingSuppliedPostField(value any, field postField) bool {
	fields, ok := value.([]any)
	if !ok {
		return false
	}
	matches := 0
	for _, rawField := range fields {
		row, _ := rawField.(map[string]any)
		if row["json_pointer"] != field.Pointer || row["schema_pointer"] != field.Schema {
			continue
		}
		rawStars, present := row["literal_star_positions"]
		stars, ok := rawStars.([]any)
		if (present && !ok) || len(stars) != len(field.Stars) {
			continue
		}
		valid := true
		for i, index := range field.Stars {
			if stars[i] != json.Number(strconv.Itoa(index)) {
				valid = false
				break
			}
		}
		if valid {
			matches++
			if row["schema_definition_pointer"] != field.Definition {
				return false
			}
		}
	}
	return matches == 1
}

func matchPostReviewCandidate(inventory postInventory, id string) (postOperation, postField, postCandidate, error) {
	var selected postOperation
	var candidate postCandidate
	for _, operation := range inventory.Operations {
		for _, c := range operation.Candidates {
			if c.ID != id {
				continue
			}
			if candidate.ID != "" {
				return postOperation{}, postField{}, postCandidate{}, errPostInventoryMatch
			}
			selected, candidate = operation, c
		}
	}
	if candidate.ID == "" {
		return postOperation{}, postField{}, postCandidate{}, errPostInventoryMatch
	}
	for _, field := range selected.Fields {
		if !slices.Equal(field.Types, []string{"string"}) {
			continue
		}
		actual, err := postCandidateID(selected.Path, field)
		if err != nil {
			return postOperation{}, postField{}, postCandidate{}, err
		}
		if actual == candidate.ID {
			return selected, field, candidate, nil
		}
	}
	return postOperation{}, postField{}, postCandidate{}, errPostInventoryMatch
}

func postExactKeys(object map[string]any, keys ...string) bool {
	if len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, has := object[key]; !has {
			return false
		}
	}
	return true
}

func postTrue(value any, label string) error {
	if value != true {
		return fmt.Errorf("%s must be JSON true. Review and explicitly confirm this decision.", label)
	}
	return nil
}

func postReviewConfirmations(answer map[string]any) (string, error) {
	if err := postTrue(answer["operation_approved"], "operation_approved"); err != nil {
		return "", err
	}
	sideEffect, _ := answer["side_effect"].(map[string]any)
	if !postExactKeys(sideEffect, "class", "confirmed") {
		return "", errors.New("Side-effect decision is invalid. Explicitly confirm no_side_effect.")
	}
	if sideEffect["class"] != "no_side_effect" {
		return "", errors.New("POST side effects are not approved. Use no_side_effect only after explicit review; mutating operations are not supported.")
	}
	if err := postTrue(sideEffect["confirmed"], "side_effect.confirmed"); err != nil {
		return "", err
	}
	environment, _ := answer["environment"].(map[string]any)
	if !postExactKeys(environment, "class", "confirmed") {
		return "", errors.New("Environment decision is invalid. Name and explicitly confirm an isolated test environment class.")
	}
	class, ok := environment["class"].(string)
	if !ok || !postEnvLabel.MatchString(class) {
		return "", errors.New("Environment class is invalid. Use a lowercase bounded alias for an isolated test environment.")
	}
	return class, postTrue(environment["confirmed"], "environment.confirmed")
}

func (d *postDocument) reviewBaseline(media, source string, raw any, answers []byte) (map[string]any, any, error) {
	baseline, _ := raw.(map[string]any)
	var value, provenance any = nil, "reviewer"
	var bodyValue any
	switch {
	case postExactKeys(baseline, "value", "body_sha256"):
		value = baseline["value"]
		// Hash the original value token, already validated by strictjson,
		// to preserve lone surrogates as well as signed zero and float types.
		var tokens struct {
			Baseline map[string]json.RawMessage `json:"baseline"`
		}
		if err := json.Unmarshal(answers, &tokens); err != nil {
			return nil, nil, errPostBaseline
		}
		parsed, err := strictjson.Parse(tokens.Baseline["value"])
		if err != nil {
			return nil, nil, errPostBaseline
		}
		bodyValue = parsed
	case postExactKeys(baseline, "pointer", "body_sha256"):
		pointer, ok := baseline["pointer"].(string)
		if !ok {
			return nil, nil, errPostExample
		}
		if _, ok := postPointerTokens(pointer); !ok {
			return nil, nil, errPostExample
		}
		value, ok = d.reviewExample(media, pointer)
		if !ok || source == "" || strings.ContainsAny(source, "\\\x00") || !utf8.ValidString(source) {
			return nil, nil, errPostExample
		}
		provenance = Source{File: path.Base(source), Pointer: pointer}
		bodyValue = value
	default:
		return nil, nil, errPostBaseline
	}
	digest, err := postBaselineDigest(d.definitions.ctx, bodyValue)
	if err != nil {
		return nil, nil, err
	}
	if baseline["body_sha256"] != digest {
		return nil, nil, errPostBaselineDigest
	}
	return map[string]any{"source": provenance, "body_sha256": digest}, value, nil
}

func postBaselineDigest(ctx context.Context, value any) (string, error) {
	sum := sha256.New()
	remaining := postBaselineLimit
	dst := bufio.NewWriterSize(postDigestWriter{ctx, sum, &remaining, errPostBaseline}, postDigestBuffer)
	if err := strictjson.NewEncoder(dst, nil).Value(value); err != nil {
		return "", err
	}
	if err := dst.Flush(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sum.Sum(nil)), nil
}

func (d *postDocument) reviewExample(media, chosen string) (any, bool) {
	raw, _, err := lookupPointerFragment(d.root, url.PathEscape(media))
	if err != nil {
		return nil, false
	}
	node, _ := raw.(map[string]any)
	if chosen == postChild(media, "example") {
		value, ok := node["example"]
		return value, ok
	}
	examples, _ := node["examples"].(map[string]any)
	refs := postDocument{root: d.root, targets: d.targets}
	for _, name := range slices.Sorted(maps.Keys(examples)) {
		site := postChild(postChild(media, "examples"), name)
		// Use an independent bounded reference traversal for the examples.
		value, definition, _, err := refs.resolve(examples[name], site, nil, nil)
		if err != nil {
			continue
		}
		example, _ := value.(map[string]any)
		body, exists := example["value"]
		_, external := example["externalValue"]
		if exists && !external && (chosen == postChild(site, "value") || chosen == postChild(definition, "value")) {
			return body, true
		}
	}
	return nil, false
}

func postPointerTokens(pointer string) ([]string, bool) {
	if pointer == "" {
		return nil, true
	}
	if pointer[0] != '/' {
		return nil, false
	}
	tokens := strings.Split(pointer[1:], "/")
	for i, token := range tokens {
		for j := 0; j < len(token); j++ {
			if token[j] == '~' {
				j++
				if j == len(token) || (token[j] != '0' && token[j] != '1') {
					return nil, false
				}
			}
		}
		tokens[i] = unescapeToken.Replace(token)
	}
	return tokens, true
}

func validatePostReviewLeaf(field postField, concrete string, value any) error {
	pattern, validPattern := postPointerTokens(field.Pointer)
	tokens, validConcrete := postPointerTokens(concrete)
	if !validPattern || !validConcrete {
		return errPostConcrete
	}
	if len(pattern) != len(tokens) {
		return errors.New("Concrete JSON Pointer does not match the candidate. Replace each array wildcard with an explicit index.")
	}
	for i, expected := range pattern {
		if expected == "*" && !slices.Contains(field.Stars, i) {
			if !canonicalDecimal(tokens[i]) {
				return errPostIndex
			}
		} else if expected != tokens[i] {
			return errors.New("Concrete JSON Pointer does not match the candidate. Change only explicit array indexes.")
		}
	}
	for i, expected := range pattern {
		token := tokens[i]
		if expected == "*" && !slices.Contains(field.Stars, i) {
			array, ok := value.([]any)
			if !ok {
				return errors.New("The candidate pointer pattern requires a JSON array at the wildcard position. Supply a baseline body with an array there.")
			}
			index, err := strconv.Atoi(token)
			if err != nil || index >= len(array) {
				return errPostLeaf
			}
			value = array[index]
			continue
		}
		var exists bool
		switch node := value.(type) {
		case map[string]any:
			value, exists = node[token]
		case strictjson.SurrogateObject:
			value, exists = node.UTF8[token]
		default:
			return errors.New("The candidate property requires a JSON object at its parent pointer.")
		}
		if !exists {
			return errPostLeaf
		}
	}
	switch value.(type) {
	case string, strictjson.SurrogateString:
		return nil
	case []any, map[string]any, strictjson.SurrogateObject:
		return errPostLeaf
	default:
		return errors.New("Reviewed JSON Pointer does not select a string. Supply a baseline whose selected field is a JSON string.")
	}
}
