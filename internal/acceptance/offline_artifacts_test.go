package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

type offlineArtifactGolden struct {
	Code   int             `json:"exit_code"`
	Text   string          `json:"stdout"`
	Stdout json.RawMessage `json:"stdout_json"`
	Stderr string          `json:"stderr"`
	Report json.RawMessage `json:"report_json"`
	Review json.RawMessage `json:"review_json"`
}

func offlineGolden(t *testing.T, root, name string) offlineArtifactGolden {
	t.Helper()
	var expected offlineArtifactGolden
	if err := json.Unmarshal(readFixture(t, root, "tests/golden/cli/"+name+".json"), &expected); err != nil {
		t.Fatal(err)
	}
	return expected
}

func writeOfflineFixture(t *testing.T, cwd, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(cwd, name), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func checkReviewDraftCLI(t *testing.T, root, binary string) {
	cwd := t.TempDir()
	writeOfflineFixture(t, cwd, "openapi.json", readFixture(t, root, "tests/fixtures/discovery/openapi30.json"))
	writeOfflineFixture(t, cwd, "selection.toml", []byte("version = 1\napproved = [\"input-24a9c3cf0c3d01709121ac0d09079903\"]\n"))
	export := runProduct(t, binary, cwd, "discover", "--spec", "openapi.json", "--selection", "selection.toml", "--drafts-dir", "drafts")
	if export.code != 0 {
		t.Fatalf("draft export: %+v", export)
	}
	draft := "drafts/case-24a9c3cf0c3d01709121ac0d09079903.draft.toml"
	args := []string{"review-draft", "--spec", "openapi.json", "--draft", draft, "--answers", "answers.json", "--output", "review.json"}
	const answer = `{"version":1,"expected_verdict":"not_detected","parameters":{"q":{"value":%s}}}`
	writeOfflineFixture(t, cwd, "answers.json", []byte(strings.Replace(answer, "%s", `"fixture-baseline"`, 1)))
	expected := offlineGolden(t, root, "review-draft/success")
	report := requireOfflineReview(t, binary, cwd, args, expected, expected.Report)
	if bytes.Contains(report, []byte("fixture-baseline")) {
		t.Fatal("review disclosed the baseline value")
	}
	originalDraft := readFixture(t, cwd, draft)
	writeOfflineFixture(t, cwd, draft, append(bytes.Clone(originalDraft), '\n'))
	stale := runProduct(t, binary, cwd, args...)
	if stale.code != 2 || stale.stdout != "" || !bytes.Equal(readFixture(t, cwd, "review.json"), report) {
		t.Fatalf("non-current draft did not fail without changing the artifact: %+v", stale)
	}
	writeOfflineFixture(t, cwd, draft, originalDraft)
	writeOfflineFixture(t, cwd, "answers.json", []byte(strings.Replace(answer, "%s", `"\ud800"`, 1)))
	surrogate := runProduct(t, binary, cwd, args...)
	if surrogate.code != 2 || surrogate.stdout != "" ||
		surrogate.stderr != "Error: Cannot read review answers. Supply a bounded UTF-8 JSON file with unique keys.\n" ||
		!bytes.Equal(readFixture(t, cwd, "review.json"), report) {
		t.Fatalf("invalid Unicode was accepted or changed the artifact: %+v", surrogate)
	}
	writeOfflineFixture(t, cwd, "answers.json", []byte(strings.Replace(answer, "%s", "null", 1)))
	got := runProduct(t, binary, cwd, args...)
	rejected := offlineGolden(t, root, "review-draft/null-baseline")
	_, guidance, _ := strings.Cut(rejected.Stderr, ": baseline")
	// The released diagnostic includes the input ID and parameter name.
	// Compare the error meaning and remediation without requiring that echo.
	if got.code != rejected.Code || got.stdout != "" || got.stderr != "Error: Baseline"+guidance ||
		!bytes.Equal(readFixture(t, cwd, "review.json"), report) {
		t.Fatalf("null review input did not fail without changing the artifact: %+v", got)
	}
}

func requireOfflineReview(t *testing.T, binary, cwd string, args []string, golden offlineArtifactGolden, want json.RawMessage) []byte {
	t.Helper()
	got := runProduct(t, binary, cwd, args...)
	if got.code != golden.Code || got.stderr != "" || !strings.HasSuffix(got.stdout, "\n") {
		t.Fatalf("review: %+v", got)
	}
	equivalentJSON(t, []byte(got.stdout), golden.Stdout)
	data := readFixture(t, cwd, "review.json")
	equivalentJSON(t, data, want)
	if repeat := runProduct(t, binary, cwd, args...); repeat != got ||
		!bytes.Equal(readFixture(t, cwd, "review.json"), data) {
		t.Fatal("identical review was not reusable with stable output")
	}
	writeOfflineFixture(t, cwd, "review.json", []byte("existing review"))
	rejected := runProduct(t, binary, cwd, args...)
	if rejected.code != 2 || rejected.stdout != "" ||
		string(readFixture(t, cwd, "review.json")) != "existing review" {
		t.Fatalf("different review was not preserved: %+v", rejected)
	}
	writeOfflineFixture(t, cwd, "review.json", data)
	// An input alias must remain intact even when it looks like a JSON output.
	answers := readFixture(t, cwd, "answers.json")
	if err := os.Link(filepath.Join(cwd, "answers.json"), filepath.Join(cwd, "answers-alias.json")); err != nil {
		t.Fatal(err)
	}
	other := slices.Clone(args)
	other[len(other)-1] = "answers-alias.json"
	if rejected := runProduct(t, binary, cwd, other...); rejected.code != 2 || rejected.stdout != "" ||
		!bytes.Equal(readFixture(t, cwd, "answers-alias.json"), answers) {
		t.Fatalf("review changed its input alias: %+v", rejected)
	}
	if runtime.GOOS != "windows" {
		if err := os.Mkdir(filepath.Join(cwd, "real"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(cwd, "linked")); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ output, forbidden string }{
			{"linked/escaped.json", "real/escaped.json"},
			{"linked/../escaped.json", "escaped.json"},
		} {
			other[len(other)-1] = tc.output
			rejected := runProduct(t, binary, cwd, other...)
			if _, err := os.Lstat(filepath.Join(cwd, tc.forbidden)); !os.IsNotExist(err) ||
				rejected.code != 2 || rejected.stdout != "" {
				t.Fatalf("review followed a linked output directory: %+v", rejected)
			}
		}
		other[len(other)-1] = "real/../parent-review.json"
		if allowed := runProduct(t, binary, cwd, other...); allowed != got ||
			!bytes.Equal(readFixture(t, cwd, "parent-review.json"), data) {
			t.Fatalf("review of a real parent traversal failed: %+v", allowed)
		}
	}
	return data
}

const postInventorySpec = `{"openapi":"3.1.2","paths":{"/items":{"post":{"operationId":"createItem","requestBody":{"content":{"application/json":{"schema":%s}}}}}}%s}`

func checkPostInventoryCLI(t *testing.T, root, binary string) {
	schemas := publishedSchemas(t, root)
	for _, tc := range []struct{ name, spec string }{
		{"success", postSpec(`{"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}`, "")},
		{"empty", `{"openapi":"3.1.2","paths":{}}`},
		{"external-ref", postSpec(`{"$ref":"external.json#/Item"}`, "")},
		{"cyclic-ref", postSpec(`{"$ref":"#/components/schemas/Node"}`, `,"components":{"schemas":{"Node":{"type":"object","properties":{"child":{"$ref":"#/components/schemas/Node"}}}}}`)},
		{"invalid-spec", "{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := t.TempDir()
			writeOfflineFixture(t, cwd, "openapi.json", []byte(tc.spec))
			expected := offlineGolden(t, root, "inventory-post-json/"+tc.name)
			got := runProduct(t, binary, cwd, "inventory-post-json", "--spec", "openapi.json", "--output", "inventory.json")
			if got.code != expected.Code || got.stdout != expected.Text || got.stderr != expected.Stderr {
				t.Fatalf("inventory: %+v", got)
			}
			path := filepath.Join(cwd, "inventory.json")
			if expected.Code != 0 {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("invalid spec published an artifact")
				}
				return
			}
			payload := readFixture(t, cwd, "inventory.json")
			equivalentJSON(t, payload, expected.Report)
			if err := schemas[inventoryV2].Validate(decodeSchemaJSON(t, "generated inventory", payload)); err != nil {
				t.Fatal(err)
			}
			writeOfflineFixture(t, cwd, "inventory.json", []byte("replace me"))
			repeat := runProduct(t, binary, cwd, "inventory-post-json", "--spec", "openapi.json", "--output", "inventory.json")
			if repeat != got || !bytes.Equal(payload, readFixture(t, cwd, "inventory.json")) {
				t.Fatal("inventory replacement did not reproduce the same artifact")
			}
			if err := os.Link(filepath.Join(cwd, "openapi.json"), filepath.Join(cwd, "alias.json")); err != nil {
				t.Fatal(err)
			}
			conflict := runProduct(t, binary, cwd, "inventory-post-json", "--spec", "openapi.json", "--output", "alias.json")
			if conflict.code != 2 || conflict.stdout != "" ||
				conflict.stderr != offlineGolden(t, root, "inventory-post-json/output-spec-conflict").Stderr ||
				string(readFixture(t, cwd, "alias.json")) != tc.spec {
				t.Fatalf("inventory changed its input alias: %+v", conflict)
			}
			if runtime.GOOS != "windows" {
				if err := os.Symlink("openapi.json", filepath.Join(cwd, "linked.json")); err != nil {
					t.Fatal(err)
				}
				rejected := runProduct(t, binary, cwd, "inventory-post-json", "--spec", "linked.json", "--output", "unused.json")
				if _, err := os.Lstat(filepath.Join(cwd, "unused.json")); !os.IsNotExist(err) || rejected.code != 2 || rejected.stdout != "" {
					t.Fatal("linked input was not safely rejected")
				}
			}
		})
	}
}

func postSpec(schema, extra string) string {
	return fmt.Sprintf(postInventorySpec, schema, extra)
}

func checkPostReviewCLI(t *testing.T, root, binary string) {
	cwd := t.TempDir()
	spec := strings.Replace(postSpec(`{"type":"object","properties":{"orders":{"type":"array","items":{"type":"object","properties":{"sku":{"type":"string"}}}}}}`, ""), `"operationId":"createItem",`, "", 1)
	writeOfflineFixture(t, cwd, "openapi.json", []byte(spec))
	got := runProduct(t, binary, cwd, "inventory-post-json", "--spec", "openapi.json", "--output", "inventory.json")
	if got.code != 0 {
		t.Fatalf("review inventory: %+v", got)
	}
	const sentinel = "PRIVATE-BODY-SENTINEL-74d9"
	const answers = `{"version":1,"identity_id":"reviewed-user","candidate_id":"post-json-candidate-5e0e940b7970259d433021a5897ed4ea","operation_definition_sha256":"268e7c17172e2d18d999782168cfd032a4b5d4eca1ad0c62c9fa5f7bb399059e","schema_pointer":"/paths/~1items/post/requestBody/content/application~1json/schema/properties/orders/items/properties/sku","schema_definition_pointer":"/paths/~1items/post/requestBody/content/application~1json/schema/properties/orders/items/properties/sku","baseline":{"value":{"orders":[{"sku":"` + sentinel + `"}]},"body_sha256":"8b672bf71f217f9211c2b86ac9a0ca4049ebbac956e13ffd2af8200cf5e953b2"},"concrete_pointer":"/orders/0/sku","operation_approved":true,"side_effect":{"class":"no_side_effect","confirmed":true},"environment":{"class":"isolated_test","confirmed":true}}`
	writeOfflineFixture(t, cwd, "answers.json", []byte(answers))
	args := []string{"review-post-json", "--spec", "openapi.json", "--inventory", "inventory.json", "--answers", "answers.json", "--output", "review.json"}
	expected := offlineGolden(t, root, "review-post-json/success")
	report := requireOfflineReview(t, binary, cwd, args, expected, expected.Review)
	if err := publishedSchemas(t, root)[reviewV2].Validate(decodeSchemaJSON(t, "generated review", report)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, from, to string }{
		{"digest-mismatch", "8b672bf71f217f9211c2b86ac9a0ca4049ebbac956e13ffd2af8200cf5e953b2", strings.Repeat("0", 64)},
		{"operation-unconfirmed", `"operation_approved":true`, `"operation_approved":false`},
		{"side-effect-unconfirmed", `"no_side_effect","confirmed":true`, `"no_side_effect","confirmed":false`},
		{"environment-unconfirmed", `"isolated_test","confirmed":true`, `"isolated_test","confirmed":false`},
		{"wildcard-pointer", "/orders/0/sku", "/orders/*/sku"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writeOfflineFixture(t, cwd, "answers.json", []byte(strings.Replace(answers, tc.from, tc.to, 1)))
			got := runProduct(t, binary, cwd, args...)
			rejected := offlineGolden(t, root, "review-post-json/"+tc.name)
			if got.code != rejected.Code || got.stdout != "" || got.stderr != rejected.Stderr ||
				!bytes.Equal(readFixture(t, cwd, "review.json"), report) {
				t.Fatalf("invalid review did not preserve the artifact: %+v", got)
			}
		})
	}
	if bytes.Contains(report, []byte(sentinel)) {
		t.Fatal("review disclosed the baseline body")
	}
	writeOfflineFixture(t, cwd, "answers.json", []byte(answers))
	inventory := readFixture(t, cwd, "inventory.json")
	altered := bytes.Replace(inventory, []byte(`"operation_pointer": "/paths/~1items/post"`),
		[]byte(`"operation_pointer": "/paths/~1other/post"`), 1)
	if bytes.Equal(inventory, altered) {
		t.Fatal("test did not alter the selected operation's provenance")
	}
	writeOfflineFixture(t, cwd, "inventory.json", altered)
	stale := runProduct(t, binary, cwd, args...)
	if stale.code != 2 || stale.stdout != "" || !bytes.Equal(readFixture(t, cwd, "review.json"), report) {
		t.Fatalf("non-current inventory did not fail without changing the artifact: %+v", stale)
	}
}
