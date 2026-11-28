package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/natori-hrj/vintar/internal/discovery"
)

const (
	maxOfflineSpecBytes = 1 << 20
	maxDraftBytes       = 64 << 10
	maxPostReportBytes  = 2 << 20
	maxPostReviewBytes  = 256 << 10
)

var (
	errOfflineInput            = errors.New("cannot read a bounded regular input file")
	errOfflineOutputDirectory  = errors.New("Draft directory traverses a symlink or non-directory. Choose a real directory.")
	errDiscoveryOutputConflict = errors.New("Output conflicts with the spec or selection. Choose a separate report path.")
)

type offlineInput struct {
	data []byte
	info os.FileInfo
}

func readOfflineInput(path string, limit int64) (offlineInput, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return offlineInput{}, errOfflineInput
	}
	file, err := openOfflineInput(path)
	if err != nil {
		return offlineInput{}, errOfflineInput
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !sameOfflineInput(before, opened) {
		return offlineInput{}, errOfflineInput
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != opened.Size() {
		return offlineInput{}, errOfflineInput
	}
	after, err := file.Stat()
	if err != nil || !sameOfflineInput(opened, after) {
		return offlineInput{}, errOfflineInput
	}
	linked, err := os.Lstat(path)
	if err != nil || !sameOfflineInput(opened, linked) {
		return offlineInput{}, errOfflineInput
	}
	return offlineInput{data, opened}, nil
}

func sameOfflineInput(a, b os.FileInfo) bool {
	return b.Mode().IsRegular() && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func readOfflineSpec(path string, decodeYAML bool) (offlineInput, error) {
	spec, err := readOfflineInput(path, maxOfflineSpecBytes)
	if err != nil {
		return offlineInput{}, err
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		if decodeYAML {
			spec.data, err = discovery.DecodeYAML(spec.data)
		}
	case ".json":
	default:
		err = errOfflineInput
	}
	return spec, err
}

func runPostJSONInventory(ctx context.Context, args arguments, stdout, stderr io.Writer) int {
	const failed = "invalid or unreadable OpenAPI spec. Check the local file format, declarations, references, and limits, then try again."
	const interrupted = "POST JSON inventory was interrupted. Rerun to regenerate the report."
	source := args.value("spec")
	spec, err := readOfflineSpec(source, false)
	if ctx.Err() != nil {
		return diagnostic(stderr, 130, interrupted)
	}
	if err != nil {
		return diagnostic(stderr, 2, failed)
	}
	report, summary, err := discovery.BuildPostJSONInventoryContext(ctx, spec.data, filepath.ToSlash(source))
	if ctx.Err() != nil {
		return diagnostic(stderr, 130, interrupted)
	}
	if errors.Is(err, discovery.ErrPostArtifactSize) {
		return diagnostic(stderr, 2, "The POST JSON inventory exceeds the report size limit. Split the OpenAPI spec into smaller specs and run the inventory for each.")
	}
	if errors.Is(err, discovery.ErrPostDefinitionLimit) {
		return diagnostic(stderr, 2, err.Error())
	}
	if err != nil {
		return diagnostic(stderr, 2, failed)
	}
	err = publishDiscoveryReport(ctx, args.value("output"), report, []os.FileInfo{spec.info})
	if ctx.Err() != nil {
		return diagnostic(stderr, 130, interrupted)
	}
	if err != nil {
		if errors.Is(err, errDiscoveryOutputConflict) {
			return diagnostic(stderr, 2, "Output conflicts with the spec. Choose a separate report path.")
		}
		return diagnostic(stderr, 2, "cannot write the POST JSON inventory. Choose a writable output path separate from the spec.")
	}
	return writeText(stdout, stderr, strings.TrimSuffix(summary, "\n")+"\n", 0)
}

func runOfflineReview(ctx context.Context, args arguments, stdout, stderr io.Writer, post bool) int {
	pathArg, reportType, idKey := "draft", "discovery_draft_review_summary", "input_id"
	failed := "cannot complete offline review. Check the local spec, draft, answers, and writable output path."
	interrupted := "review interrupted. Rerun the command to finish writing the report."
	artifactLimit, answerLimit := int64(maxDraftBytes), int64(maxOfflineSpecBytes)
	if post {
		pathArg, reportType, idKey = "inventory", "post_json_discovery_review_summary", "candidate_id"
		failed = "cannot complete offline POST JSON review. Check the local spec, current inventory, answers, and writable output path."
		interrupted = "POST JSON review was interrupted. Rerun to regenerate the review artifact."
		artifactLimit, answerLimit = maxPostReportBytes, maxPostReviewBytes
	}
	specPath := args.value("spec")
	label := filepath.ToSlash(specPath)
	if !post && discoveryDraftSpecOutsideCWD(specPath) {
		return offlineReviewFailure(ctx, stderr, interrupted, "Spec is outside the current working directory. Run from a directory containing the spec.")
	}
	spec, err := readOfflineSpec(specPath, !post)
	if err != nil {
		if !post {
			failed = "Cannot inventory the spec. Check its format, declarations, and references, then rerun discovery."
		}
		return offlineReviewFailure(ctx, stderr, interrupted, failed)
	}
	if !post {
		label, err = draftSource(specPath)
		if err != nil {
			return offlineReviewFailure(ctx, stderr, interrupted, failed)
		}
	}
	artifact, err := readOfflineInput(args.value(pathArg), artifactLimit)
	if err != nil {
		return offlineReviewFailure(ctx, stderr, interrupted, failed)
	}
	answers, err := readOfflineInput(args.value("answers"), answerLimit)
	if err != nil {
		return offlineReviewFailure(ctx, stderr, interrupted, failed)
	}
	var report []byte
	var id string
	if post {
		report, id, err = discovery.BuildPostJSONReviewContext(ctx, spec.data, label, artifact.data, answers.data)
	} else {
		report, id, err = discovery.BuildDraftReview(spec.data, label, artifact.data, answers.data)
	}
	if errors.Is(err, discovery.ErrPostArtifactSize) {
		return offlineReviewFailure(ctx, stderr, interrupted, "POST JSON review exceeds its size limit. Shorten non-secret environment metadata.")
	}
	if err != nil {
		return offlineReviewFailure(ctx, stderr, interrupted, err.Error())
	}
	if ctx.Err() != nil {
		return diagnostic(stderr, 130, interrupted)
	}
	output := args.value("output")
	name := filepath.Base(output)
	if name == ".json" || filepath.Ext(name) != ".json" {
		return offlineReviewFailure(ctx, stderr, interrupted, "Review output requires a .json filename. Pass a JSON path to --output.")
	}
	err = publishOfflineReview(ctx, output, report, []os.FileInfo{spec.info, artifact.info, answers.info})
	if err != nil {
		if errors.Is(err, errOfflineOutputDirectory) {
			return offlineReviewFailure(ctx, stderr, interrupted, errOfflineOutputDirectory.Error())
		}
		// A conflicting output name is supplied by the caller and need not
		// be included in the diagnostic.
		return offlineReviewFailure(ctx, stderr, interrupted, "Cannot publish review. Use a separate writable JSON file.")
	}
	if ctx.Err() != nil {
		return diagnostic(stderr, 130, interrupted)
	}
	summary, _ := json.Marshal(map[string]any{
		"schema_version": 1, "report_type": reportType, idKey: id,
	})
	return writeText(stdout, stderr, string(summary)+"\n", 0)
}

func offlineReviewFailure(ctx context.Context, stderr io.Writer, interrupted, message string) int {
	if ctx.Err() != nil {
		return diagnostic(stderr, 130, interrupted)
	}
	return diagnostic(stderr, 2, message)
}

func publishOfflineReview(ctx context.Context, output string, report []byte, inputs []os.FileInfo) error {
	output = strings.TrimRightFunc(output, func(r rune) bool { return r <= 127 && os.IsPathSeparator(byte(r)) })
	parent, name := filepath.Split(output)
	root, err := openOfflineOutputDirectory(ctx, parent, true)
	if err != nil {
		return err
	}
	defer root.Close()
	return publishDraftsAtRoot(ctx, root, []string{name}, map[string][]byte{name: report}, inputs)
}

// Inspect existing raw path components before creating anything. Missing
// components are only materialized when create is true; the filesystem may
// reject a name at that point. A returned root is owned by the caller.
func openOfflineOutputDirectory(ctx context.Context, path string, create bool) (*os.Root, error) {
	// Do not use filepath.Abs, Join or Clean on the original path before
	// examining its components: each directory before ".." must be checked.
	if !filepath.IsAbs(path) {
		if filepath.VolumeName(path) != "" {
			return nil, errOfflineOutputDirectory
		}
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		path = cwd + string(filepath.Separator) + path
	}
	volume := filepath.VolumeName(path)
	anchor := volume + string(filepath.Separator)
	root, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, err
	}
	type frame struct {
		name string
		root *os.Root // nil for a directory that does not yet exist
	}
	frames := []frame{{root: root}}
	lastExisting := 0
	defer func() {
		for _, f := range frames {
			if f.root != nil {
				f.root.Close()
			}
		}
	}()
	for name := range strings.SplitSeq(filepath.ToSlash(path[len(volume):]), "/") {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch name {
		case "", ".":
			continue
		case "..":
			if last := len(frames) - 1; last > 0 {
				if root := frames[last].root; root != nil {
					root.Close()
					lastExisting--
				} else if create {
					// A missing parent makes the real lookup return ENOENT
					// before it reaches this name. Check whether the target
					// filesystem can represent the component before hiding
					// it with "..". Only name-length errors matter here:
					// an entry at the probe location is not this component.
					_, err := frames[lastExisting].root.Lstat(frames[last].name)
					if offlineNameTooLong(err) {
						return nil, err
					}
				}
				frames = frames[:last]
			}
			continue
		}
		next := frame{name: name}
		if parent := frames[len(frames)-1].root; parent != nil {
			opened, err := openOfflineOutputComponent(parent, name, false)
			if err != nil {
				return nil, err
			}
			next.root = opened
			if opened != nil {
				lastExisting = len(frames)
			}
		}
		frames = append(frames, next)
	}
	if !create {
		return nil, nil
	}
	// Only materialize missing components that survived "..", starting at
	// the last validated handle, without reopening it by its pathname.
	for i := 1; i < len(frames); i++ {
		if frames[i].root != nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		next, err := openOfflineOutputComponent(frames[i-1].root, frames[i].name, true)
		if err != nil {
			return nil, err
		}
		frames[i].root = next
	}
	last := &frames[len(frames)-1]
	result := last.root
	last.root = nil
	return result, nil
}

// Comparing the opened handle and the non-followed entry prevents a
// replacement from redirecting publication into a different directory.
func openOfflineOutputComponent(parent *os.Root, name string, create bool) (*os.Root, error) {
	before, err := parent.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			return nil, nil
		}
		if err := parent.Mkdir(name, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		before, err = parent.Lstat(name)
	}
	if offlineNameTooLong(err) {
		return nil, err
	}
	if err != nil || !ordinaryOfflineDirectory(before) {
		return nil, errOfflineOutputDirectory
	}
	next, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	opened, openErr := next.Stat(".")
	linked, linkErr := parent.Lstat(name)
	if openErr != nil || linkErr != nil || !ordinaryOfflineDirectory(opened) ||
		!ordinaryOfflineDirectory(linked) || !os.SameFile(before, opened) || !os.SameFile(before, linked) {
		next.Close()
		return nil, errOfflineOutputDirectory
	}
	return next, nil
}
