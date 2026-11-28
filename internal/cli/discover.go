package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/natori-hrj/vintar/internal/discovery"
	"github.com/pelletier/go-toml/v2"
)

func runDiscover(ctx context.Context, args arguments, stdout, stderr io.Writer) int {
	spec := args.value("spec")
	if args.has("drafts-dir") && discoveryDraftSpecOutsideCWD(spec) {
		return diagnostic(stderr, 2, "Spec is outside the current working directory. Run from a directory that contains the spec.")
	}
	data, specInfo, err := readDiscoveryFile(spec)
	if err != nil {
		return diagnostic(stderr, 2, "invalid OpenAPI spec. Check the local file format, declarations, references, and limits.")
	}
	switch strings.ToLower(filepath.Ext(spec)) {
	case ".yaml", ".yml":
		data, err = discovery.DecodeYAML(data)
	case ".json":
	default:
		err = errors.New("unsupported spec format")
	}
	inventory, inventoryErr := discovery.BuildInventory(data, filepath.ToSlash(spec))
	if err != nil || inventoryErr != nil {
		return diagnostic(stderr, 2, "invalid OpenAPI spec. Check the local file format, declarations, references, and limits.")
	}
	inputs := []os.FileInfo{specInfo}
	var approved []string
	if args.has("selection") {
		selection, info, err := readDiscoveryFile(args.value("selection"))
		if err != nil {
			return diagnostic(stderr, 2, "Cannot read selection. Supply a bounded local TOML file.")
		}
		approved, err = parseDiscoverySelection(selection)
		if err == nil {
			err = inventory.Select(approved)
		}
		if err != nil {
			return diagnostic(stderr, 2, err.Error())
		}
		inputs = append(inputs, info)
	}
	if ctx.Err() != nil {
		return diagnostic(stderr, 130, "discovery was interrupted")
	}
	if args.has("drafts-dir") {
		return runDiscoveryDrafts(ctx, args.value("drafts-dir"), spec, inventory, inputs, stdout, stderr)
	}
	report, err := json.MarshalIndent(inventory, "", "  ")
	if err == nil {
		err = publishDiscoveryReport(ctx, args.value("output"), append(report, '\n'), inputs)
	}
	if ctx.Err() != nil {
		return diagnostic(stderr, 130, "discovery was interrupted")
	}
	if err != nil {
		return diagnostic(stderr, 2, err.Error())
	}
	ignored := 0
	for _, operation := range inventory.Operations {
		for _, input := range operation.Inputs {
			if input.IgnoredReason != nil {
				ignored++
			}
		}
	}
	return writeText(stdout, stderr, fmt.Sprintf(
		"{\"held\": %d, \"ignored\": %d, \"operations\": %d, \"report_type\": \"discovery_summary\", \"schema_version\": 1, \"selected\": %d}\n",
		len(inventory.Held), ignored, len(inventory.Operations), len(approved),
	), 0)
}

// Draft export checks containment before validating the spec or selection.
// Resolve symlinks in path order (including before "..") and tolerate missing
// components so an absent spec inside cwd still gets the usual spec diagnostic.
func discoveryDraftSpecOutsideCWD(spec string) bool {
	cwd, err := os.Getwd()
	if err != nil {
		return false
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		return false
	}
	pending, resolved := "", cwd
	const sep = string(filepath.Separator)
	start := func(path string) {
		pending = filepath.FromSlash(path)
		if filepath.IsAbs(pending) {
			volume := filepath.VolumeName(pending)
			resolved, pending = volume+sep, pending[len(volume):]
		}
	}
	start(spec)
	for links := 0; pending != ""; {
		component, rest, _ := strings.Cut(pending, sep)
		pending = rest
		switch component {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, component)
		info, err := os.Lstat(next)
		if errors.Is(err, os.ErrNotExist) || err == nil && info.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}
		if err != nil || links >= 255 {
			return false // Leave unreadable paths and loops to the spec diagnostic.
		}
		target, err := os.Readlink(next)
		if err != nil {
			return false
		}
		links++
		start(target)
		if rest != "" {
			pending += sep + rest
		}
	}
	rel, err := filepath.Rel(cwd, resolved)
	return err != nil || !filepath.IsLocal(rel)
}

func readDiscoveryFile(path string) ([]byte, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > 1<<20 {
		return nil, nil, errors.New("input must be a bounded local file")
	}
	f, err := openDiscoveryInput(path)
	if err != nil {
		return nil, nil, errors.New("input could not be opened")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return nil, nil, errors.New("input changed or is not regular")
	}
	value, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(value) > 1<<20 {
		return nil, nil, errors.New("input exceeded its read limit")
	}
	return value, info, nil
}

func parseDiscoverySelection(value []byte) ([]string, error) {
	var selection map[string]any
	if !utf8.Valid(value) || toml.Unmarshal(value, &selection) != nil {
		return nil, errors.New("Invalid selection TOML. Use version = 1 and an approved list of inventory input IDs.")
	}
	_, hasVersion := selection["version"]
	_, hasApproved := selection["approved"]
	if len(selection) != 2 || !hasVersion || !hasApproved {
		return nil, errors.New("Invalid selection keys. Use only version and approved.")
	}
	version, _ := selection["version"].(int64)
	raw, ok := selection["approved"].([]any)
	if version != 1 || !ok {
		return nil, errors.New("Invalid selection schema. Set version = 1 and approved to an array of input IDs.")
	}
	selected := make([]string, 0, len(raw))
	for _, value := range raw {
		id, ok := value.(string)
		if !ok || len(id) != 38 || !strings.HasPrefix(id, "input-") || strings.Trim(id[6:], "0123456789abcdef") != "" {
			return nil, errors.New("Invalid input ID. Copy its ID from the current inventory.")
		}
		selected = append(selected, id)
	}
	return selected, nil
}

func publishDiscoveryReport(ctx context.Context, path string, report []byte, inputs []os.FileInfo) error {
	failed := errors.New("cannot write the discovery report. Choose a writable output path.")
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return failed
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return failed
	}
	defer root.Close()
	dest := filepath.Base(path)
	if err := checkDiscoveryDestination(root, dest, inputs); err != nil {
		return err
	}
	tmp := ".vintar-inventory-" + rand.Text()
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return failed
	}
	defer root.Remove(tmp)
	_, writeErr := f.Write(report)
	if err := f.Close(); err != nil || writeErr != nil {
		return failed
	}
	if err := checkDiscoveryDestination(root, dest, inputs); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := root.Rename(tmp, dest); err != nil {
		return failed
	}
	return nil
}

func checkDiscoveryDestination(root *os.Root, dest string, inputs []os.FileInfo) error {
	info, err := root.Stat(dest)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("cannot write the discovery report. Choose a writable output path.")
	}
	for _, input := range inputs {
		if os.SameFile(info, input) {
			return errDiscoveryOutputConflict
		}
	}
	return nil
}
