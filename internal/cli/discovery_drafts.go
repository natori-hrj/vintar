package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/natori-hrj/vintar/internal/discovery"
)

func draftSource(path string) (string, error) {
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(cwd, path)
	if err != nil || !filepath.IsLocal(rel) {
		return "", errors.New("Spec is outside the current working directory. Run from a directory that contains the spec.")
	}
	return filepath.ToSlash(rel), nil
}

func runDiscoveryDrafts(ctx context.Context, directory, spec string, inventory discovery.Inventory, inputs []os.FileInfo, stdout, stderr io.Writer) int {
	source, err := draftSource(spec)
	if err != nil {
		return diagnostic(stderr, 2, "Spec is outside the current working directory. Run from a directory that contains the spec.")
	}
	names := []string{}
	drafts := map[string][]byte{}
	for _, operation := range inventory.Operations {
		for _, input := range operation.Inputs {
			if input.Selected {
				id := "case-" + strings.TrimPrefix(input.ID, "input-")
				name := id + ".draft.toml"
				draft := discovery.EncodeDraft(source, operation, input)
				if len(draft) > 65536 {
					return diagnostic(stderr, 2, "Draft exceeds 64 KiB. Shorten the declarations and retry.")
				}
				names = append(names, name)
				drafts[name] = draft
			}
		}
	}
	slices.Sort(names)
	err = publishDiscoveryDrafts(ctx, directory, names, drafts, inputs)
	if ctx.Err() != nil {
		return diagnostic(stderr, 130, "discovery was interrupted")
	}
	if err != nil {
		return diagnostic(stderr, 2, err.Error())
	}
	quoted := make([]string, len(names))
	for i, name := range names {
		quoted[i] = draftString(name)
	}
	return writeText(stdout, stderr, `{"drafts": [`+strings.Join(quoted, ", ")+`], "report_type": "discovery_draft_summary", "schema_version": 1}`+"\n", 0)
}

func draftString(value string) string {
	var b strings.Builder
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return strings.ReplaceAll(strings.TrimSuffix(b.String(), "\n"), "\x7f", `\u007f`)
}

func publishDiscoveryDrafts(ctx context.Context, directory string, names []string, drafts map[string][]byte, inputs []os.FileInfo) error {
	badDirectory := errors.New("Draft directory traverses a symlink or non-directory. Choose a real directory.")
	failed := errors.New("cannot write review drafts. Choose a writable output path.")
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return failed
	}
	for dir := absolute; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err == nil && !info.IsDir() || err != nil && !errors.Is(err, os.ErrNotExist) {
			return badDirectory
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	if len(names) == 0 {
		return nil
	}
	if err := os.MkdirAll(absolute, 0755); err != nil {
		return failed
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return failed
	}
	defer root.Close()
	return publishDraftsAtRoot(ctx, root, names, drafts, inputs)
}

func publishDraftsAtRoot(ctx context.Context, root *os.Root, names []string, drafts map[string][]byte, inputs []os.FileInfo) error {
	failed := errors.New("cannot write review drafts. Choose a writable output path.")
	var pending []string
	for _, name := range names {
		info, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			pending = append(pending, name)
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			return failed
		}
		for _, input := range inputs {
			if os.SameFile(info, input) {
				return errors.New("Draft path aliases an input file.")
			}
		}
		if info.Size() == int64(len(drafts[name])) && identicalDraft(root, name, info, drafts[name]) {
			continue
		}
		return fmt.Errorf("Draft path %s already has different content. Use an empty directory or move the existing file.", name)
	}
	for _, name := range pending {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := writeNewDraft(ctx, root, name, drafts[name]); err != nil {
			return failed
		}
	}
	return nil
}

func identicalDraft(root *os.Root, name string, before os.FileInfo, data []byte) bool {
	f, err := openExistingDraft(root, name)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, before) {
		return false
	}
	old, err := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
	return err == nil && bytes.Equal(old, data)
}

func writeNewDraft(ctx context.Context, root *os.Root, name string, content []byte) error {
	tmp := ".vintar-draft-" + rand.Text()
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	_, err = f.Write(content)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return root.Link(tmp, name)
}
