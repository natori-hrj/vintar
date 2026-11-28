package casefile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const maxBatchCases = 128

var errCaseSource = errors.New("unable to read case source safely")

type caseInput struct {
	name string
	info os.FileInfo
}

// LoadBatch reads inert TOML cases in filename order and checks the selection
// against the supplied request ceiling. It returns no cases on failure.
// Neither the selection nor the ceiling conveys execution authority.
func LoadBatch(source string, maxRequests int64) ([]Case, error) {
	if source == "" || maxRequests <= 0 {
		return nil, errors.New("invalid case source or request ceiling")
	}
	volume := filepath.VolumeName(source)
	for {
		for len(source) > len(volume)+1 && os.IsPathSeparator(source[len(source)-1]) {
			source = source[:len(source)-1]
		}
		// A final "/." refers to the same selection and must not bypass
		// the final-component link check.
		n := len(source)
		if n <= len(volume)+1 || source[n-1] != '.' || !os.IsPathSeparator(source[n-2]) {
			break
		}
		source = source[:n-1]
	}
	parent, name := filepath.Split(source)
	if parent == "" {
		parent = "."
	}
	if name == "" {
		name = "."
	} else if name == ".." {
		parent, name = source, "."
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, errCaseSource
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil || !supportedCaseEntry(info) {
		return nil, errCaseSource
	}

	if info.IsDir() {
		dir, err := root.OpenRoot(name)
		if err != nil {
			return nil, errCaseSource
		}
		defer dir.Close()
		if !sameCaseEntry(dir.Stat, ".", info) || !sameCaseEntry(root.Lstat, name, info) {
			return nil, errCaseSource
		}
		inputs, err := caseInputs(dir)
		if err != nil {
			return nil, err
		}
		cases, err := loadCases(dir, inputs, maxRequests)
		if !sameCaseEntry(dir.Stat, ".", info) || !sameCaseEntry(root.Lstat, name, info) {
			return nil, errCaseSource
		}
		return cases, err
	}
	if name == ".toml" || !strings.HasSuffix(name, ".toml") {
		return nil, errors.New("expected a TOML case file")
	}
	return loadCases(root, []caseInput{{name, info}}, maxRequests)
}

func caseInputs(dir *os.Root) ([]caseInput, error) {
	f, err := dir.Open(".")
	if err != nil {
		return nil, errCaseSource
	}
	defer f.Close()
	var names []string
	for {
		entries, err := f.ReadDir(128)
		if err != nil && err != io.EOF {
			return nil, errCaseSource
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".toml") {
				names = append(names, entry.Name())
				if len(names) > maxBatchCases {
					return nil, errors.New("too many regression cases")
				}
			}
		}
		if err == io.EOF {
			break
		}
	}
	if len(names) == 0 {
		return nil, errors.New("no regression cases found")
	}
	slices.Sort(names)
	inputs := make([]caseInput, 0, len(names))
	for _, name := range names {
		info, err := dir.Lstat(name)
		if err != nil || !supportedCaseEntry(info) || !info.Mode().IsRegular() {
			return nil, errCaseSource
		}
		inputs = append(inputs, caseInput{name, info})
	}
	return inputs, nil
}

func loadCases(root *os.Root, inputs []caseInput, maxRequests int64) ([]Case, error) {
	cases := make([]Case, 0, len(inputs))
	ids := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		data, err := readCase(root, input)
		if err != nil {
			return nil, err
		}
		c, err := Parse(data)
		if err != nil {
			return nil, err
		}
		if _, exists := ids[c.ID]; exists {
			return nil, errors.New("duplicate regression case identifier")
		}
		ids[c.ID] = struct{}{}
		if len(cases) != 0 {
			first := cases[0]
			if c.Version != first.Version {
				return nil, errors.New("mixed case schema versions")
			}
			if c.Version == Version2 && *c.IdentityID != *first.IdentityID {
				return nil, errors.New("multiple v2 identities in one batch")
			}
		}
		if c.Limits.MaxRequests > maxRequests {
			return nil, errors.New("request ceiling cannot cover every case")
		}
		maxRequests -= c.Limits.MaxRequests
		cases = append(cases, c)
	}
	return cases, nil
}

func readCase(root *os.Root, input caseInput) ([]byte, error) {
	name, before := input.name, input.info
	if before.Size() > MaxCaseBytes {
		return nil, errCaseSource
	}
	f, err := root.OpenFile(name, caseOpenFlags, 0)
	if err != nil {
		return nil, errCaseSource
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !sameInfo(opened, before) {
		return nil, errCaseSource
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxCaseBytes+1))
	if err != nil || int64(len(data)) != before.Size() {
		return nil, errCaseSource
	}
	after, err := f.Stat()
	if err != nil || !sameInfo(after, before) || !sameCaseEntry(root.Lstat, name, before) {
		return nil, errCaseSource
	}
	return data, nil
}

func sameCaseEntry(stat func(string) (os.FileInfo, error), name string, expected os.FileInfo) bool {
	info, err := stat(name)
	return err == nil && sameInfo(info, expected)
}

func sameInfo(info, expected os.FileInfo) bool {
	return supportedCaseEntry(info) && info.Mode() == expected.Mode() &&
		info.Size() == expected.Size() && info.ModTime().Equal(expected.ModTime()) &&
		os.SameFile(info, expected) && sameChangeTime(info, expected)
}
