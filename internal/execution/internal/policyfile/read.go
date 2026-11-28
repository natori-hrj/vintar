package policyfile

import (
	"errors"
	"io"
)

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("policy file could not be read within its limit")
	}
	return data, nil
}
