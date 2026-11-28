//go:build !linux && !darwin && !windows

package policyfile

import "errors"

func Read(string, int64) ([]byte, error) {
	return nil, errors.New("safe policy file loading is unavailable; use inline policy JSON")
}
