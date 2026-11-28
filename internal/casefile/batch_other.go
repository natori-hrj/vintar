//go:build !linux && !darwin && !windows

package casefile

import "os"

const caseOpenFlags = os.O_RDONLY

func supportedCaseEntry(os.FileInfo) bool { return false }

func sameChangeTime(os.FileInfo, os.FileInfo) bool { return false }
