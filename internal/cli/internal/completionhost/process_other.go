//go:build !linux && !darwin && !windows

package completionhost

import "context"

func processLookup(context.Context) func(int) process {
	return func(int) process { return process{} }
}
