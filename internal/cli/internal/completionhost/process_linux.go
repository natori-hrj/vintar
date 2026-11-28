package completionhost

import (
	"context"
	"os"
	"strconv"
	"strings"
)

func processLookup(context.Context) func(int) process {
	return func(pid int) process {
		dir := "/proc/" + strconv.Itoa(pid)
		raw, _ := os.ReadFile(dir + "/cmdline")
		name, _, _ := strings.Cut(string(raw), "\x00")
		stat, err := os.ReadFile(dir + "/stat")
		if err != nil {
			return process{name: name}
		}
		end := strings.LastIndexByte(string(stat), ')')
		if end < 0 {
			return process{name: name}
		}
		fields := strings.Fields(string(stat[end+1:]))
		if len(fields) < 2 {
			return process{name: name}
		}
		parent, _ := strconv.Atoi(fields[1])
		return process{name, parent}
	}
}
