package execution

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestGovernorBudgetAndStop(t *testing.T) {
	g, err := NewGovernor(PolicyLimits{MaxRequests: 2, Rate: 10, Timeout: time.Second, MaxResponseSize: 42, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var starts []time.Time
	work := func(_ context.Context, size int64) (bool, error) {
		if size != 42 {
			t.Error("incorrect response limit")
		}
		starts = append(starts, time.Now())
		return false, nil
	}
	for i := 0; i < 2; i++ {
		if err := g.Run(t.Context(), work); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Run(t.Context(), work); err == nil || len(starts) != 2 {
		t.Fatalf("budget exhaustion: %v, starts %d", err, len(starts))
	}
	if starts[1].Sub(starts[0]) < 95*time.Millisecond {
		t.Fatal("second operation started before its interval")
	}
}

func TestPolicyGovernorCapsRequestedLimits(t *testing.T) {
	p := parsePolicyFixture(t, policyFixture)
	g, err := p.Governor(PolicyLimits{MaxRequests: 768, Rate: 10, Timeout: time.Minute, MaxResponseSize: 32, Deadline: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if g.limits != (PolicyLimits{MaxRequests: 48, Rate: 2.5, Timeout: 10 * time.Second, MaxResponseSize: 32, Deadline: 45250 * time.Millisecond}) {
		t.Fatalf("trusted policy limits were not intersected: %+v", g.limits)
	}
}

func TestGovernorSerializesAndCancels(t *testing.T) {
	g, err := NewGovernor(PolicyLimits{MaxRequests: 2, Rate: 10, Timeout: time.Second, MaxResponseSize: 42, Deadline: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	var hits atomic.Int32
	go func() {
		first <- g.Run(t.Context(), func(ctx context.Context, _ int64) (bool, error) {
			hits.Add(1)
			close(started)
			select {
			case <-release:
				return true, nil
			case <-ctx.Done():
				return true, ctx.Err()
			}
		})
	}()
	<-started
	waiting, cancel := context.WithTimeout(t.Context(), 15*time.Millisecond)
	defer cancel()
	work := func(context.Context, int64) (bool, error) { hits.Add(1); return false, nil }
	if err := g.Run(waiting, work); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting operation: %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := g.Run(t.Context(), work); err == nil || hits.Load() != 1 {
		t.Fatalf("stopped governor: %v, operations %d", err, hits.Load())
	}
}

func TestGovernorDeadlineBoundsWork(t *testing.T) {
	g, err := NewGovernor(PolicyLimits{MaxRequests: 2, Rate: 10, Timeout: time.Second, MaxResponseSize: 42, Deadline: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	work := func(ctx context.Context, _ int64) (bool, error) {
		<-ctx.Done()
		return false, ctx.Err()
	}
	if err := g.Run(t.Context(), work); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
}
