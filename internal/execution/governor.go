package execution

import (
	"context"
	"errors"
	"math"
	"time"
)

// Governor applies an already approved resource envelope to sequential
// operations. It has no knowledge of cases, credentials, or transport.
type Governor struct {
	queue     chan struct{}
	limits    PolicyLimits
	deadline  time.Time
	interval  time.Duration
	nextStart time.Time
	remaining int
	stopped   bool
}

func NewGovernor(limits PolicyLimits) (*Governor, error) {
	if limits.MaxRequests < 1 || limits.MaxRequests > 768 ||
		math.IsNaN(limits.Rate) || limits.Rate < 0.1 || limits.Rate > 10 ||
		limits.Timeout < 100*time.Millisecond || limits.Timeout > 60*time.Second ||
		limits.Deadline < 100*time.Millisecond || limits.Deadline > 120*time.Second ||
		limits.MaxResponseSize < 1 || limits.MaxResponseSize > 1<<20 {
		return nil, errors.New("invalid execution limits")
	}
	return &Governor{
		queue:     make(chan struct{}, 1),
		limits:    limits,
		deadline:  time.Now().Add(limits.Deadline),
		interval:  time.Duration(math.Ceil(float64(time.Second) / limits.Rate)),
		remaining: limits.MaxRequests,
	}, nil
}

// Governor intersects operator-approved limits with a consumer's requested
// limits. No requested value can increase the trusted resource envelope.
func (p *RuntimePolicy) Governor(requested PolicyLimits) (*Governor, error) {
	if p == nil {
		return nil, errors.New("trusted runtime policy is required")
	}
	allowed := p.Limits()
	return NewGovernor(PolicyLimits{
		MaxRequests:     min(allowed.MaxRequests, requested.MaxRequests),
		Rate:            min(allowed.Rate, requested.Rate),
		Timeout:         min(allowed.Timeout, requested.Timeout),
		MaxResponseSize: min(allowed.MaxResponseSize, requested.MaxResponseSize),
		Deadline:        min(allowed.Deadline, requested.Deadline),
	})
}

// Run invokes at most one operation with a bounded context and response cap.
// The operation must honor both. A true stop result or a failed operation
// prevents subsequent calls from starting work.
func (g *Governor) Run(ctx context.Context, work func(context.Context, int64) (stop bool, err error)) error {
	if g == nil || g.queue == nil || ctx == nil || work == nil {
		return errors.New("invalid execution request")
	}
	batch, cancel := context.WithDeadline(ctx, g.deadline)
	defer cancel()
	select {
	case g.queue <- struct{}{}:
		defer func() { <-g.queue }()
	case <-batch.Done():
		return batch.Err()
	}
	if err := batch.Err(); err != nil {
		return err
	}
	if g.stopped || g.remaining == 0 {
		return errors.New("execution is stopped or request budget is exhausted")
	}
	if delay := time.Until(g.nextStart); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-batch.Done():
			return batch.Err()
		}
	}
	request, cancelRequest := context.WithTimeout(batch, g.limits.Timeout)
	defer cancelRequest()
	if err := request.Err(); err != nil {
		return err
	}
	g.remaining--
	g.nextStart = time.Now().Add(g.interval)
	stop, err := work(request, g.limits.MaxResponseSize)
	if contextErr := request.Err(); contextErr != nil {
		g.stopped = true
		return contextErr
	}
	g.stopped = stop || err != nil
	if err != nil {
		return errors.New("execution operation failed")
	}
	return nil
}
