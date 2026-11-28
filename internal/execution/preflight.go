package execution

import (
	"context"
	"errors"
	"time"
)

// PreparedOperation describes a reviewed request without making it executable.
// The credential is not stored in the URL or exposed by formatting.
type PreparedOperation struct {
	URL, Method string
	credential  Credential
}

func (op PreparedOperation) ApplyCredential(headers map[string]string) error {
	return op.credential.Apply(headers)
}

// PrepareAll checks every operation against independent trusted origins and
// policy before resolving any secrets. Failure returns no partial operations.
func (p *RuntimePolicy) PrepareAll(ctx context.Context, requests []ApprovalRequest, trusted []Origin, now time.Time, lookup func(string) (string, bool)) ([]PreparedOperation, error) {
	if ctx == nil || p == nil || len(requests) == 0 || len(requests) > 128 || len(requests) > p.limits.MaxRequests {
		return nil, errors.New("invalid preflight")
	}
	result := make([]PreparedOperation, len(requests))
	sources := make([]policyIdentity, len(requests))
	for i, request := range requests {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		url, err := RebindApprovedPath(request.Origin, trusted, request.Path)
		if err != nil {
			return nil, errPolicyDenied
		}
		source, err := p.authorizedSource(request, now)
		if err != nil {
			return nil, err
		}
		sources[i] = source
		result[i] = PreparedOperation{URL: url, Method: request.Method}
	}
	for i, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		credential, err := source.credential(lookup)
		if err != nil {
			return nil, err
		}
		result[i].credential = credential
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
