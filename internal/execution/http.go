package execution

import (
	"context"
	"time"

	"github.com/natori-hrj/vintar/internal/execution/internal/httpio"
)

type HTTPRequest = httpio.Request
type HTTPResponse = httpio.Response

// SendHTTP executes the single request explicitly supplied to http send.
func SendHTTP(ctx context.Context, request HTTPRequest, timeout time.Duration, limit int64) (HTTPResponse, error) {
	return httpio.SendPublic(ctx, request, timeout, limit)
}
