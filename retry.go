package httpw

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// Option configures Do.
type Option func(*options)

type options struct {
	retry *RetryPolicy
	// sleep waits for d or until ctx is done; tests replace it.
	sleep func(ctx context.Context, d time.Duration) error
}

// WithRetry retries a failed attempt as policy says. Without it, Do sends the request once.
func WithRetry(policy RetryPolicy) Option {
	return func(o *options) {
		o.retry = &policy
	}
}

// RetryPolicy retries requests with exponential backoff and full jitter: the wait before attempt n+1 is a random
// duration up to BaseDelay * 2^(n-1), capped at MaxDelay. A Retry-After header (seconds or an HTTP date) replaces the
// random wait, also capped at MaxDelay. A request whose body can't be sent again (no GetBody) is not retried. Waiting
// stops when the request's context is done.
type RetryPolicy struct {
	// MaxAttempts is the number of attempts including the first; 1 or less never retries.
	MaxAttempts int
	// BaseDelay is the longest wait before the second attempt; it doubles for each further one.
	BaseDelay time.Duration
	// MaxDelay caps every wait.
	MaxDelay time.Duration
	// Retryable reports whether an attempt that returned response or err should be retried. It defaults to
	// DefaultRetryable.
	Retryable func(response *http.Response, err error) bool
}

// DefaultRetryable retries transport errors (except a cancelled or expired context), 429 Too Many Requests and the
// gateway errors 502, 503 and 504.
func DefaultRetryable(response *http.Response, err error) bool {
	if err != nil {
		return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
	}

	switch response.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// send sends request, retrying as o.retry says, and returns the last attempt's response or error.
func send(request *http.Request, client *http.Client, logger *slog.Logger, o options) (*http.Response, error) {
	policy := o.retry
	if policy == nil || policy.MaxAttempts <= 1 || (request.Body != nil && request.Body != http.NoBody && request.GetBody == nil) {
		return client.Do(request)
	}

	retryable := policy.Retryable
	if retryable == nil {
		retryable = DefaultRetryable
	}

	ctx := request.Context()
	for attempt := 1; ; attempt++ {
		attemptRequest := request
		if attempt > 1 {
			attemptRequest = request.Clone(ctx)
			if request.GetBody != nil {
				body, err := request.GetBody()
				if err != nil {
					return nil, err
				}
				attemptRequest.Body = body
			}
		}

		response, err := client.Do(attemptRequest)
		if attempt >= policy.MaxAttempts || !retryable(response, err) {
			return response, err
		}

		wait := policy.wait(attempt, response)
		attrs := []slog.Attr{slog.Int("attempt", attempt), slog.Duration("wait", wait)}
		if response != nil {
			attrs = append(attrs, slog.Int("status_code", response.StatusCode))
			// Drain the body so the connection can be reused.
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxErrorBodyBytes))
			CloseReader(ctx, response.Body, logger)
		} else {
			attrs = append(attrs, slog.String("error", err.Error()))
		}
		logger.LogAttrs(ctx, slog.LevelWarn, "Retrying HTTP request", attrs...)

		if sleepErr := o.sleep(ctx, wait); sleepErr != nil {
			if response != nil {
				return nil, sleepErr
			}

			return nil, errors.Join(err, sleepErr)
		}
	}
}

// wait returns how long to wait before the attempt after attempt.
func (policy *RetryPolicy) wait(attempt int, response *http.Response) time.Duration {
	if response != nil {
		if retryAfter, ok := parseRetryAfter(response.Header.Get("Retry-After")); ok {
			return min(retryAfter, policy.MaxDelay)
		}
	}

	backoff := policy.BaseDelay << min(attempt-1, 30)
	if backoff <= 0 || backoff > policy.MaxDelay {
		backoff = policy.MaxDelay
	}

	if backoff <= 0 {
		return 0
	}

	return rand.N(backoff + 1)
}

// parseRetryAfter reads a Retry-After header: delay seconds or an HTTP date.
func parseRetryAfter(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}

	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second, true
	}

	if date, err := http.ParseTime(value); err == nil {
		return max(time.Until(date), 0), true
	}

	return 0, false
}
