package httpw

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-openapi/testify/v2/assert"
	"github.com/go-openapi/testify/v2/require"
)

var discard = slog.New(slog.DiscardHandler)

// recordSleeps replaces the wait between attempts and records it.
func recordSleeps(waits *[]time.Duration) Option {
	return func(o *options) {
		o.sleep = func(_ context.Context, d time.Duration) error {
			*waits = append(*waits, d)
			return nil
		}
	}
}

var testPolicy = RetryPolicy{MaxAttempts: 4, BaseDelay: 100 * time.Millisecond, MaxDelay: time.Second}

// statusSequence answers each request with the next status, then 200 with {"ok":true}.
func statusSequence(t *testing.T, statuses ...int) (*httptest.Server, *atomic.Int32, *[]string) {
	t.Helper()

	var calls atomic.Int32
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(body))

		n := int(calls.Add(1))
		if n <= len(statuses) {
			w.WriteHeader(statuses[n-1])
			_, _ = w.Write([]byte(`{"errors":["try again"]}`))
			return
		}

		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	return server, &calls, &bodies
}

func TestDo_RetriesUntilSuccessAndReplaysTheBody(t *testing.T) {
	server, calls, bodies := statusSequence(t, http.StatusServiceUnavailable, http.StatusTooManyRequests)

	var waits []time.Duration
	request, err := NewJsonRequest(context.Background(), http.MethodPost, server.URL, map[string]string{"a": "b"})
	require.NoError(t, err)

	result, err := Do[map[string]bool](request, server.Client(), discard, WithRetry(testPolicy), recordSleeps(&waits))
	require.NoError(t, err)
	assert.True(t, result["ok"])
	assert.EqualValues(t, 3, calls.Load())
	assert.Equal(t, []string{`{"a":"b"}`, `{"a":"b"}`, `{"a":"b"}`}, *bodies)

	require.Len(t, waits, 2)
	assert.LessOrEqual(t, waits[0], 100*time.Millisecond)
	assert.LessOrEqual(t, waits[1], 200*time.Millisecond)
}

func TestDo_GivesUpAfterMaxAttempts(t *testing.T) {
	server, calls, _ := statusSequence(t, 503, 503, 503, 503, 503)

	var waits []time.Duration
	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	_, err := Do[IgnoreBody](request, server.Client(), discard, WithRetry(testPolicy), recordSleeps(&waits))

	responseErr, ok := errors.AsType[*ResponseError](err)
	require.True(t, ok)
	assert.Equal(t, http.StatusServiceUnavailable, responseErr.StatusCode())
	assert.Equal(t, `{"errors":["try again"]}`, string(responseErr.Body()))
	assert.EqualValues(t, 4, calls.Load())
	assert.Len(t, waits, 3)
}

func TestDo_DoesNotRetryOtherStatuses(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		server, calls, _ := statusSequence(t, status)

		request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		_, err := Do[IgnoreBody](request, server.Client(), discard, WithRetry(testPolicy))
		assert.Error(t, err)
		assert.EqualValues(t, 1, calls.Load(), status)
	}
}

func TestDo_NoRetryWithoutPolicy(t *testing.T) {
	server, calls, _ := statusSequence(t, http.StatusServiceUnavailable)

	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	_, err := Do[IgnoreBody](request, server.Client(), discard)
	assert.Error(t, err)
	assert.EqualValues(t, 1, calls.Load())
}

func TestDo_RetryAfterHeader(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	var waits []time.Duration
	policy := RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 1500 * time.Millisecond}
	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	_, err := Do[IgnoreBody](request, server.Client(), discard, WithRetry(policy), recordSleeps(&waits))
	require.NoError(t, err)
	// 2s is capped at MaxDelay; 0 is honoured.
	assert.Equal(t, []time.Duration{1500 * time.Millisecond, 0}, waits)
}

func TestDo_RetriesTransportErrors(t *testing.T) {
	var waits []time.Duration
	request, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1", nil)
	_, err := Do[IgnoreBody](request, http.DefaultClient, discard, WithRetry(RetryPolicy{MaxAttempts: 3, MaxDelay: time.Millisecond}), recordSleeps(&waits))
	assert.ErrorContains(t, err, "failed to execute http request")
	assert.Len(t, waits, 2)
}

func TestDo_StopsWaitingWhenTheContextIsDone(t *testing.T) {
	server, calls, _ := statusSequence(t, 503, 503)

	ctx, cancel := context.WithCancel(context.Background())
	cancelOnSleep := func(o *options) {
		o.sleep = func(ctx context.Context, d time.Duration) error {
			cancel()
			return sleepContext(ctx, d)
		}
	}

	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	_, err := Do[IgnoreBody](request, server.Client(), discard, WithRetry(testPolicy), cancelOnSleep)
	assert.ErrorIs(t, err, context.Canceled)
	assert.EqualValues(t, 1, calls.Load())
}

func TestDo_RealSleepIsShort(t *testing.T) {
	server, calls, _ := statusSequence(t, 503)

	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	start := time.Now()
	_, err := Do[IgnoreBody](request, server.Client(), discard, WithRetry(RetryPolicy{MaxAttempts: 2, BaseDelay: 10 * time.Millisecond, MaxDelay: 10 * time.Millisecond}))
	require.NoError(t, err)
	assert.EqualValues(t, 2, calls.Load())
	assert.Less(t, time.Since(start), time.Second)
}

func TestDo_BodyThatCannotBeReplayedIsNotRetried(t *testing.T) {
	server, calls, _ := statusSequence(t, 503)

	request, _ := http.NewRequest(http.MethodPost, server.URL, io.NopCloser(strings.NewReader("x")))
	request.GetBody = nil
	_, err := Do[IgnoreBody](request, server.Client(), discard, WithRetry(testPolicy))
	assert.Error(t, err)
	assert.EqualValues(t, 1, calls.Load())
}

func TestDo_GetBodyError(t *testing.T) {
	server, _, _ := statusSequence(t, 503)

	request, _ := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("x"))
	request.GetBody = func() (io.ReadCloser, error) { return nil, errors.New("no body") }
	var waits []time.Duration
	_, err := Do[IgnoreBody](request, server.Client(), discard, WithRetry(testPolicy), recordSleeps(&waits))
	assert.ErrorContains(t, err, "no body")
}

func TestDo_CustomRetryable(t *testing.T) {
	server, calls, _ := statusSequence(t, http.StatusInternalServerError)

	policy := testPolicy
	policy.Retryable = func(response *http.Response, err error) bool {
		return err == nil && response.StatusCode == http.StatusInternalServerError
	}

	var waits []time.Duration
	request, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	_, err := Do[IgnoreBody](request, server.Client(), discard, WithRetry(policy), recordSleeps(&waits))
	require.NoError(t, err)
	assert.EqualValues(t, 2, calls.Load())
}

func TestDefaultRetryable(t *testing.T) {
	assert.True(t, DefaultRetryable(nil, errors.New("connection refused")))
	assert.False(t, DefaultRetryable(nil, context.Canceled))
	assert.False(t, DefaultRetryable(nil, context.DeadlineExceeded))
	for _, status := range []int{429, 502, 503, 504} {
		assert.True(t, DefaultRetryable(&http.Response{StatusCode: status}, nil), status)
	}
	for _, status := range []int{200, 400, 401, 403, 404, 500} {
		assert.False(t, DefaultRetryable(&http.Response{StatusCode: status}, nil), status)
	}
}

func TestRetryPolicy_Wait(t *testing.T) {
	policy := RetryPolicy{BaseDelay: 100 * time.Millisecond, MaxDelay: 300 * time.Millisecond}
	for range 50 {
		assert.LessOrEqual(t, policy.wait(1, nil), 100*time.Millisecond)
		assert.LessOrEqual(t, policy.wait(2, nil), 200*time.Millisecond)
		assert.LessOrEqual(t, policy.wait(5, nil), 300*time.Millisecond)
		assert.LessOrEqual(t, policy.wait(100, nil), 300*time.Millisecond)
	}

	assert.Equal(t, time.Duration(0), (&RetryPolicy{}).wait(1, nil))
}

func TestParseRetryAfter(t *testing.T) {
	d, ok := parseRetryAfter("3")
	assert.True(t, ok)
	assert.Equal(t, 3*time.Second, d)

	d, ok = parseRetryAfter(time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
	assert.True(t, ok)
	assert.Greater(t, d, 59*time.Minute)

	d, ok = parseRetryAfter(time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
	assert.True(t, ok)
	assert.Equal(t, time.Duration(0), d)

	for _, value := range []string{"", "-1", "soon"} {
		_, ok = parseRetryAfter(value)
		assert.False(t, ok, value)
	}
}
