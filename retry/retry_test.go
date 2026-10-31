package retry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// clock is a fake: Sleep advances it and records each wait, and Jitter
// returns the full ceiling so the waits are exact.
type clock struct {
	now   time.Time
	waits []time.Duration
}

func (c *clock) policy(p Policy) Policy {
	p.Now = func() time.Time { return c.now }
	p.Sleep = func(ctx context.Context, d time.Duration) error {
		c.waits = append(c.waits, d)
		c.now = c.now.Add(d)
		return ctx.Err()
	}
	p.Jitter = func(d time.Duration) time.Duration { return d }
	return p
}

func newClock() *clock { return &clock{now: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)} }

// failing returns errs in order, then nil.
func failing(errs ...error) (func(context.Context) error, *int) {
	calls := 0
	return func(context.Context) error {
		calls++
		if calls <= len(errs) {
			return errs[calls-1]
		}
		return nil
	}, &calls
}

func status(code int) error { return &StatusError{Code: code} }

func TestDo_RetriesUntilSuccess(t *testing.T) {
	c := newClock()
	fn, calls := failing(status(503), status(503))

	attempts, err := Do(context.Background(), c.policy(Policy{}), fn)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if attempts != 3 || *calls != 3 {
		t.Fatalf("attempts = %d, calls = %d, want 3", attempts, *calls)
	}
	want := []time.Duration{time.Second, 2 * time.Second}
	if fmt.Sprint(c.waits) != fmt.Sprint(want) {
		t.Fatalf("waits = %v, want %v", c.waits, want)
	}
}

func TestDo_BackoffCapsAtMaxDelay(t *testing.T) {
	c := newClock()
	fn, _ := failing(status(500), status(500), status(500), status(500))

	_, err := Do(context.Background(), c.policy(Policy{BaseDelay: time.Second, MaxDelay: 3 * time.Second, MaxAttempts: 10}), fn)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 3 * time.Second, 3 * time.Second}
	if fmt.Sprint(c.waits) != fmt.Sprint(want) {
		t.Fatalf("waits = %v, want %v", c.waits, want)
	}
}

func TestDo_JitterPicksBelowCeiling(t *testing.T) {
	c := newClock()
	p := c.policy(Policy{})
	var ceilings []time.Duration
	p.Jitter = func(d time.Duration) time.Duration {
		ceilings = append(ceilings, d)
		return d / 4
	}
	fn, _ := failing(status(502), status(502))

	if _, err := Do(context.Background(), p, fn); err != nil {
		t.Fatalf("err = %v", err)
	}
	if fmt.Sprint(ceilings) != fmt.Sprint([]time.Duration{time.Second, 2 * time.Second}) {
		t.Fatalf("ceilings = %v", ceilings)
	}
	if fmt.Sprint(c.waits) != fmt.Sprint([]time.Duration{250 * time.Millisecond, 500 * time.Millisecond}) {
		t.Fatalf("waits = %v", c.waits)
	}
}

func TestDo_DoesNotRetryClientErrors(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 409, 422} {
		c := newClock()
		fn, calls := failing(status(code))

		attempts, err := Do(context.Background(), c.policy(Policy{}), fn)
		var se *StatusError
		if !errors.As(err, &se) || se.Code != code {
			t.Fatalf("%d: err = %v", code, err)
		}
		if attempts != 1 || *calls != 1 || len(c.waits) != 0 {
			t.Fatalf("%d: attempts = %d, calls = %d, waits = %v", code, attempts, *calls, c.waits)
		}
	}
}

func TestDo_DoesNotRetryOtherErrors(t *testing.T) {
	c := newClock()
	fn, calls := failing(errors.New("marshal: bad"))

	if _, err := Do(context.Background(), c.policy(Policy{}), fn); err == nil || *calls != 1 {
		t.Fatalf("err = %v, calls = %d", err, *calls)
	}
}

func TestDo_StopsAtMaxAttempts(t *testing.T) {
	c := newClock()
	fn, calls := failing(status(503), status(503), status(503), status(503))

	attempts, err := Do(context.Background(), c.policy(Policy{MaxAttempts: 3}), fn)
	if se := (*StatusError)(nil); !errors.As(err, &se) || se.Code != 503 {
		t.Fatalf("err = %v", err)
	}
	if attempts != 3 || *calls != 3 || len(c.waits) != 2 {
		t.Fatalf("attempts = %d, calls = %d, waits = %v", attempts, *calls, c.waits)
	}
}

func TestDo_StopsBeforeExceedingMaxElapsed(t *testing.T) {
	c := newClock()
	fn, calls := failing(status(503), status(503), status(503), status(503))

	// Waits of 1s and 2s fit in 4s; the next 4s wait would end at 7s.
	attempts, err := Do(context.Background(), c.policy(Policy{MaxElapsed: 4 * time.Second, MaxAttempts: 10}), fn)
	if err == nil {
		t.Fatal("want the last error")
	}
	if attempts != 3 || *calls != 3 {
		t.Fatalf("attempts = %d, calls = %d", attempts, *calls)
	}
}

func TestDo_HonoursRetryAfter(t *testing.T) {
	c := newClock()
	fn, _ := failing(&StatusError{Code: 429, RetryAfter: 7 * time.Second})

	if _, err := Do(context.Background(), c.policy(Policy{}), fn); err != nil {
		t.Fatalf("err = %v", err)
	}
	if fmt.Sprint(c.waits) != fmt.Sprint([]time.Duration{7 * time.Second}) {
		t.Fatalf("waits = %v", c.waits)
	}
}

func TestDo_RetryAfterBeyondBudgetStops(t *testing.T) {
	c := newClock()
	fn, calls := failing(&StatusError{Code: 503, RetryAfter: time.Hour})

	if _, err := Do(context.Background(), c.policy(Policy{}), fn); err == nil || *calls != 1 || len(c.waits) != 0 {
		t.Fatalf("err = %v, calls = %d, waits = %v", err, *calls, c.waits)
	}
}

func TestDo_CancelledWhileWaitingStops(t *testing.T) {
	c := newClock()
	ctx, cancel := context.WithCancel(context.Background())
	p := c.policy(Policy{})
	p.Sleep = func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	fn, calls := failing(status(503), status(503))

	attempts, err := Do(ctx, p, fn)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 503 {
		t.Fatalf("err = %v, want the last status too", err)
	}
	if attempts != 1 || *calls != 1 {
		t.Fatalf("attempts = %d, calls = %d", attempts, *calls)
	}
}

func TestDo_CancelledDuringAttemptStops(t *testing.T) {
	c := newClock()
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	fn := func(context.Context) error {
		calls++
		cancel()
		return &url.Error{Op: "Post", URL: "http://x", Err: context.Canceled}
	}

	_, err := Do(ctx, c.policy(Policy{}), fn)
	if !errors.Is(err, context.Canceled) || calls != 1 || len(c.waits) != 0 {
		t.Fatalf("err = %v, calls = %d, waits = %v", err, calls, c.waits)
	}
}

func TestDo_RealSleepHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fn, calls := failing(status(503))

	_, err := Do(ctx, Policy{BaseDelay: time.Hour, MaxDelay: time.Hour, MaxElapsed: 2 * time.Hour,
		Jitter: func(d time.Duration) time.Duration { return d }}, fn)
	if !errors.Is(err, context.Canceled) || *calls != 1 {
		t.Fatalf("err = %v, calls = %d", err, *calls)
	}
}

func TestRetryable(t *testing.T) {
	timeout := &net.OpError{Op: "dial", Err: &timeoutErr{}}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"429", status(429), true},
		{"500", status(500), true},
		{"503 wrapped", fmt.Errorf("notify: %w", status(503)), true},
		{"400", status(400), false},
		{"404", status(404), false},
		{"url error", &url.Error{Op: "Post", URL: "http://x", Err: errors.New("connection refused")}, true},
		{"net timeout", timeout, true},
		{"plain", errors.New("boom"), false},
	}
	for _, tc := range cases {
		if got := Retryable(tc.err); got != tc.want {
			t.Errorf("%s: Retryable = %v, want %v", tc.name, got, tc.want)
		}
	}
}

type timeoutErr struct{}

func (*timeoutErr) Error() string   { return "i/o timeout" }
func (*timeoutErr) Timeout() bool   { return true }
func (*timeoutErr) Temporary() bool { return true }

func TestCheckResponse(t *testing.T) {
	resp := func(code int, retryAfter, body string) *http.Response {
		h := http.Header{}
		if retryAfter != "" {
			h.Set("Retry-After", retryAfter)
		}
		return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader(body))}
	}

	if err := CheckResponse(resp(200, "", "")); err != nil {
		t.Fatalf("200: err = %v", err)
	}
	if err := CheckResponse(resp(204, "", "")); err != nil {
		t.Fatalf("204: err = %v", err)
	}

	var se *StatusError
	err := CheckResponse(resp(429, "12", `{"error":"slow down"}`))
	if !errors.As(err, &se) || se.Code != 429 || se.RetryAfter != 12*time.Second {
		t.Fatalf("429: err = %#v", err)
	}
	if err.Error() != `status 429: {"error":"slow down"}` {
		t.Fatalf("message = %q", err.Error())
	}

	err = CheckResponse(resp(500, "", strings.Repeat("x", 5000)))
	if !errors.As(err, &se) || len(se.Body) != 1024 || se.RetryAfter != 0 {
		t.Fatalf("500: body len = %d, retry after = %v", len(se.Body), se.RetryAfter)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"":                              0,
		"30":                            30 * time.Second,
		"-5":                            0,
		"soon":                          0,
		"Sat, 31 Oct 2026 09:00:45 GMT": 45 * time.Second,
		"Sat, 31 Oct 2026 08:59:00 GMT": 0,
	}
	for in, want := range cases {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("%q: got %v, want %v", in, got, want)
		}
	}
}
