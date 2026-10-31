// Package retry runs an operation again, with exponential backoff and full
// jitter, when it fails in a way that might succeed next time: a network
// error, a timeout, HTTP 429 or a 5xx. Any other error ends the run.
package retry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	defaultMaxAttempts = 6
	defaultBaseDelay   = time.Second
	defaultMaxDelay    = 30 * time.Second
	defaultMaxElapsed  = 2 * time.Minute
)

// Policy bounds a run. The zero value is ready to use: six attempts, a one
// second base delay doubling up to thirty seconds, and two minutes in all.
type Policy struct {
	// MaxAttempts counts the first call. Defaults to 6.
	MaxAttempts int
	// BaseDelay is the backoff ceiling before the second attempt; it doubles
	// for each attempt after. Defaults to one second.
	BaseDelay time.Duration
	// MaxDelay caps the backoff ceiling. Defaults to thirty seconds.
	MaxDelay time.Duration
	// MaxElapsed ends the run when the next wait would take it past this
	// long since the first attempt. Defaults to two minutes.
	MaxElapsed time.Duration

	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time
	// Sleep waits for d or until ctx is done. Defaults to a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// Jitter picks the actual wait from [0, ceiling). Defaults to uniform
	// random.
	Jitter func(ceiling time.Duration) time.Duration
}

// Do calls fn until it succeeds, returns an error Retryable rejects, or the
// policy runs out. It returns the number of attempts made and fn's last
// error. When ctx ends while waiting, the error also matches ctx.Err().
func Do(ctx context.Context, p Policy, fn func(context.Context) error) (int, error) {
	p = p.withDefaults()
	start := p.Now()
	for attempt := 1; ; attempt++ {
		err := fn(ctx)
		if err == nil {
			return attempt, nil
		}
		if ctx.Err() != nil {
			return attempt, errors.Join(err, ctx.Err())
		}
		if attempt >= p.MaxAttempts || !Retryable(err) {
			return attempt, err
		}
		wait := p.backoff(attempt)
		var se *StatusError
		if errors.As(err, &se) && se.RetryAfter > 0 {
			wait = se.RetryAfter
		}
		if p.Now().Add(wait).Sub(start) > p.MaxElapsed {
			return attempt, err
		}
		if serr := p.Sleep(ctx, wait); serr != nil {
			return attempt, errors.Join(err, serr)
		}
	}
}

// Retryable reports whether err is worth another attempt: a *StatusError
// for 429 or a 5xx, or a transport failure from an http.Client or the net
// package.
func Retryable(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code == http.StatusTooManyRequests || se.Code >= 500
	}
	var ue *url.Error
	var ne net.Error
	return errors.As(err, &ue) || errors.As(err, &ne)
}

// StatusError is a non-2xx HTTP response.
type StatusError struct {
	Code int
	// RetryAfter is the wait the server asked for, zero when it asked for
	// none.
	RetryAfter time.Duration
	// Body is the start of the response body, for the error message.
	Body string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("status %d", e.Code)
	}
	return fmt.Sprintf("status %d: %s", e.Code, e.Body)
}

// CheckResponse returns nil for a 2xx response, otherwise a *StatusError
// carrying the Retry-After header and up to 1 KiB of the body. It does not
// close the body.
func CheckResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return &StatusError{
		Code:       resp.StatusCode,
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
		Body:       string(body),
	}
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return max(time.Duration(secs)*time.Second, 0)
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0)
	}
	return 0
}

func (p Policy) withDefaults() Policy {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = defaultMaxAttempts
	}
	if p.BaseDelay <= 0 {
		p.BaseDelay = defaultBaseDelay
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = defaultMaxDelay
	}
	if p.MaxElapsed <= 0 {
		p.MaxElapsed = defaultMaxElapsed
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	if p.Sleep == nil {
		p.Sleep = sleep
	}
	if p.Jitter == nil {
		p.Jitter = func(d time.Duration) time.Duration { return rand.N(d) }
	}
	return p
}

// backoff is the full-jitter wait after the given attempt.
func (p Policy) backoff(attempt int) time.Duration {
	ceiling := p.MaxDelay
	if shift := attempt - 1; shift < 32 {
		if d := p.BaseDelay << shift; d > 0 && d < ceiling {
			ceiling = d
		}
	}
	return p.Jitter(ceiling)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
