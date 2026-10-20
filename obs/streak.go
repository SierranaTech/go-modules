package obs

import (
	"context"
	"log"
	"sync"
	"time"
)

const (
	defaultStreakGrace = 2 * time.Minute
	defaultStreakMax   = 5 * time.Minute
)

// Streak tracks a failure that repeats on every pass of a polling loop,
// such as a worker that cannot reach its database. Every failure is
// logged, but Sentry gets one event per streak, and only once the streak
// has lasted longer than Grace, so a brief database failover stays out of
// Sentry. Wait slows the loop down while the streak lasts.
//
// The zero value is ready to use. A Streak is safe for concurrent use.
type Streak struct {
	// Grace is how long failures must continue before Sentry hears about
	// them. Defaults to two minutes.
	Grace time.Duration
	// Max caps the delay Wait returns. Defaults to five minutes.
	Max time.Duration
	// Now returns the current time. Defaults to time.Now.
	Now func() time.Time

	mu       sync.Mutex
	since    time.Time
	fails    int
	reported bool
}

// Fail records one failed pass. It always logs; it sends a single Sentry
// event, grouped by fingerprint, once the streak has outlasted Grace.
func (s *Streak) Fail(ctx context.Context, msg string, err error, fingerprint []string, fields ...any) {
	s.mu.Lock()
	now := s.now()
	if s.fails == 0 {
		s.since = now
	}
	s.fails++
	report := !s.reported && now.Sub(s.since) >= s.grace()
	if report {
		s.reported = true
	}
	fails, since := s.fails, s.since
	s.mu.Unlock()

	fields = append(fields, "failures", fails, "failing_since", since.UTC().Format(time.RFC3339))
	if report {
		CaptureFingerprint(ctx, msg, err, fingerprint, fields...)
		return
	}
	logFields(msg, err, fields...)
}

// OK records a successful pass, ending any streak. A streak that lasted
// long enough to reach Sentry gets a log line saying it has recovered.
func (s *Streak) OK(msg string) {
	s.mu.Lock()
	fails, since, reported := s.fails, s.since, s.reported
	s.fails, s.reported = 0, false
	now := s.now()
	s.mu.Unlock()

	if reported {
		log.Printf("%s recovered after %d failures over %s", msg, fails, now.Sub(since).Round(time.Second))
	}
}

// Wait returns how long the loop should wait before its next pass: base
// while there is no streak, then doubling with each failure up to Max.
func (s *Streak) Wait(base time.Duration) time.Duration {
	s.mu.Lock()
	fails := s.fails
	s.mu.Unlock()

	limit := s.Max
	if limit <= 0 {
		limit = defaultStreakMax
	}
	wait := base
	for i := 0; i < fails && wait < limit; i++ {
		wait *= 2
	}
	if fails > 0 && wait > limit {
		wait = limit
	}
	return wait
}

func (s *Streak) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Streak) grace() time.Duration {
	if s.Grace > 0 {
		return s.Grace
	}
	return defaultStreakGrace
}
