package obs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func streakHub(t *testing.T) (context.Context, *sentry.Hub, *sentry.MockTransport) {
	t.Helper()
	mock := &sentry.MockTransport{}
	client, err := sentry.NewClient(sentry.ClientOptions{Dsn: "https://key@example.test/1", Transport: mock})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hub := sentry.NewHub(client, sentry.NewScope())
	return sentry.SetHubOnContext(context.Background(), hub), hub, mock
}

func TestStreakStaysOutOfSentryWithinGrace(t *testing.T) {
	ctx, hub, mock := streakHub(t)
	c := &clock{t: time.Date(2026, 10, 19, 22, 32, 0, 0, time.UTC)}
	s := &Streak{Grace: 2 * time.Minute, Now: c.now}

	for i := 0; i < 4; i++ {
		s.Fail(ctx, "claim failed", errors.New("connection refused"), []string{"claim"})
		c.advance(30 * time.Second)
	}
	s.OK("claim")
	hub.Flush(0)

	if n := len(mock.Events()); n != 0 {
		t.Fatalf("got %d Sentry events for a 90 second outage, want 0", n)
	}
}

func TestStreakReportsOncePastGrace(t *testing.T) {
	ctx, hub, mock := streakHub(t)
	c := &clock{t: time.Date(2026, 10, 19, 22, 32, 0, 0, time.UTC)}
	s := &Streak{Grace: 2 * time.Minute, Now: c.now}

	for i := 0; i < 10; i++ {
		s.Fail(ctx, "claim failed", errors.New("connection refused"), []string{"claim"}, "worker", "refund")
		c.advance(30 * time.Second)
	}
	hub.Flush(0)

	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("got %d Sentry events, want 1", len(events))
	}
	if got := events[0].Tags["failures"]; got != "5" {
		t.Errorf("failures tag = %q, want 5, the pass that crossed the two minute grace", got)
	}
	if got := events[0].Tags["failing_since"]; got != "2026-10-19T22:32:00Z" {
		t.Errorf("failing_since tag = %q", got)
	}
	if got := events[0].Tags["worker"]; got != "refund" {
		t.Errorf("worker tag = %q, want refund", got)
	}
}

func TestStreakReportsAgainAfterRecovering(t *testing.T) {
	ctx, hub, mock := streakHub(t)
	c := &clock{t: time.Date(2026, 10, 19, 22, 0, 0, 0, time.UTC)}
	s := &Streak{Grace: time.Minute, Now: c.now}

	outage := func() {
		for i := 0; i < 4; i++ {
			s.Fail(ctx, "claim failed", errors.New("connection refused"), []string{"claim"})
			c.advance(30 * time.Second)
		}
	}
	outage()
	s.OK("claim")
	outage()
	hub.Flush(0)

	if n := len(mock.Events()); n != 2 {
		t.Fatalf("got %d Sentry events across two outages, want 2", n)
	}
}

func TestStreakWaitBacksOffToMax(t *testing.T) {
	ctx, _, _ := streakHub(t)
	s := &Streak{Max: 5 * time.Minute, Now: (&clock{t: time.Unix(0, 0)}).now}
	base := 30 * time.Second

	if got := s.Wait(base); got != base {
		t.Fatalf("Wait with no streak = %s, want %s", got, base)
	}
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		s.Fail(ctx, "claim failed", errors.New("down"), []string{"claim"})
		if got := s.Wait(base); got != w {
			t.Errorf("Wait after %d failures = %s, want %s", i+1, got, w)
		}
	}
	s.OK("claim")
	if got := s.Wait(base); got != base {
		t.Errorf("Wait after recovery = %s, want %s", got, base)
	}
}

func TestStreakZeroValueUsesDefaults(t *testing.T) {
	var s Streak
	if got := s.Wait(time.Minute); got != time.Minute {
		t.Fatalf("Wait = %s, want 1m", got)
	}
	if s.grace() != 2*time.Minute {
		t.Errorf("grace = %s, want 2m", s.grace())
	}
	s.fails = 10
	if got := s.Wait(time.Minute); got != 5*time.Minute {
		t.Errorf("Wait at the cap = %s, want 5m", got)
	}
}
