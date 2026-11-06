package obs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/getsentry/sentry-go"
)

func panicRequest(ctx context.Context, h http.Handler, header ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/boom?token=secret", nil)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	Recoverer(h).ServeHTTP(rec, req)
	return rec
}

func TestRecovererCapturesStringPanicAndReturnsJSON500(t *testing.T) {
	ctx, _, mock := streakHub(t)

	rec := panicRequest(ctx, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("kaboom") }))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"internal server error"}` {
		t.Errorf("body = %q", got)
	}
	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Message != "kaboom" {
		t.Errorf("event message = %q, want kaboom", events[0].Message)
	}
	if events[0].Level != sentry.LevelFatal {
		t.Errorf("event level = %q, want fatal", events[0].Level)
	}
	if events[0].Request == nil || !strings.Contains(events[0].Request.URL, "/boom") {
		t.Errorf("event request = %+v, want the panicking request", events[0].Request)
	}
}

func TestRecovererCapturesErrorPanicAsException(t *testing.T) {
	ctx, _, mock := streakHub(t)

	rec := panicRequest(ctx, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(errors.New("kaboom")) }))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if len(events[0].Exception) == 0 || events[0].Exception[0].Value != "kaboom" {
		t.Errorf("event exception = %+v, want kaboom", events[0].Exception)
	}
}

func TestRecovererGivesHandlersARequestHub(t *testing.T) {
	mock := &sentry.MockTransport{}
	client, err := sentry.NewClient(sentry.ClientOptions{Dsn: "https://key@example.test/1", Transport: mock})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	sentry.CurrentHub().BindClient(client)
	t.Cleanup(func() { sentry.CurrentHub().BindClient(nil) })

	rec := panicRequest(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sentry.GetHubFromContext(r.Context()) == nil {
			t.Error("handler context carries no hub")
		}
		Capture(r.Context(), "mid-request failure", errors.New("db down"))
		w.WriteHeader(http.StatusAccepted)
	}))

	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d, want the handler's 202", rec.Code)
	}
	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Request == nil || !strings.Contains(events[0].Request.URL, "/boom") {
		t.Errorf("event request = %+v, want the request being served", events[0].Request)
	}
}

// initHub builds the client through initWith, because the filter on
// http.ErrAbortHandler only exists on a client built that way.
func initHub(t *testing.T) *sentry.MockTransport {
	t.Helper()
	t.Setenv("SENTRY_DSN", "https://key@example.test/1")
	mock := &sentry.MockTransport{}
	t.Cleanup(func() { sentry.CurrentHub().BindClient(nil) })
	initWith(Config{Service: "widget"}, mock)
	return mock
}

func TestRecovererLetsErrAbortHandlerReachNetHTTPUnreported(t *testing.T) {
	mock := initHub(t)
	defer func() {
		if got := recover(); got != http.ErrAbortHandler { //nolint:errorlint // asserting the exact sentinel
			t.Errorf("recovered %v, want http.ErrAbortHandler", got)
		}
		if n := len(mock.Events()); n != 0 {
			t.Errorf("got %d Sentry events for http.ErrAbortHandler, want 0", n)
		}
	}()
	panicRequest(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	t.Error("Recoverer swallowed http.ErrAbortHandler")
}

func TestInitClientStillReportsOtherPanics(t *testing.T) {
	cases := []struct {
		name  string
		value any
	}{
		{"string", "kaboom"},
		{"error", errors.New("kaboom")},
		{"wrapped abort", fmt.Errorf("wrapped: %w", http.ErrAbortHandler)},
		{"uncomparable", []string{"kaboom"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := initHub(t)

			rec := panicRequest(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(tc.value) }))

			if rec.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want 500", rec.Code)
			}
			if n := len(mock.Events()); n != 1 {
				t.Errorf("got %d events, want 1", n)
			}
		})
	}
}

func TestRecovererWritesNothingOnAnUpgradeRequest(t *testing.T) {
	ctx, _, mock := streakHub(t)

	rec := panicRequest(ctx, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("kaboom") }), "Connection", "Upgrade")

	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want nothing written to a hijacked connection", rec.Body.String())
	}
	if n := len(mock.Events()); n != 1 {
		t.Errorf("got %d events, want 1", n)
	}
}

func TestGoReportsPanicWithoutCrashing(t *testing.T) {
	events := make(chan *sentry.Event, 1)
	client, err := sentry.NewClient(sentry.ClientOptions{
		Dsn:       "https://key@example.test/1",
		Transport: &sentry.MockTransport{},
		BeforeSend: func(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
			events <- event
			return event
		},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := sentry.SetHubOnContext(context.Background(), sentry.NewHub(client, sentry.NewScope()))

	Go(ctx, "send-email", func() { panic("kaboom") })

	select {
	case event := <-events:
		if event.Message != "kaboom" || event.Level != sentry.LevelFatal {
			t.Errorf("event = %q at %q, want kaboom at fatal", event.Message, event.Level)
		}
		if !slices.Equal(event.Fingerprint, []string{"panic", "send-email"}) {
			t.Errorf("fingerprint = %v", event.Fingerprint)
		}
		if event.Tags["task"] != "send-email" {
			t.Errorf("task tag = %q", event.Tags["task"])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("panic was not reported")
	}
}

// loopRun drives Loop in a synctest bubble, so every wait passes instantly on a
// fake clock, and returns the gap before each call after the first. Calls
// beyond the script cancel the loop.
func loopRun(t *testing.T, ctx context.Context, every time.Duration, script ...func()) []time.Duration {
	t.Helper()
	var gaps []time.Duration
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		var last time.Time
		call := 0
		Loop(ctx, "worker", every, func(context.Context) {
			if call > 0 {
				gaps = append(gaps, time.Since(last))
			}
			// Deferred so a panicking script still marks when this call ended.
			defer func() { last = time.Now() }()
			call++
			if call > len(script) {
				cancel()
				return
			}
			script[call-1]()
		})
	})
	return gaps
}

func boom() { panic("kaboom") }

func TestLoopReportsEachPanicAndBacksOffToTheCap(t *testing.T) {
	ctx, _, mock := streakHub(t)

	gaps := loopRun(t, ctx, time.Second, slices.Repeat([]func(){boom}, 10)...)

	want := []time.Duration{
		2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second,
		64 * time.Second, 128 * time.Second, 256 * time.Second, 5 * time.Minute, 5 * time.Minute,
	}
	if !slices.Equal(gaps, want) {
		t.Errorf("restart delays = %v, want %v", gaps, want)
	}
	events := mock.Events()
	if len(events) != 10 {
		t.Fatalf("got %d events, want one per panic", len(events))
	}
	for _, e := range events {
		if !slices.Equal(e.Fingerprint, []string{"panic", "worker"}) {
			t.Errorf("fingerprint = %v", e.Fingerprint)
		}
	}
}

func TestLoopSendsOneEventPerPanicPastTheStreakGrace(t *testing.T) {
	ctx, _, mock := streakHub(t)

	// Enough panics for the streak to run well beyond its default two minutes.
	loopRun(t, ctx, time.Minute, boom, boom, boom, boom)

	if n := len(mock.Events()); n != 4 {
		t.Errorf("got %d events for 4 panics", n)
	}
}

func TestLoopResetsBackoffAfterAHealthyRun(t *testing.T) {
	ctx, _, _ := streakHub(t)

	gaps := loopRun(t, ctx, time.Second,
		boom,
		boom,
		func() {
			time.Sleep(defaultStreakMax)
			panic("kaboom")
		},
		boom,
	)

	want := []time.Duration{2 * time.Second, 4 * time.Second, 2 * time.Second, 4 * time.Second}
	if !slices.Equal(gaps, want) {
		t.Errorf("restart delays = %v, want %v", gaps, want)
	}
}

func TestLoopWaitsEveryAfterACleanReturn(t *testing.T) {
	ctx, _, mock := streakHub(t)
	ok := func() {}

	gaps := loopRun(t, ctx, time.Hour, ok, ok, boom, ok)

	want := []time.Duration{time.Hour, time.Hour, 5 * time.Minute, time.Hour}
	if !slices.Equal(gaps, want) {
		t.Errorf("gaps = %v, want %v", gaps, want)
	}
	if n := len(mock.Events()); n != 1 {
		t.Errorf("got %d events, want only the panic", n)
	}
}

func TestLoopDoesNotHotLoopOnAZeroDelay(t *testing.T) {
	ctx, _, _ := streakHub(t)

	gaps := loopRun(t, ctx, 0, boom, func() {})

	want := []time.Duration{2 * time.Second, time.Second}
	if !slices.Equal(gaps, want) {
		t.Errorf("gaps = %v, want %v", gaps, want)
	}
}

func TestLoopKeepsRestartingWithNoSentryClient(t *testing.T) {
	ctx := sentry.SetHubOnContext(context.Background(), sentry.NewHub(nil, sentry.NewScope()))

	gaps := loopRun(t, ctx, time.Second, boom, boom)

	if len(gaps) != 2 {
		t.Errorf("got %d restarts, want 2", len(gaps))
	}
}

func TestLoopStopsWhenCancelledDuringBackoff(t *testing.T) {
	base, _, _ := streakHub(t)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(base)
		defer cancel()
		calls := 0
		done := make(chan struct{})
		go func() {
			defer close(done)
			Loop(ctx, "worker", time.Hour, func(context.Context) {
				calls++
				panic("kaboom")
			})
		}()

		synctest.Wait()
		start := time.Now()
		cancel()
		<-done

		if calls != 1 {
			t.Errorf("fn ran %d times, want 1", calls)
		}
		if waited := time.Since(start); waited != 0 {
			t.Errorf("Loop took %s to stop, want no wait", waited)
		}
	})
}

func TestLoopReportsAPanicDuringShutdownWithoutWaiting(t *testing.T) {
	base, _, mock := streakHub(t)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(base)
		defer cancel()
		start := time.Now()

		Loop(ctx, "worker", time.Hour, func(context.Context) {
			cancel()
			panic("kaboom")
		})

		if waited := time.Since(start); waited != 0 {
			t.Errorf("Loop took %s to stop, want no wait", waited)
		}
	})
	if n := len(mock.Events()); n != 1 {
		t.Errorf("got %d events, want 1", n)
	}
}

func TestLoopDoesNotCallFnOnceCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	Loop(ctx, "worker", time.Hour, func(context.Context) { t.Error("fn ran after cancel") })
}
