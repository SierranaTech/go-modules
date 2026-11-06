package obs

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/getsentry/sentry-go"
	sentryhttp "github.com/getsentry/sentry-go/http"
)

// minLoopDelay stops a zero or negative delay turning Loop into a hot loop.
const minLoopDelay = time.Second

// Recoverer makes a handler panic reach Sentry while the client still gets a
// JSON 500. It also gives every request the hub Capture and ServerError rely
// on. It replaces both chi's Recoverer and sentryhttp: if chi's stays inside
// it, chi swallows the panic and Sentry sees nothing.
//
// sentryhttp has to re-panic: without that it swallows the panic and the
// client gets an empty 200. http.ErrAbortHandler carries on up to net/http,
// which aborts the connection. Keeping it out of Sentry depends on the client
// being built by Init, whose BeforeSend filters it. A panic after the response
// has started cannot change the status, and the error body lands after what
// was already written.
func Recoverer(next http.Handler) http.Handler {
	capture := sentryhttp.New(sentryhttp.Options{Repanic: true}).Handle(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler { //nolint:errorlint // net/http compares it the same way
				panic(rec)
			}
			log.Printf("panic in %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
			if r.Header.Get("Connection") != "Upgrade" {
				writeError(w, "internal server error")
			}
		}()
		capture.ServeHTTP(w, r)
	})
}

// Go runs fn in a goroutine. A panic is logged and sent to Sentry, grouped by
// name, and the process carries on. ctx only supplies the hub to report on, so
// a request context is safe here. Use it for one-shot work; a worker that has
// to keep running wants Loop.
func Go(ctx context.Context, name string, fn func()) {
	go func() {
		_ = protect(ctx, name, fn)
	}()
}

// Loop calls fn until ctx is cancelled, waiting every between calls, and blocks
// until it stops: start it with go. A worker whose fn blocks until ctx is
// cancelled only comes back round after a panic or an early return. When fn
// blocks with its own ticker, every is only the restart delay, so pass a small
// value rather than the worker's tick.
//
// Every panic is logged and sent to Sentry, grouped by name, then fn restarts
// after a delay from Streak: doubling from every, capped at five minutes. A run
// that outlasts the cap counts as healthy and resets the delay, as does a clean
// return. Cancelling ctx ends the wait at once, but Loop cannot interrupt fn, so
// fn must honour ctx for shutdown not to hang.
func Loop(ctx context.Context, name string, every time.Duration, fn func(context.Context)) {
	if every < minLoopDelay {
		every = minLoopDelay
	}
	// The Streak only paces restarts. Loop reports each panic itself, so the
	// grace period is set high enough that Fail never sends a second event.
	streak := Streak{Grace: math.MaxInt64}
	for ctx.Err() == nil {
		start := time.Now()
		err := protect(ctx, name, func() { fn(ctx) })
		if err == nil || time.Since(start) >= defaultStreakMax {
			streak.OK(name)
		}
		if err != nil {
			streak.Fail(ctx, name+" restarting", err, nil)
		}
		select {
		case <-ctx.Done():
		case <-time.After(streak.Wait(every)):
		}
	}
}

// protect runs fn and reports a panic, returning it as an error. The event goes
// through a clone of the hub because ctx's hub may belong to a request that is
// still using it.
func protect(ctx context.Context, name string, fn func()) (err error) {
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		err = fmt.Errorf("panic: %v", rec)
		log.Printf("%s panicked: %v\n%s", name, rec, debug.Stack())
		hub := sentry.GetHubFromContext(ctx)
		if hub == nil {
			hub = sentry.CurrentHub()
		}
		hub = hub.Clone()
		hub.Scope().SetFingerprint([]string{"panic", name})
		hub.Scope().SetTag("task", name)
		hub.RecoverWithContext(ctx, rec)
	}()
	fn()
	return nil
}
