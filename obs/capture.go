package obs

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/getsentry/sentry-go"
)

// Capture logs err and forwards it to Sentry using the per-request hub
// from ctx when present, so the event carries the request's URL, method
// and scrubbed headers. fields also become Sentry tags (the same
// key/value pairs the log line gets), so triaging an event in Sentry
// doesn't require cross-referencing logs to find out which resource it
// was about. Use it for mid-request errors that do not return a 500.
func Capture(ctx context.Context, msg string, err error, fields ...any) {
	logFields(msg, err, fields...)
	tags := tagsFromFields(fields...)
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub()
	}
	hub.WithScope(func(scope *sentry.Scope) {
		scope.SetTags(tags)
		hub.CaptureException(err)
	})
}

// CaptureFingerprint behaves like Capture, but replaces Sentry's default
// grouping — the call site's stack trace — with an explicit fingerprint.
// Use it where one shared call site captures many distinct underlying
// causes (a generic reconcile-error wrapper, for example): without a
// fingerprint, every cause collapses into a single Sentry issue that can
// never be resolved, since a different cause keeps reopening it.
func CaptureFingerprint(ctx context.Context, msg string, err error, fingerprint []string, fields ...any) {
	logFields(msg, err, fields...)
	tags := tagsFromFields(fields...)
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub()
	}
	hub.WithScope(func(scope *sentry.Scope) {
		scope.SetFingerprint(fingerprint)
		scope.SetTags(tags)
		hub.CaptureException(err)
	})
}

// tagsFromFields converts Capture/CaptureFingerprint's key/value pairs
// into Sentry tags, using the same formatting logFields uses so a tag
// value matches what the log line shows.
func tagsFromFields(fields ...any) map[string]string {
	tags := make(map[string]string, len(fields)/2)
	for i := 0; i+1 < len(fields); i += 2 {
		key, ok := fields[i].(string)
		if !ok {
			continue
		}
		tags[key] = str(fields[i+1])
	}
	return tags
}

// AddBreadcrumb records a breadcrumb on ctx's Sentry hub (or the current hub
// when ctx carries none), so an error captured later in the same unit of
// work shows the steps that led up to it, not just which one failed.
func AddBreadcrumb(ctx context.Context, category, message string) {
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub()
	}
	hub.AddBreadcrumb(&sentry.Breadcrumb{
		Category: category,
		Message:  message,
		Level:    sentry.LevelInfo,
	}, nil)
}

// ClearBreadcrumbs clears ctx's Sentry hub's breadcrumb trail (or the
// current hub's when ctx carries none). Call it once at the start of a unit
// of work that uses AddBreadcrumb (e.g. once per reconcile), so an error
// captured at the end shows only this unit's own trail rather than
// breadcrumbs left over from an earlier, unrelated one.
//
// Safe only when callers of AddBreadcrumb for that unit of work run
// single-threaded against this hub — concurrent callers sharing one hub
// would race and clear each other's breadcrumbs. If a caller ever needs
// concurrent isolation, give each unit of work its own cloned hub via
// sentry.SetHubOnContext(ctx, sentry.CurrentHub().Clone()) instead of
// relying on this.
func ClearBreadcrumbs(ctx context.Context) {
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub()
	}
	hub.Scope().ClearBreadcrumbs()
}

// ServerError captures err and writes a 500 response with body
// {"error": msg}. The caller still owns the return.
func ServerError(w http.ResponseWriter, r *http.Request, msg string, err error, fields ...any) {
	Capture(r.Context(), msg, err, fields...)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func logFields(msg string, err error, fields ...any) {
	out := msg + " error=" + errStr(err)
	for i := 0; i+1 < len(fields); i += 2 {
		out += " " + str(fields[i]) + "=" + str(fields[i+1])
	}
	log.Print(out)
}

func errStr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case error:
		return t.Error()
	default:
		return jsonString(v)
	}
}

func jsonString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	return string(b)
}
