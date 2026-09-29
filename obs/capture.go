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
// and scrubbed headers. Use it for mid-request errors that do not return
// a 500.
func Capture(ctx context.Context, msg string, err error, fields ...any) {
	logFields(msg, err, fields...)
	if hub := sentry.GetHubFromContext(ctx); hub != nil {
		hub.CaptureException(err)
		return
	}
	sentry.CaptureException(err)
}

// CaptureFingerprint behaves like Capture, but replaces Sentry's default
// grouping — the call site's stack trace — with an explicit fingerprint.
// Use it where one shared call site captures many distinct underlying
// causes (a generic reconcile-error wrapper, for example): without a
// fingerprint, every cause collapses into a single Sentry issue that can
// never be resolved, since a different cause keeps reopening it.
func CaptureFingerprint(ctx context.Context, msg string, err error, fingerprint []string, fields ...any) {
	logFields(msg, err, fields...)
	hub := sentry.GetHubFromContext(ctx)
	if hub == nil {
		hub = sentry.CurrentHub()
	}
	hub.WithScope(func(scope *sentry.Scope) {
		scope.SetFingerprint(fingerprint)
		hub.CaptureException(err)
	})
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
