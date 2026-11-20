package obs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/getsentry/sentry-go"
)

// RequestIDHeader carries the correlation ID between services.
const RequestIDHeader = "X-Request-Id"

// maxRequestIDLen bounds an incoming ID, which ends up in logs and Sentry tags.
const maxRequestIDLen = 128

type requestIDKey struct{}

// RequestID gives every request a correlation ID. It keeps a well-formed
// incoming X-Request-Id, otherwise it mints one. The ID goes on the request
// context, back onto the request header (so a reverse proxy and chi's
// middleware.RequestID pass it on unchanged) and onto the response.
//
// It must sit outside Recoverer, which tags the request's Sentry scope with
// the ID, and outside any access logger that should print it.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(RequestIDHeader)
		if !validRequestID(id) {
			id = newRequestID()
		}
		r.Header.Set(RequestIDHeader, id)
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), id)))
	})
}

// WithRequestID returns ctx carrying id, for work that starts outside an
// HTTP request but should still correlate.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext returns the correlation ID on ctx, or "".
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// PropagateRequestID wraps base (http.DefaultTransport when nil) so every
// outbound request whose context carries a correlation ID sends it as
// X-Request-Id.
func PropagateRequestID(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if id := RequestIDFromContext(req.Context()); id != "" {
			req = req.Clone(req.Context())
			req.Header.Set(RequestIDHeader, id)
		}
		return base.RoundTrip(req)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// tagRequestID runs inside sentryhttp, once the request's hub exists.
func tagRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := RequestIDFromContext(r.Context()); id != "" {
			if hub := sentry.GetHubFromContext(r.Context()); hub != nil {
				hub.Scope().SetTag("request_id", id)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// withRequestID appends ctx's correlation ID to Capture's key/value fields.
func withRequestID(ctx context.Context, fields []any) []any {
	if id := RequestIDFromContext(ctx); id != "" {
		return append(fields[:len(fields):len(fields)], "request_id", id)
	}
	return fields
}

func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] <= ' ' || id[i] > '~' {
			return false
		}
	}
	return true
}

func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
