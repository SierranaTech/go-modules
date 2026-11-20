package obs

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var mintedID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// serveRequestID runs one request through RequestID and returns the ID the
// handler saw on its context and request header, and the response.
func serveRequestID(t *testing.T, incoming string) (ctxID, headerID string, rec *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if incoming != "" {
		req.Header.Set(RequestIDHeader, incoming)
	}
	rec = httptest.NewRecorder()
	RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ctxID = RequestIDFromContext(r.Context())
		headerID = r.Header.Get(RequestIDHeader)
	})).ServeHTTP(rec, req)
	return ctxID, headerID, rec
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &logs
}

func TestRequestIDKeepsAWellFormedIncomingID(t *testing.T) {
	ctxID, headerID, rec := serveRequestID(t, "8f1a2b3c4d5e6f70-LHR")

	if ctxID != "8f1a2b3c4d5e6f70-LHR" {
		t.Errorf("context ID = %q, want the incoming ID", ctxID)
	}
	if headerID != ctxID {
		t.Errorf("request header = %q, want %q", headerID, ctxID)
	}
	if got := rec.Header().Get(RequestIDHeader); got != ctxID {
		t.Errorf("response header = %q, want %q", got, ctxID)
	}
}

func TestRequestIDMintsAFreshIDWhenMissingOrMalformed(t *testing.T) {
	cases := []struct {
		name     string
		incoming string
	}{
		{"missing", ""},
		{"control character", "abc\ndef"},
		{"space", "abc def"},
		{"non-ascii", "abcé"},
		{"too long", strings.Repeat("a", maxRequestIDLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctxID, headerID, rec := serveRequestID(t, tc.incoming)

			if !mintedID.MatchString(ctxID) {
				t.Errorf("context ID = %q, want a fresh 32-character hex ID", ctxID)
			}
			if headerID != ctxID || rec.Header().Get(RequestIDHeader) != ctxID {
				t.Errorf("request header %q and response header %q, want both %q",
					headerID, rec.Header().Get(RequestIDHeader), ctxID)
			}
		})
	}
}

func TestRequestIDMintsADifferentIDPerRequest(t *testing.T) {
	first, _, _ := serveRequestID(t, "")
	second, _, _ := serveRequestID(t, "")
	if first == second {
		t.Errorf("two requests got the same ID %q", first)
	}
}

func TestRequestIDReachesTheSentryScopeAndCaptureLog(t *testing.T) {
	ctx, _, mock := streakHub(t)
	logs := captureLog(t)

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, "req-123")
	RequestID(Recoverer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		Capture(r.Context(), "lookup failed", errors.New("boom"), "widget_id", 42)
	}))).ServeHTTP(httptest.NewRecorder(), req)

	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if got := events[0].Tags["request_id"]; got != "req-123" {
		t.Errorf("request_id tag = %q, want req-123", got)
	}
	if !strings.Contains(logs.String(), "request_id=req-123") {
		t.Errorf("log = %q, want it to carry request_id=req-123", logs.String())
	}
}

func TestCaptureWithoutRequestIDLeavesTheLogAlone(t *testing.T) {
	ctx, _, _ := streakHub(t)
	logs := captureLog(t)

	Capture(ctx, "lookup failed", errors.New("boom"))

	if strings.Contains(logs.String(), "request_id") {
		t.Errorf("log = %q, want no request_id without one on the context", logs.String())
	}
}

func TestPropagateRequestIDSendsTheContextID(t *testing.T) {
	cases := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"with ID", WithRequestID(context.Background(), "req-123"), "req-123"},
		{"without ID", context.Background(), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = r.Header.Get(RequestIDHeader)
			}))
			t.Cleanup(srv.Close)
			client := &http.Client{Transport: PropagateRequestID(nil)}

			req, err := http.NewRequestWithContext(tc.ctx, http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			_ = resp.Body.Close()

			if got != tc.want {
				t.Errorf("server saw %s %q, want %q", RequestIDHeader, got, tc.want)
			}
			if req.Header.Get(RequestIDHeader) != "" {
				t.Error("the caller's request was modified")
			}
		})
	}
}
