package obs

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/getsentry/sentry-go"
)

func TestScrubFormBody(t *testing.T) {
	s := scrubber{headers: defaultScrubHeaders, fields: defaultScrubFields}

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"no equals", "not a form body", "not a form body"},
		{"single secret", "password=hunter2", "password=[scrubbed]"},
		{"secret among fields", "a=1&password=hunter2&c=3", "a=1&password=[scrubbed]&c=3"},
		{"case insensitive name", "Password=hunter2", "Password=[scrubbed]"},
		{"session token", "session_token=abc.def", "session_token=[scrubbed]"},
		{"nothing sensitive", "email=a@b.com&page=2", "email=a@b.com&page=2"},
		{"valueless pair kept", "flag&password=x", "flag&password=[scrubbed]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.scrubFormBody(tc.in); got != tc.want {
				t.Fatalf("scrubFormBody(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBeforeSendScrubsRequest(t *testing.T) {
	s := scrubber{headers: defaultScrubHeaders, fields: defaultScrubFields}

	event := sentry.NewEvent()
	event.Request = &sentry.Request{
		Headers: map[string]string{
			"Authorization": "Bearer secret",
			"X-Request-Id":  "keep-me",
		},
		Cookies: "session=abc",
		Data:    "user=alice&password=hunter2",
	}

	got := s.beforeSend(event, nil)

	if got.Request.Headers["Authorization"] != "[scrubbed]" {
		t.Errorf("Authorization header not scrubbed: %q", got.Request.Headers["Authorization"])
	}
	if got.Request.Headers["X-Request-Id"] != "keep-me" {
		t.Errorf("non-sensitive header was altered: %q", got.Request.Headers["X-Request-Id"])
	}
	if got.Request.Cookies != "[scrubbed]" {
		t.Errorf("cookies not scrubbed: %q", got.Request.Cookies)
	}
	if got.Request.Data != "user=alice&password=[scrubbed]" {
		t.Errorf("body not scrubbed: %q", got.Request.Data)
	}
}

func TestBeforeSendNoRequest(t *testing.T) {
	s := scrubber{headers: defaultScrubHeaders, fields: defaultScrubFields}
	event := sentry.NewEvent()
	if got := s.beforeSend(event, nil); got != event {
		t.Fatal("beforeSend should return the event unchanged when Request is nil")
	}
}

func TestExtraScrubEntriesAppendToDefaults(t *testing.T) {
	scrub := scrubber{
		headers: append(append([]string(nil), defaultScrubHeaders...), "X-Api-Key"),
		fields:  append(append([]string(nil), defaultScrubFields...), "otp"),
	}

	if got := scrub.scrubFormBody("otp=123456&token=t&keep=1"); got != "otp=[scrubbed]&token=[scrubbed]&keep=1" {
		t.Errorf("extra field not scrubbed alongside defaults: %q", got)
	}

	event := sentry.NewEvent()
	event.Request = &sentry.Request{Headers: map[string]string{"X-Api-Key": "k", "Cookie": "c"}}
	got := scrub.beforeSend(event, nil)
	if got.Request.Headers["X-Api-Key"] != "[scrubbed]" {
		t.Errorf("extra header not scrubbed: %q", got.Request.Headers["X-Api-Key"])
	}
	if got.Request.Headers["Cookie"] != "[scrubbed]" {
		t.Errorf("default header no longer scrubbed after adding an extra: %q", got.Request.Headers["Cookie"])
	}
}

func TestInitPanicsWithoutService(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Init(Config{}) should panic when Service is empty")
		}
	}()
	Init(Config{})
}

func TestInitNoDSNReturnsUsableFlush(t *testing.T) {
	t.Setenv("SENTRY_DSN", "")
	flush := Init(Config{Service: "widget"})
	if flush == nil {
		t.Fatal("Init returned a nil flush func")
	}
	flush() // must not panic
}

func TestInitSetsServiceTag(t *testing.T) {
	t.Setenv("SENTRY_DSN", "https://key@example.test/1")
	mock := &sentry.MockTransport{}

	// initWith binds a client onto the global hub, like every real caller.
	// Unbind it afterwards so a later test cannot capture into this mock.
	t.Cleanup(func() { sentry.CurrentHub().BindClient(nil) })

	flush := initWith(Config{Service: "widget"}, mock)
	defer flush()

	sentry.CaptureException(errors.New("boom"))
	flush()

	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Tags["service"] != "widget" {
		t.Errorf("service tag = %q, want %q", events[0].Tags["service"], "widget")
	}
}

func TestCaptureUsesContextHub(t *testing.T) {
	mock := &sentry.MockTransport{}
	client, err := sentry.NewClient(sentry.ClientOptions{
		Dsn:       "https://key@example.test/1",
		Transport: mock,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hub := sentry.NewHub(client, sentry.NewScope())
	ctx := sentry.SetHubOnContext(context.Background(), hub)

	Capture(ctx, "widget lookup failed", errors.New("boom"), "widget_id", 42, "attempt", "final")
	hub.Flush(0)

	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("got %d events on the context hub, want 1", len(events))
	}
}

func TestServerErrorWritesJSON500(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/things/1", nil)

	ServerError(rec, req, "could not load thing", errors.New("db down"))

	if rec.Code != 500 {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if body := rec.Body.String(); body != "{\"error\":\"could not load thing\"}\n" {
		t.Errorf("body = %q", body)
	}
}

func TestStrFormatsNonStringFields(t *testing.T) {
	// str falls through to jsonString for values that are neither string
	// nor error; logFields must not panic on them.
	logFields("mixed fields", nil, "count", 3, "meta", map[string]int{"a": 1})
}

func TestRevisionSafeInTest(t *testing.T) {
	// In `go test` the binary carries no vcs.revision, so this is "".
	// The point is that Revision never panics and returns a plain string.
	if r := Revision(); r != "" && len(r) != 40 {
		t.Errorf("Revision() = %q, want empty or a 40-char SHA", r)
	}
}
