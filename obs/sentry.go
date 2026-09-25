package obs

import (
	"log"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"
)

// Config parameterises Init.
type Config struct {
	// Service is required. It sets the "service" tag on every event so one
	// Sentry project can carry more than one service.
	Service string

	// ExtraScrubHeaders and ExtraScrubFields are appended to the built-in
	// scrub lists. A caller can grow the lists, never shrink them.
	ExtraScrubHeaders []string
	ExtraScrubFields  []string
}

// defaultScrubHeaders are redacted from an event's request headers before send.
var defaultScrubHeaders = []string{
	"Cookie",
	"Set-Cookie",
	"Authorization",
	"X-Stripe-Signature",
}

// defaultScrubFields are redacted from a urlencoded request body before send.
var defaultScrubFields = []string{
	"password",
	"current_password",
	"new_password",
	"confirm_password",
	"token",
	"session_token",
}

// Init configures the global Sentry hub from the environment:
//
//   - SENTRY_DSN                (required; empty disables Sentry entirely)
//   - SENTRY_ENVIRONMENT        (defaults to "development")
//   - SENTRY_RELEASE            (defaults to the binary's vcs.revision)
//   - SENTRY_TRACES_SAMPLE_RATE (defaults to 0)
//
// It returns a flush function the caller should defer. Init panics if
// cfg.Service is empty.
func Init(cfg Config) func() {
	return initWith(cfg, nil)
}

// initWith is the seam Init and the tests share: the test passes a
// sentry.TransportMock so no assertion path touches the network.
func initWith(cfg Config, transport sentry.Transport) func() {
	if cfg.Service == "" {
		panic("obs: Config.Service is required")
	}

	scrub := scrubber{
		headers: slices.Concat(defaultScrubHeaders, cfg.ExtraScrubHeaders),
		fields:  slices.Concat(defaultScrubFields, cfg.ExtraScrubFields),
	}

	dsn := os.Getenv("SENTRY_DSN")
	if dsn == "" {
		log.Printf("sentry disabled (no DSN configured)")
		return func() {}
	}

	env := os.Getenv("SENTRY_ENVIRONMENT")
	if env == "" {
		env = "development"
	}
	release := os.Getenv("SENTRY_RELEASE")
	if release == "" {
		release = Revision()
	}
	tracesRate := 0.0
	if v := os.Getenv("SENTRY_TRACES_SAMPLE_RATE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			tracesRate = f
		}
	}

	// PII collection stays off: that is the SDK default, so it is not set
	// explicitly (the SendDefaultPII option is deprecated in sentry-go).
	opts := sentry.ClientOptions{
		Dsn:         dsn,
		Environment: env,
		Release:     release,
		// EnableTracing is sentry-go's separate master switch for performance
		// tracing — without it, TracesSampleRate is silently ignored and no
		// transaction is ever sampled, regardless of its value.
		EnableTracing:    tracesRate > 0,
		TracesSampleRate: tracesRate,
		AttachStacktrace: true,
		BeforeSend:       scrub.beforeSend,
	}
	if transport != nil {
		opts.Transport = transport
	}

	if err := sentry.Init(opts); err != nil {
		log.Printf("sentry init failed; continuing without it: %v", err)
		return func() {}
	}

	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag("service", cfg.Service)
	})

	log.Printf("sentry initialised service=%s environment=%s release=%s", cfg.Service, env, release)
	return func() {
		sentry.Flush(2 * time.Second)
	}
}

type scrubber struct {
	headers []string
	fields  []string
}

func (s scrubber) beforeSend(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	if event.Request == nil {
		return event
	}
	for _, h := range s.headers {
		if _, ok := event.Request.Headers[h]; ok {
			event.Request.Headers[h] = "[scrubbed]"
		}
	}
	if event.Request.Cookies != "" {
		event.Request.Cookies = "[scrubbed]"
	}
	event.Request.Data = s.scrubFormBody(event.Request.Data)
	return event
}

func (s scrubber) scrubFormBody(body string) string {
	if body == "" || !strings.Contains(body, "=") {
		return body
	}
	parts := strings.Split(body, "&")
	for i, p := range parts {
		eq := strings.IndexByte(p, '=')
		if eq < 0 {
			continue
		}
		name := p[:eq]
		for _, f := range s.fields {
			if strings.EqualFold(name, f) {
				parts[i] = name + "=[scrubbed]"
				break
			}
		}
	}
	return strings.Join(parts, "&")
}
