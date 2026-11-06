package obs

import (
	"errors"
	"testing"

	"github.com/getsentry/sentry-go"
)

func TestRunMonitoredReportsCheckIns(t *testing.T) {
	cases := []struct {
		name    string
		fnErr   error
		wantEnd sentry.CheckInStatus
	}{
		{"success", nil, sentry.CheckInStatusOK},
		{"failure", errors.New("boom"), sentry.CheckInStatusError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, hub, transport := streakHub(t)

			ran := false
			err := RunMonitored(hub, "test-job", "0 2 * * *", "Europe/London", 30, func() error {
				ran = true
				return tc.fnErr
			})

			if !ran {
				t.Fatal("fn did not run")
			}
			if !errors.Is(err, tc.fnErr) {
				t.Errorf("err = %v, want %v", err, tc.fnErr)
			}
			events := transport.Events()
			if len(events) != 2 {
				t.Fatalf("got %d check-in events, want 2", len(events))
			}
			first, last := events[0].CheckIn, events[1].CheckIn
			if first == nil || last == nil {
				t.Fatal("events are not check-ins")
			}
			if first.Status != sentry.CheckInStatusInProgress {
				t.Errorf("first status = %q, want in_progress", first.Status)
			}
			if last.Status != tc.wantEnd {
				t.Errorf("last status = %q, want %q", last.Status, tc.wantEnd)
			}
			if first.ID != last.ID || first.MonitorSlug != "test-job" || last.MonitorSlug != "test-job" {
				t.Errorf("check-ins do not pair: %+v / %+v", first, last)
			}
			if events[0].MonitorConfig == nil || events[0].MonitorConfig.Timezone != "Europe/London" {
				t.Errorf("monitor config not sent: %+v", events[0].MonitorConfig)
			}
		})
	}
}

func TestRunMonitoredWithoutClientStillRunsFn(t *testing.T) {
	hub := sentry.NewHub(nil, sentry.NewScope())
	want := errors.New("boom")
	err := RunMonitored(hub, "test-job", "0 2 * * *", "Europe/London", 30, func() error { return want })
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want %v", err, want)
	}
}
