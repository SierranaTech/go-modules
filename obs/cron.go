package obs

import (
	"time"

	"github.com/getsentry/sentry-go"
)

// RunMonitored runs fn as one execution of a Sentry cron monitor: an
// in_progress check-in before, ok or error after. Sentry upserts the monitor
// from the config on the first check-in, so nothing is created by hand.
// schedule and timezone must match the CronJob manifest in homelab. With no
// Sentry client bound (no DSN) the check-ins are skipped and fn still runs.
func RunMonitored(hub *sentry.Hub, slug, schedule, timezone string, maxMinutes int64, fn func() error) error {
	cfg := &sentry.MonitorConfig{
		Schedule:              sentry.CrontabSchedule(schedule),
		Timezone:              timezone,
		CheckInMargin:         maxMinutes,
		MaxRuntime:            maxMinutes,
		FailureIssueThreshold: 1,
		RecoveryThreshold:     1,
	}
	start := time.Now()
	id := hub.CaptureCheckIn(&sentry.CheckIn{MonitorSlug: slug, Status: sentry.CheckInStatusInProgress}, cfg)
	err := fn()
	if id == nil {
		return err
	}
	status := sentry.CheckInStatusOK
	if err != nil {
		status = sentry.CheckInStatusError
	}
	hub.CaptureCheckIn(&sentry.CheckIn{
		ID:          *id,
		MonitorSlug: slug,
		Status:      status,
		Duration:    time.Since(start),
	}, cfg)
	return err
}
