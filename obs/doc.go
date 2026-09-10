// Package obs wires Sentry into a SierranaTech service and carries the
// error-capture helpers the services were each copying.
//
// Init is a no-op when SENTRY_DSN is empty, so local development runs
// without sending anything. The flush function it returns must run before
// the process exits — defer it in main — so events still in flight at
// shutdown reach Sentry.
package obs
