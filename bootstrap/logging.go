package bootstrap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
)

const logSchemaVersion = 1

var moscow = time.FixedZone("Europe/Moscow", 3*3600)

// NewLogger writes JSON log records in the shape of the factory observability
// document (section 3): time with the +03:00 offset, level, msg, event,
// log_schema_version, service, version and instance_id. Callers pass event and
// only identifiers, states and counters as attributes; no code, address, token or
// ciphertext is ever logged.
func NewLogger(w io.Writer, version, instanceID string) *slog.Logger {
	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelInfo,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.String(slog.TimeKey, a.Value.Time().In(moscow).Format(time.RFC3339Nano))
			}
			return a
		},
	})
	return slog.New(handler).With("log_schema_version", logSchemaVersion, "service", "umir-auth", "version", version, "instance_id", instanceID)
}

func discardLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// errorClass is the fixed, non-identifying name of a worker error for the log.
func errorClass(err error) string {
	switch {
	case errors.Is(err, application.ErrRecoveryRequired):
		return "recovery_required"
	case errors.Is(err, application.ErrUpdateOutcomeUnknown):
		return "update_outcome_unknown"
	case errors.Is(err, application.ErrClosed):
		return "closed"
	case errors.Is(err, application.ErrStorageUnavailable):
		return "storage_unavailable"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	default:
		return "other"
	}
}

// fatalWorkerError reports an error after which the process must stop: the stored
// state is in doubt or the store is gone, so continuing could serve or write
// wrong data. Everything else is waited out.
func fatalWorkerError(err error) bool {
	return errors.Is(err, application.ErrRecoveryRequired) || errors.Is(err, application.ErrUpdateOutcomeUnknown) || errors.Is(err, application.ErrClosed)
}

// loggingMailSender records each delivery attempt: job id, attempt number, age and
// outcome, never the recipient or the content.
type loggingMailSender struct {
	sender application.MailSender
	log    *slog.Logger
}

func (s loggingMailSender) Send(ctx context.Context, d application.MailDelivery) application.DeliveryResult {
	result := s.sender.Send(ctx, d)
	state, level := "retry", slog.LevelWarn
	switch {
	case result.Success:
		state, level = "sent", slog.LevelInfo
	case result.Permanent:
		state, level = "permanent_failure", slog.LevelError
	case result.Unknown:
		state = "unknown"
	}
	s.log.Log(ctx, level, "mail delivery attempt", "event", "auth.mail.attempt", "job_id", string(d.JobID), "attempt", d.Attempt, "age_seconds", int64(d.Age/time.Second), "state", state)
	return result
}
