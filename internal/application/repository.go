package application

import (
	"context"
	"errors"

	"github.com/JustIkra/umir-auth/internal/domain"
)

type CommitOutcome string

const (
	Committed    CommitOutcome = "committed"
	NotCommitted CommitOutcome = "not_committed"
	Unknown      CommitOutcome = "unknown"
)

type CommitResult struct {
	Outcome           CommitOutcome
	AggregateRevision domain.Version
}

var (
	ErrRevisionConflict   = errors.New("auth aggregate revision conflict")
	ErrWriterLocked       = errors.New("auth writer already locked")
	ErrRecoveryRequired   = errors.New("auth storage recovery required")
	ErrClosed             = errors.New("auth store closed")
	ErrStorageUnavailable = errors.New("auth storage unavailable")
)

type AggregateRepository interface {
	Load(context.Context) (domain.ValidatedAggregate, error)
	Commit(context.Context, domain.Version, domain.ValidatedAggregate) (CommitResult, error)
}
