package application

import (
	"context"
	"errors"

	"github.com/JustIkra/umir-auth/internal/domain"
)

type Actor string

const (
	ActorTenant    Actor = "tenant"
	ActorUser      Actor = "user"
	ActorAnonymous Actor = "anonymous"
	ActorSystem    Actor = "system"
)

type Scope struct {
	Actor        Actor
	OrgID        domain.EntityID
	RestaurantID domain.EntityID
	UserID       domain.EntityID
}

var (
	ErrEntityConflict   = errors.New("auth entity conflict")
	ErrReferenceMissing = errors.New("auth entity reference missing")
	ErrInvalidScope     = errors.New("invalid auth storage scope")
)

type Store interface {
	InTx(context.Context, Scope, func(Tx) error) (CommitResult, error)
	View(context.Context, Scope, func(Reader) error) error
}

type Reader interface {
	Users() UserReader
	Sessions() SessionReader
}

type Tx interface {
	Users() UserRepository
	Sessions() SessionRepository
}

type UserReader interface {
	Get(context.Context, domain.EntityID) (domain.User, bool, error)
}

type UserRepository interface {
	UserReader
	Insert(context.Context, domain.User) error
}

type SessionReader interface {
	Get(context.Context, domain.EntityID) (domain.Session, bool, error)
	ByDigest(context.Context, string) (domain.Session, bool, error)
	ForUser(context.Context, domain.EntityID) ([]domain.Session, error)
}

type SessionRepository interface {
	SessionReader
	Insert(context.Context, domain.Session) error
}
