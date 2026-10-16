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

type CommandKey struct {
	ActorID       domain.EntityID
	PreauthDigest string
	OperationID   string
	OrgID         domain.EntityID
	RestaurantID  domain.EntityID
	CommandID     string
}

func CommandKeyOf(record domain.IdempotencyRecord) CommandKey {
	return CommandKey{ActorID: record.ActorID, PreauthDigest: record.PreauthDigest, OperationID: record.OperationID, OrgID: record.OrgID, RestaurantID: record.RestaurantID, CommandID: record.CommandID}
}

var (
	ErrEntityConflict   = errors.New("auth entity conflict")
	ErrInvalidCommand   = errors.New("invalid auth command identity")
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
	Commands() CommandReader
	Organizations() OrganizationReader
	Restaurants() RestaurantReader
}

type Tx interface {
	Users() UserRepository
	Sessions() SessionRepository
	Commands() CommandRepository
	Organizations() OrganizationRepository
	Restaurants() RestaurantRepository
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

type CommandReader interface {
	Get(context.Context, CommandKey) (domain.IdempotencyRecord, bool, error)
}

type CommandRepository interface {
	CommandReader
	Insert(context.Context, domain.IdempotencyRecord) error
}

type OrganizationReader interface {
	Get(context.Context, domain.EntityID) (domain.Organization, bool, error)
}

type OrganizationRepository interface {
	OrganizationReader
	Insert(context.Context, domain.Organization) error
}

type RestaurantReader interface {
	Get(context.Context, domain.EntityID) (domain.Restaurant, bool, error)
	ForOrganization(context.Context, domain.EntityID) ([]domain.Restaurant, error)
}

type RestaurantRepository interface {
	RestaurantReader
	Insert(context.Context, domain.Restaurant) error
}
