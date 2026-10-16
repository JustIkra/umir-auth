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
	ErrEntityConflict     = errors.New("auth entity conflict")
	ErrInvalidCommand     = errors.New("invalid auth command identity")
	ErrReferenceMissing   = errors.New("auth entity reference missing")
	ErrInvalidScope       = errors.New("invalid auth storage scope")
	ErrScopeMismatch      = errors.New("auth entity scope mismatch")
	ErrLeaseLost          = errors.New("auth work lease lost")
	ErrInvalidMailJob     = errors.New("invalid auth mail job")
	ErrInvalidBudgetEvent = errors.New("invalid auth budget event")
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
	Memberships() MembershipReader
	Invitations() InvitationReader
	Challenges() ChallengeReader
	MailJobs() MailJobReader
	Budgets() BudgetReader
}

type Tx interface {
	Users() UserRepository
	Sessions() SessionRepository
	Commands() CommandRepository
	Organizations() OrganizationRepository
	Restaurants() RestaurantRepository
	Memberships() MembershipRepository
	Invitations() InvitationRepository
	Challenges() ChallengeRepository
	MailJobs() MailJobRepository
	Budgets() BudgetRepository
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

type MembershipReader interface {
	Get(context.Context, domain.EntityID) (domain.Membership, bool, error)
	ForUserInOrganization(context.Context, domain.EntityID, domain.EntityID) (domain.Membership, bool, error)
}

type MembershipRepository interface {
	MembershipReader
	Insert(context.Context, domain.Membership) error
}

type InvitationReader interface {
	Get(context.Context, domain.EntityID) (domain.Invitation, bool, error)
	ForOrganization(context.Context, domain.EntityID) ([]domain.Invitation, error)
	PendingByEmail(context.Context, domain.EntityID, string) (domain.Invitation, bool, error)
}

type InvitationRepository interface {
	InvitationReader
	Insert(context.Context, domain.Invitation) error
}

type ChallengeReader interface {
	Get(context.Context, domain.EntityID) (domain.Challenge, bool, error)
}

type ChallengeRepository interface {
	ChallengeReader
	Insert(context.Context, domain.Challenge) error
	ConsumeProof(context.Context, domain.EntityID, string) (bool, error)
}

type MailJobReader interface {
	Get(context.Context, domain.EntityID) (domain.MailJob, bool, error)
}

type MailJobRepository interface {
	MailJobReader
	Insert(context.Context, domain.MailJob) error
	Claim(context.Context, domain.EntityID, string, domain.Instant, domain.Instant) (bool, domain.MailJob, error)
	Finish(context.Context, domain.EntityID, string, int, string, string) error
}

type BudgetEvent struct {
	Kind      string
	KeyDigest string
	At        domain.Instant
}

type BudgetReader interface {
	CountSince(context.Context, string, string, domain.Instant) (int, error)
}

type BudgetRepository interface {
	BudgetReader
	Record(context.Context, BudgetEvent) error
}
