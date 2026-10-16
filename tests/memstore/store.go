package memstore

import (
	"context"
	"strconv"
	"sync"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type Store struct {
	mu       sync.RWMutex
	users    map[domain.EntityID]domain.User
	revision domain.Version
}

func New() *Store {
	return &Store{users: make(map[domain.EntityID]domain.User), revision: "1"}
}

func (s *Store) InTx(ctx context.Context, scope application.Scope, fn func(application.Tx) error) (application.CommitResult, error) {
	if err := check(ctx, scope); err != nil {
		return application.CommitResult{Outcome: application.NotCommitted}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := domain.VersionNumber(s.revision)
	if !ok || n == int64(^uint64(0)>>1) {
		return application.CommitResult{Outcome: application.NotCommitted}, application.ErrStorageUnavailable
	}
	users := cloneUsers(s.users)
	tx := transaction{users: users}
	if err := fn(tx); err != nil {
		return application.CommitResult{Outcome: application.NotCommitted}, err
	}
	if err := ctx.Err(); err != nil {
		return application.CommitResult{Outcome: application.NotCommitted}, err
	}
	s.revision = domain.Version(strconv.FormatInt(n+1, 10))
	s.users = users
	return application.CommitResult{Outcome: application.Committed, AggregateRevision: s.revision}, nil
}

func (s *Store) View(ctx context.Context, scope application.Scope, fn func(application.Reader) error) error {
	if err := check(ctx, scope); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(reader{users: s.users})
}

type reader struct {
	users map[domain.EntityID]domain.User
}

func (r reader) Users() application.UserReader { return userReader(r) }

type transaction struct {
	users map[domain.EntityID]domain.User
}

func (t transaction) Users() application.UserRepository {
	return userRepository{userReader(t)}
}

type userReader struct {
	users map[domain.EntityID]domain.User
}

func (r userReader) Get(ctx context.Context, id domain.EntityID) (domain.User, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.User{}, false, err
	}
	user, ok := r.users[id]
	return user, ok, nil
}

type userRepository struct{ userReader }

func (r userRepository) Insert(ctx context.Context, user domain.User) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if user.UserID == "" || r.users[user.UserID].UserID != "" {
		return application.ErrEntityConflict
	}
	for _, existing := range r.users {
		if application.NormalizedLoginKey(existing.Login) == application.NormalizedLoginKey(user.Login) {
			return application.ErrEntityConflict
		}
	}
	r.users[user.UserID] = user
	return nil
}

func check(ctx context.Context, scope application.Scope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	switch scope.Actor {
	case application.ActorTenant, application.ActorUser, application.ActorAnonymous, application.ActorSystem:
		return nil
	default:
		return application.ErrInvalidScope
	}
}

func cloneUsers(users map[domain.EntityID]domain.User) map[domain.EntityID]domain.User {
	copyOf := make(map[domain.EntityID]domain.User, len(users))
	for id, user := range users {
		copyOf[id] = user
	}
	return copyOf
}

var _ application.Store = (*Store)(nil)
