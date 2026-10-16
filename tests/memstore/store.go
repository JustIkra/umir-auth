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
	sessions map[domain.EntityID]domain.Session
	commands map[application.CommandKey]domain.IdempotencyRecord
	revision domain.Version
}

func New() *Store {
	return &Store{users: make(map[domain.EntityID]domain.User), sessions: make(map[domain.EntityID]domain.Session), commands: make(map[application.CommandKey]domain.IdempotencyRecord), revision: "1"}
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
	sessions := cloneSessions(s.sessions)
	commands := cloneCommands(s.commands)
	tx := transaction{users: users, sessions: sessions, commands: commands}
	if err := fn(tx); err != nil {
		return application.CommitResult{Outcome: application.NotCommitted}, err
	}
	if err := ctx.Err(); err != nil {
		return application.CommitResult{Outcome: application.NotCommitted}, err
	}
	s.revision = domain.Version(strconv.FormatInt(n+1, 10))
	s.users = users
	s.sessions = sessions
	s.commands = commands
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
	return fn(reader{users: s.users, sessions: s.sessions, commands: s.commands})
}

type reader struct {
	users    map[domain.EntityID]domain.User
	sessions map[domain.EntityID]domain.Session
	commands map[application.CommandKey]domain.IdempotencyRecord
}

func (r reader) Users() application.UserReader { return userReader{users: r.users} }
func (r reader) Sessions() application.SessionReader {
	return sessionReader{users: r.users, sessions: r.sessions}
}
func (r reader) Commands() application.CommandReader { return commandReader{commands: r.commands} }

type transaction struct {
	users    map[domain.EntityID]domain.User
	sessions map[domain.EntityID]domain.Session
	commands map[application.CommandKey]domain.IdempotencyRecord
}

func (t transaction) Users() application.UserRepository {
	return userRepository{userReader{users: t.users}}
}

func (t transaction) Sessions() application.SessionRepository {
	return sessionRepository{sessionReader{users: t.users, sessions: t.sessions}}
}

func (t transaction) Commands() application.CommandRepository {
	return commandRepository{commandReader{commands: t.commands}}
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

type sessionReader struct {
	users    map[domain.EntityID]domain.User
	sessions map[domain.EntityID]domain.Session
}

func (r sessionReader) Get(ctx context.Context, id domain.EntityID) (domain.Session, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Session{}, false, err
	}
	session, ok := r.sessions[id]
	return session, ok, nil
}

func (r sessionReader) ByDigest(ctx context.Context, digest string) (domain.Session, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Session{}, false, err
	}
	for _, session := range r.sessions {
		if session.Digest == digest {
			return session, true, nil
		}
	}
	return domain.Session{}, false, nil
}

func (r sessionReader) ForUser(ctx context.Context, userID domain.EntityID) ([]domain.Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var sessions []domain.Session
	for _, session := range r.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

type sessionRepository struct{ sessionReader }

func (r sessionRepository) Insert(ctx context.Context, session domain.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if session.SessionID == "" || session.Digest == "" || r.sessions[session.SessionID].SessionID != "" {
		return application.ErrEntityConflict
	}
	if _, ok := r.users[session.UserID]; !ok {
		return application.ErrReferenceMissing
	}
	for _, existing := range r.sessions {
		if existing.Digest == session.Digest {
			return application.ErrEntityConflict
		}
	}
	r.sessions[session.SessionID] = session
	return nil
}

type commandReader struct {
	commands map[application.CommandKey]domain.IdempotencyRecord
}

func (r commandReader) Get(ctx context.Context, key application.CommandKey) (domain.IdempotencyRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.IdempotencyRecord{}, false, err
	}
	record, ok := r.commands[key]
	if ok {
		record.JobIDs = append([]domain.EntityID(nil), record.JobIDs...)
	}
	return record, ok, nil
}

type commandRepository struct{ commandReader }

func (r commandRepository) Insert(ctx context.Context, record domain.IdempotencyRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := application.CommandKeyOf(record)
	if key.OperationID == "" || key.CommandID == "" {
		return application.ErrInvalidCommand
	}
	if _, ok := r.commands[key]; ok {
		return application.ErrEntityConflict
	}
	record.JobIDs = append([]domain.EntityID(nil), record.JobIDs...)
	r.commands[key] = record
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

func cloneSessions(sessions map[domain.EntityID]domain.Session) map[domain.EntityID]domain.Session {
	copyOf := make(map[domain.EntityID]domain.Session, len(sessions))
	for id, session := range sessions {
		copyOf[id] = session
	}
	return copyOf
}

func cloneCommands(commands map[application.CommandKey]domain.IdempotencyRecord) map[application.CommandKey]domain.IdempotencyRecord {
	copyOf := make(map[application.CommandKey]domain.IdempotencyRecord, len(commands))
	for key, record := range commands {
		record.JobIDs = append([]domain.EntityID(nil), record.JobIDs...)
		copyOf[key] = record
	}
	return copyOf
}

var _ application.Store = (*Store)(nil)
