package memstore

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

type Store struct {
	mu           sync.RWMutex
	users        map[domain.EntityID]domain.User
	sessions     map[domain.EntityID]domain.Session
	commands     map[application.CommandKey]domain.IdempotencyRecord
	orgs         map[domain.EntityID]domain.Organization
	restaurants  map[domain.EntityID]domain.Restaurant
	memberships  map[domain.EntityID]domain.Membership
	invitations  map[domain.EntityID]domain.Invitation
	challenges   map[domain.EntityID]domain.Challenge
	mailJobs     map[domain.EntityID]domain.MailJob
	budgetEvents []application.BudgetEvent
	outbox       map[domain.EntityID]application.OutboxEvent
	revision     domain.Version
}

func New() *Store {
	return &Store{users: make(map[domain.EntityID]domain.User), sessions: make(map[domain.EntityID]domain.Session), commands: make(map[application.CommandKey]domain.IdempotencyRecord), orgs: make(map[domain.EntityID]domain.Organization), restaurants: make(map[domain.EntityID]domain.Restaurant), memberships: make(map[domain.EntityID]domain.Membership), invitations: make(map[domain.EntityID]domain.Invitation), challenges: make(map[domain.EntityID]domain.Challenge), mailJobs: make(map[domain.EntityID]domain.MailJob), outbox: make(map[domain.EntityID]application.OutboxEvent), revision: "1"}
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
	orgs := cloneOrganizations(s.orgs)
	restaurants := cloneRestaurants(s.restaurants)
	memberships := cloneMemberships(s.memberships)
	invitations := cloneInvitations(s.invitations)
	challenges := cloneChallenges(s.challenges)
	mailJobs := cloneMailJobs(s.mailJobs)
	budgetEvents := append([]application.BudgetEvent(nil), s.budgetEvents...)
	outbox := cloneOutbox(s.outbox)
	tx := transaction{users: users, sessions: sessions, commands: commands, orgs: orgs, restaurants: restaurants, memberships: memberships, invitations: invitations, challenges: challenges, mailJobs: mailJobs, budgetEvents: &budgetEvents, outbox: outbox}
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
	s.orgs = orgs
	s.restaurants = restaurants
	s.memberships = memberships
	s.invitations = invitations
	s.challenges = challenges
	s.mailJobs = mailJobs
	s.budgetEvents = budgetEvents
	s.outbox = outbox
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
	return fn(reader{users: s.users, sessions: s.sessions, commands: s.commands, orgs: s.orgs, restaurants: s.restaurants, memberships: s.memberships, invitations: s.invitations, challenges: s.challenges, mailJobs: s.mailJobs, budgetEvents: s.budgetEvents, outbox: s.outbox})
}

type reader struct {
	users        map[domain.EntityID]domain.User
	sessions     map[domain.EntityID]domain.Session
	commands     map[application.CommandKey]domain.IdempotencyRecord
	orgs         map[domain.EntityID]domain.Organization
	restaurants  map[domain.EntityID]domain.Restaurant
	memberships  map[domain.EntityID]domain.Membership
	invitations  map[domain.EntityID]domain.Invitation
	challenges   map[domain.EntityID]domain.Challenge
	mailJobs     map[domain.EntityID]domain.MailJob
	budgetEvents []application.BudgetEvent
	outbox       map[domain.EntityID]application.OutboxEvent
}

func (r reader) Users() application.UserReader { return userReader{users: r.users} }
func (r reader) Sessions() application.SessionReader {
	return sessionReader{users: r.users, sessions: r.sessions}
}
func (r reader) Commands() application.CommandReader { return commandReader{commands: r.commands} }
func (r reader) Organizations() application.OrganizationReader {
	return organizationReader{orgs: r.orgs}
}
func (r reader) Restaurants() application.RestaurantReader {
	return restaurantReader{orgs: r.orgs, restaurants: r.restaurants}
}
func (r reader) Memberships() application.MembershipReader {
	return membershipReader{memberships: r.memberships}
}
func (r reader) Invitations() application.InvitationReader {
	return invitationReader{orgs: r.orgs, restaurants: r.restaurants, invitations: r.invitations}
}
func (r reader) Challenges() application.ChallengeReader {
	return challengeReader{challenges: r.challenges}
}
func (r reader) MailJobs() application.MailJobReader { return mailJobReader{mailJobs: r.mailJobs} }
func (r reader) Budgets() application.BudgetReader   { return budgetReader{events: r.budgetEvents} }
func (r reader) Outbox() application.OutboxReader    { return outboxRepository{events: r.outbox} }

type transaction struct {
	users        map[domain.EntityID]domain.User
	sessions     map[domain.EntityID]domain.Session
	commands     map[application.CommandKey]domain.IdempotencyRecord
	orgs         map[domain.EntityID]domain.Organization
	restaurants  map[domain.EntityID]domain.Restaurant
	memberships  map[domain.EntityID]domain.Membership
	invitations  map[domain.EntityID]domain.Invitation
	challenges   map[domain.EntityID]domain.Challenge
	mailJobs     map[domain.EntityID]domain.MailJob
	budgetEvents *[]application.BudgetEvent
	outbox       map[domain.EntityID]application.OutboxEvent
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
func (t transaction) Organizations() application.OrganizationRepository {
	return organizationRepository{organizationReader{orgs: t.orgs}}
}
func (t transaction) Restaurants() application.RestaurantRepository {
	return restaurantRepository{restaurantReader{orgs: t.orgs, restaurants: t.restaurants}}
}
func (t transaction) Memberships() application.MembershipRepository {
	return membershipRepository{users: t.users, orgs: t.orgs, restaurants: t.restaurants, memberships: t.memberships}
}
func (t transaction) Invitations() application.InvitationRepository {
	return invitationRepository{invitationReader{orgs: t.orgs, restaurants: t.restaurants, invitations: t.invitations}}
}
func (t transaction) Challenges() application.ChallengeRepository {
	return challengeRepository{challengeReader{challenges: t.challenges}}
}
func (t transaction) MailJobs() application.MailJobRepository {
	return mailJobRepository{mailJobReader{mailJobs: t.mailJobs}}
}
func (t transaction) Budgets() application.BudgetRepository {
	return budgetRepository{budgetReader{events: *t.budgetEvents}, t.budgetEvents}
}
func (t transaction) Outbox() application.OutboxRepository { return outboxRepository{events: t.outbox} }

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

type organizationReader struct {
	orgs map[domain.EntityID]domain.Organization
}

func (r organizationReader) Get(ctx context.Context, id domain.EntityID) (domain.Organization, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Organization{}, false, err
	}
	org, ok := r.orgs[id]
	return org, ok, nil
}

type organizationRepository struct{ organizationReader }

func (r organizationRepository) Insert(ctx context.Context, org domain.Organization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if org.OrgID == "" || r.orgs[org.OrgID].OrgID != "" {
		return application.ErrEntityConflict
	}
	r.orgs[org.OrgID] = org
	return nil
}

type restaurantReader struct {
	orgs        map[domain.EntityID]domain.Organization
	restaurants map[domain.EntityID]domain.Restaurant
}

func (r restaurantReader) Get(ctx context.Context, id domain.EntityID) (domain.Restaurant, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Restaurant{}, false, err
	}
	restaurant, ok := r.restaurants[id]
	return restaurant, ok, nil
}

func (r restaurantReader) ForOrganization(ctx context.Context, orgID domain.EntityID) ([]domain.Restaurant, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var restaurants []domain.Restaurant
	for _, restaurant := range r.restaurants {
		if restaurant.OrgID == orgID {
			restaurants = append(restaurants, restaurant)
		}
	}
	return restaurants, nil
}

type restaurantRepository struct{ restaurantReader }

func (r restaurantRepository) Insert(ctx context.Context, restaurant domain.Restaurant) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if restaurant.RestaurantID == "" || r.restaurants[restaurant.RestaurantID].RestaurantID != "" {
		return application.ErrEntityConflict
	}
	if _, ok := r.orgs[restaurant.OrgID]; !ok {
		return application.ErrReferenceMissing
	}
	r.restaurants[restaurant.RestaurantID] = restaurant
	return nil
}

type membershipReader struct {
	memberships map[domain.EntityID]domain.Membership
}

func (r membershipReader) Get(ctx context.Context, id domain.EntityID) (domain.Membership, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Membership{}, false, err
	}
	membership, ok := r.memberships[id]
	return cloneMembership(membership), ok, nil
}

func (r membershipReader) ForUserInOrganization(ctx context.Context, userID, orgID domain.EntityID) (domain.Membership, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Membership{}, false, err
	}
	for _, membership := range r.memberships {
		if membership.UserID == userID && membership.OrgID == orgID {
			return cloneMembership(membership), true, nil
		}
	}
	return domain.Membership{}, false, nil
}

type membershipRepository struct {
	users       map[domain.EntityID]domain.User
	orgs        map[domain.EntityID]domain.Organization
	restaurants map[domain.EntityID]domain.Restaurant
	memberships map[domain.EntityID]domain.Membership
}

func (r membershipRepository) Get(ctx context.Context, id domain.EntityID) (domain.Membership, bool, error) {
	return (membershipReader{memberships: r.memberships}).Get(ctx, id)
}

func (r membershipRepository) ForUserInOrganization(ctx context.Context, userID, orgID domain.EntityID) (domain.Membership, bool, error) {
	return (membershipReader{memberships: r.memberships}).ForUserInOrganization(ctx, userID, orgID)
}

func (r membershipRepository) Insert(ctx context.Context, membership domain.Membership) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if membership.MembershipID == "" || r.memberships[membership.MembershipID].MembershipID != "" {
		return application.ErrEntityConflict
	}
	if _, ok := r.users[membership.UserID]; !ok {
		return application.ErrReferenceMissing
	}
	if _, ok := r.orgs[membership.OrgID]; !ok {
		return application.ErrReferenceMissing
	}
	for _, existing := range r.memberships {
		if existing.UserID == membership.UserID && existing.OrgID == membership.OrgID {
			return application.ErrEntityConflict
		}
	}
	for _, assignment := range membership.Assignments {
		restaurant, ok := r.restaurants[assignment.RestaurantID]
		if !ok {
			return application.ErrReferenceMissing
		}
		if restaurant.OrgID != membership.OrgID {
			return application.ErrScopeMismatch
		}
	}
	r.memberships[membership.MembershipID] = cloneMembership(membership)
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

func cloneOrganizations(orgs map[domain.EntityID]domain.Organization) map[domain.EntityID]domain.Organization {
	copyOf := make(map[domain.EntityID]domain.Organization, len(orgs))
	for id, org := range orgs {
		copyOf[id] = org
	}
	return copyOf
}

func cloneRestaurants(restaurants map[domain.EntityID]domain.Restaurant) map[domain.EntityID]domain.Restaurant {
	copyOf := make(map[domain.EntityID]domain.Restaurant, len(restaurants))
	for id, restaurant := range restaurants {
		copyOf[id] = restaurant
	}
	return copyOf
}

func cloneMemberships(memberships map[domain.EntityID]domain.Membership) map[domain.EntityID]domain.Membership {
	copyOf := make(map[domain.EntityID]domain.Membership, len(memberships))
	for id, membership := range memberships {
		copyOf[id] = cloneMembership(membership)
	}
	return copyOf
}

func cloneMembership(membership domain.Membership) domain.Membership {
	membership.OrgRoles = append([]string(nil), membership.OrgRoles...)
	membership.Assignments = append([]domain.Assignment(nil), membership.Assignments...)
	for i := range membership.Assignments {
		membership.Assignments[i].Roles = append([]string(nil), membership.Assignments[i].Roles...)
	}
	return membership
}

type invitationReader struct {
	orgs        map[domain.EntityID]domain.Organization
	restaurants map[domain.EntityID]domain.Restaurant
	invitations map[domain.EntityID]domain.Invitation
}

func (r invitationReader) Get(ctx context.Context, id domain.EntityID) (domain.Invitation, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Invitation{}, false, err
	}
	invitation, ok := r.invitations[id]
	return cloneInvitation(invitation), ok, nil
}

func (r invitationReader) ForOrganization(ctx context.Context, orgID domain.EntityID) ([]domain.Invitation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var invitations []domain.Invitation
	for _, invitation := range r.invitations {
		if invitation.OrgID == orgID {
			invitations = append(invitations, cloneInvitation(invitation))
		}
	}
	return invitations, nil
}

func (r invitationReader) PendingByEmail(ctx context.Context, orgID domain.EntityID, email string) (domain.Invitation, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Invitation{}, false, err
	}
	key := strings.ToLower(email)
	for _, invitation := range r.invitations {
		if invitation.OrgID == orgID && invitation.State == "pending" && strings.ToLower(invitation.ComparisonEmail) == key {
			return cloneInvitation(invitation), true, nil
		}
	}
	return domain.Invitation{}, false, nil
}

type invitationRepository struct{ invitationReader }

func (r invitationRepository) Insert(ctx context.Context, invitation domain.Invitation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if invitation.InvitationID == "" || r.invitations[invitation.InvitationID].InvitationID != "" {
		return application.ErrEntityConflict
	}
	if _, ok := r.orgs[invitation.OrgID]; !ok {
		return application.ErrReferenceMissing
	}
	if invitation.State == "pending" {
		if _, exists, err := r.PendingByEmail(ctx, invitation.OrgID, invitation.ComparisonEmail); err != nil {
			return err
		} else if exists {
			return application.ErrEntityConflict
		}
	}
	for _, assignment := range invitation.Assignments {
		restaurant, ok := r.restaurants[assignment.RestaurantID]
		if !ok {
			return application.ErrReferenceMissing
		}
		if restaurant.OrgID != invitation.OrgID {
			return application.ErrScopeMismatch
		}
	}
	r.invitations[invitation.InvitationID] = cloneInvitation(invitation)
	return nil
}

func cloneInvitations(invitations map[domain.EntityID]domain.Invitation) map[domain.EntityID]domain.Invitation {
	copyOf := make(map[domain.EntityID]domain.Invitation, len(invitations))
	for id, invitation := range invitations {
		copyOf[id] = cloneInvitation(invitation)
	}
	return copyOf
}

func cloneInvitation(invitation domain.Invitation) domain.Invitation {
	invitation.Assignments = append([]domain.InviteAssignment(nil), invitation.Assignments...)
	for i := range invitation.Assignments {
		invitation.Assignments[i].Roles = append([]string(nil), invitation.Assignments[i].Roles...)
	}
	return invitation
}

type challengeReader struct {
	challenges map[domain.EntityID]domain.Challenge
}

func (r challengeReader) Get(ctx context.Context, id domain.EntityID) (domain.Challenge, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.Challenge{}, false, err
	}
	challenge, ok := r.challenges[id]
	return cloneChallenge(challenge), ok, nil
}

type challengeRepository struct{ challengeReader }

func (r challengeRepository) Insert(ctx context.Context, challenge domain.Challenge) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if challenge.ChallengeID == "" || r.challenges[challenge.ChallengeID].ChallengeID != "" {
		return application.ErrEntityConflict
	}
	r.challenges[challenge.ChallengeID] = cloneChallenge(challenge)
	return nil
}

func (r challengeRepository) ConsumeProof(ctx context.Context, id domain.EntityID, digest string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	challenge, ok := r.challenges[id]
	if !ok || challenge.State != "verified" || challenge.ProofDigest != digest {
		return false, nil
	}
	challenge.State = "completed"
	challenge.EncryptedProof = ""
	r.challenges[id] = challenge
	return true, nil
}

func cloneChallenges(challenges map[domain.EntityID]domain.Challenge) map[domain.EntityID]domain.Challenge {
	copyOf := make(map[domain.EntityID]domain.Challenge, len(challenges))
	for id, challenge := range challenges {
		copyOf[id] = cloneChallenge(challenge)
	}
	return copyOf
}

func cloneChallenge(challenge domain.Challenge) domain.Challenge {
	challenge.WrongAttemptTimes = append([]domain.Instant(nil), challenge.WrongAttemptTimes...)
	return challenge
}

type mailJobReader struct {
	mailJobs map[domain.EntityID]domain.MailJob
}

func (r mailJobReader) Get(ctx context.Context, id domain.EntityID) (domain.MailJob, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.MailJob{}, false, err
	}
	job, ok := r.mailJobs[id]
	return job, ok, nil
}

type mailJobRepository struct{ mailJobReader }

func (r mailJobRepository) Insert(ctx context.Context, job domain.MailJob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if job.JobID == "" || r.mailJobs[job.JobID].JobID != "" {
		return application.ErrEntityConflict
	}
	r.mailJobs[job.JobID] = job
	return nil
}

func (r mailJobRepository) Claim(ctx context.Context, id domain.EntityID, owner string, now, leaseUntil domain.Instant) (bool, domain.MailJob, error) {
	if err := ctx.Err(); err != nil {
		return false, domain.MailJob{}, err
	}
	job, ok := r.mailJobs[id]
	if !ok || owner == "" || job.Attempts >= 3 || (job.State != "queued" && job.State != "unknown") {
		return false, domain.MailJob{}, nil
	}
	if job.NextAttemptAt != "" {
		dueAt, dueErr := time.Parse(time.RFC3339Nano, string(job.NextAttemptAt))
		nowAt, nowErr := time.Parse(time.RFC3339Nano, string(now))
		if dueErr != nil || nowErr != nil {
			return false, domain.MailJob{}, application.ErrInvalidMailJob
		}
		if dueAt.After(nowAt) {
			return false, domain.MailJob{}, nil
		}
	}
	untilAt, untilErr := time.Parse(time.RFC3339Nano, string(leaseUntil))
	nowAt, nowErr := time.Parse(time.RFC3339Nano, string(now))
	if untilErr != nil || nowErr != nil || !untilAt.After(nowAt) {
		return false, domain.MailJob{}, application.ErrInvalidMailJob
	}
	job.Attempts++
	job.State = "sending"
	job.LastAttemptAt = now
	job.LeaseOwner = owner
	job.LeaseUntil = leaseUntil
	r.mailJobs[id] = job
	return true, job, nil
}

func (r mailJobRepository) Finish(ctx context.Context, id domain.EntityID, owner string, attempt int, state, encryptedPayload string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	job, ok := r.mailJobs[id]
	if !ok || job.State != "sending" || job.LeaseOwner != owner || job.Attempts != attempt {
		return application.ErrLeaseLost
	}
	if state != "delivered" && state != "failed" && state != "unknown" && state != "suppressed" {
		return application.ErrInvalidMailJob
	}
	job.State = state
	job.LeaseOwner = ""
	job.LeaseUntil = ""
	if state == "unknown" {
		job.EncryptedPayload = encryptedPayload
	} else {
		job.EncryptedPayload = ""
	}
	r.mailJobs[id] = job
	return nil
}

func cloneMailJobs(mailJobs map[domain.EntityID]domain.MailJob) map[domain.EntityID]domain.MailJob {
	copyOf := make(map[domain.EntityID]domain.MailJob, len(mailJobs))
	for id, job := range mailJobs {
		copyOf[id] = job
	}
	return copyOf
}

type outboxRepository struct {
	events map[domain.EntityID]application.OutboxEvent
}

func (r outboxRepository) Get(ctx context.Context, id domain.EntityID) (application.OutboxEvent, bool, error) {
	if err := ctx.Err(); err != nil {
		return application.OutboxEvent{}, false, err
	}
	event, ok := r.events[id]
	return cloneOutboxEvent(event), ok, nil
}

func (r outboxRepository) Insert(ctx context.Context, event application.OutboxEvent) (domain.EntityID, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := event.Validate(); err != nil {
		return "", err
	}
	if _, ok := r.events[event.ID]; ok {
		return "", application.ErrEntityConflict
	}
	r.events[event.ID] = cloneOutboxEvent(event)
	return event.ID, nil
}

func cloneOutbox(events map[domain.EntityID]application.OutboxEvent) map[domain.EntityID]application.OutboxEvent {
	copyOf := make(map[domain.EntityID]application.OutboxEvent, len(events))
	for id, event := range events {
		copyOf[id] = cloneOutboxEvent(event)
	}
	return copyOf
}

func cloneOutboxEvent(event application.OutboxEvent) application.OutboxEvent {
	event.Body = append([]byte(nil), event.Body...)
	if event.Headers != nil {
		headers := make(map[string]string, len(event.Headers))
		for name, value := range event.Headers {
			headers[name] = value
		}
		event.Headers = headers
	}
	return event
}

type budgetReader struct{ events []application.BudgetEvent }

func (r budgetReader) CountSince(ctx context.Context, kind, key string, since domain.Instant) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	cutoff, err := time.Parse(time.RFC3339Nano, string(since))
	if err != nil {
		return 0, application.ErrInvalidBudgetEvent
	}
	count := 0
	for _, event := range r.events {
		if event.Kind != kind || event.KeyDigest != key {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, string(event.At))
		if err != nil {
			return 0, application.ErrInvalidBudgetEvent
		}
		if !at.Before(cutoff) {
			count++
		}
	}
	return count, nil
}

type budgetRepository struct {
	budgetReader
	events *[]application.BudgetEvent
}

func (r budgetRepository) Record(ctx context.Context, event application.BudgetEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if event.Kind == "" || event.KeyDigest == "" {
		return application.ErrInvalidBudgetEvent
	}
	if _, err := time.Parse(time.RFC3339Nano, string(event.At)); err != nil {
		return application.ErrInvalidBudgetEvent
	}
	*r.events = append(*r.events, event)
	return nil
}

var _ application.Store = (*Store)(nil)
