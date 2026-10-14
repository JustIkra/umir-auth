package application

import (
	"context"
	"errors"
	"slices"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/JustIkra/umir-auth/internal/domain"
)

var ErrRefreshRequired = errors.New("collection refresh required")
var ErrLimitExceeded = errors.New("collection capacity exceeded")

const organizationPageRows = 10000
const organizationPageBytes = 16 << 20
const organizationTotalBytes = 64 << 20

type PageExpiryTimer interface {
	Stop() bool
}

type OrganizationListRequest struct {
	Cursor, State string
	Limit         int
}

type OrganizationPageIdentity struct {
	OrgID             domain.EntityID `json:"orgID"`
	ReaderEpoch       domain.EntityID `json:"readerEpoch"`
	AggregateRevision domain.Version  `json:"aggregateRevision"`
	EvaluatedAt       domain.Instant  `json:"evaluatedAt"`
}

type MemberContact struct {
	Membership  domain.Membership `json:"membership"`
	DisplayName string            `json:"displayName"`
	Email       *string           `json:"email"`
}

type MembersPage struct {
	Context    OrganizationPageIdentity `json:"context"`
	Items      []MemberContact          `json:"items"`
	NextCursor string                   `json:"nextCursor,omitempty"`
}

type InvitationListRow struct {
	Invitation    domain.Invitation `json:"invitation"`
	LinkDelivery  *MailJobView      `json:"linkDelivery"`
	ResendAllowed bool              `json:"resendAllowed"`
}

type InvitationsPage struct {
	Context    OrganizationPageIdentity `json:"context"`
	Items      []InvitationListRow      `json:"items"`
	NextCursor string                   `json:"nextCursor,omitempty"`
}

type organizationCapture struct {
	kind        string
	actor       domain.EntityID
	request     OrganizationListRequest
	identity    OrganizationPageIdentity
	members     []MemberContact
	invitations []InvitationListRow
	expires     time.Time
	bytes       int
	pages       map[int]string
	timer       PageExpiryTimer
}

type organizationCursor struct {
	capture *organizationCapture
	index   int
}

type organizationPages struct {
	epoch     domain.EntityID
	captures  map[*organizationCapture]bool
	cursors   map[string]organizationCursor
	orgBytes  map[domain.EntityID]int
	orgCounts map[domain.EntityID]int
	bytes     int
}

func normalizeOrganizationList(r OrganizationListRequest, kind string) (OrganizationListRequest, error) {
	if r.Limit == 0 {
		r.Limit = 100
	}
	if r.State == "" {
		r.State = "all"
		if kind == "members" {
			r.State = "active"
		}
	}
	states := []string{"pending", "accepted", "expired", "revoked", "suppressed", "all"}
	if kind == "members" {
		states = []string{"active", "revoked", "all"}
	}
	if r.Limit < 1 || r.Limit > 500 || !slices.Contains(states, r.State) || len(r.Cursor) > 128 || !utf8.ValidString(r.Cursor) {
		return r, &FieldError{Field: "query", Code: "InvalidFormat"}
	}
	return r, nil
}

func (s *Accounts) Members(ctx context.Context, token string, org domain.EntityID, request OrganizationListRequest) (MembersPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, index, err := s.organizationPageLocked(ctx, token, org, request, "members")
	if err != nil {
		return MembersPage{}, err
	}
	end := min(index+c.request.Limit, len(c.members))
	items := slices.Clone(c.members[index:end])
	for i := range items {
		items[i].Membership = cloneReadMembership(items[i].Membership)
		if items[i].Email != nil {
			email := *items[i].Email
			items[i].Email = &email
		}
	}
	cursor, err := s.organizationCursorLocked(c, end, len(c.members))
	return MembersPage{Context: c.identity, Items: items, NextCursor: cursor}, err
}

func (s *Accounts) Invitations(ctx context.Context, token string, org domain.EntityID, request OrganizationListRequest) (InvitationsPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, index, err := s.organizationPageLocked(ctx, token, org, request, "invitations")
	if err != nil {
		return InvitationsPage{}, err
	}
	end := min(index+c.request.Limit, len(c.invitations))
	items := slices.Clone(c.invitations[index:end])
	for i := range items {
		items[i].Invitation.Assignments = slices.Clone(items[i].Invitation.Assignments)
		for j := range items[i].Invitation.Assignments {
			items[i].Invitation.Assignments[j].Roles = slices.Clone(items[i].Invitation.Assignments[j].Roles)
		}
		if items[i].LinkDelivery != nil {
			job := *items[i].LinkDelivery
			items[i].LinkDelivery = &job
		}
	}
	cursor, err := s.organizationCursorLocked(c, end, len(c.invitations))
	return InvitationsPage{Context: c.identity, Items: items, NextCursor: cursor}, err
}

func cloneReadMembership(m domain.Membership) domain.Membership {
	m.OrgRoles = slices.Clone(m.OrgRoles)
	m.Assignments = slices.Clone(m.Assignments)
	for i := range m.Assignments {
		m.Assignments[i].Roles = slices.Clone(m.Assignments[i].Roles)
	}
	return m
}

func (s *Accounts) organizationPageLocked(ctx context.Context, token string, org domain.EntityID, request OrganizationListRequest, kind string) (*organizationCapture, int, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	r, err := normalizeOrganizationList(request, kind)
	if err != nil {
		return nil, 0, err
	}
	a, err := s.load(ctx)
	if err != nil {
		return nil, 0, err
	}
	u, _, err := active(a, token, s.opts.Clock.Now())
	if err != nil {
		return nil, 0, err
	}
	if !domain.IsOrgAdmin(a, u.UserID, org) {
		return nil, 0, ErrForbidden
	}
	if err := publicScope(a, org); err != nil {
		return nil, 0, err
	}
	s.purgeOrganizationPagesLocked()
	if r.Cursor != "" {
		cursor, ok := s.organizationPages.cursors[r.Cursor]
		r.Cursor = ""
		if !ok || cursor.capture.actor != u.UserID || cursor.capture.identity.OrgID != org || cursor.capture.kind != kind || cursor.capture.request != r {
			return nil, 0, ErrRefreshRequired
		}
		return cursor.capture, cursor.index, nil
	}
	if s.organizationPages.epoch == "" {
		s.organizationPages.epoch, err = s.opts.IDs.NewID()
		if err != nil || !domain.ValidEntityID(s.organizationPages.epoch) {
			return nil, 0, ErrAuthUnavailable
		}
	}
	evaluatedAt := s.opts.Clock.Now()
	c := &organizationCapture{kind: kind, actor: u.UserID, request: r, identity: OrganizationPageIdentity{OrgID: org, ReaderEpoch: s.organizationPages.epoch, AggregateRevision: a.AggregateRevision, EvaluatedAt: formatInstant(evaluatedAt)}, members: []MemberContact{}, invitations: []InvitationListRow{}, expires: s.opts.PageClock.Now().Add(5 * time.Minute), pages: map[int]string{}, bytes: 2048}
	if kind == "members" {
		err = captureMemberContacts(a, org, r.State, c)
	} else {
		err = captureInvitationRows(a, org, r.State, evaluatedAt, c)
	}
	if err != nil {
		return nil, 0, err
	}
	count := len(c.members) + len(c.invitations)
	if count <= r.Limit {
		return c, 0, nil
	}
	if s.opts.PageAfter == nil {
		return nil, 0, ErrAuthUnavailable
	}
	p := &s.organizationPages
	if p.orgCounts[org] >= 128 || c.bytes > organizationPageBytes-p.orgBytes[org] || c.bytes > organizationTotalBytes-p.bytes {
		return nil, 0, ErrLimitExceeded
	}
	p.captures[c] = true
	p.orgCounts[org]++
	p.orgBytes[org] += c.bytes
	p.bytes += c.bytes
	c.timer = s.opts.PageAfter(5*time.Minute, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.removeOrganizationPageLocked(c)
	})
	return c, 0, nil
}

func captureMemberContacts(a domain.Aggregate, org domain.EntityID, state string, c *organizationCapture) error {
	users := make(map[domain.EntityID]domain.User, len(a.Users))
	for _, u := range a.Users {
		users[u.UserID] = u
	}
	for _, m := range a.Memberships {
		if m.OrgID != org || state != "all" && m.State != state {
			continue
		}
		u, ok := users[m.UserID]
		if !ok {
			return ErrStorageUnavailable
		}
		size := 2048 + len(u.DisplayName) + len(u.Email)
		for _, assignment := range m.Assignments {
			size += 512 + len(assignment.RestaurantID) + len(assignment.AssignmentID) + len(assignment.AssignmentVersion)
		}
		if len(c.members) >= organizationPageRows || size > organizationPageBytes-c.bytes {
			return ErrLimitExceeded
		}
		row := MemberContact{Membership: cloneReadMembership(m), DisplayName: u.DisplayName}
		if u.Email != "" {
			email := u.Email
			row.Email = &email
		}
		c.bytes += size
		c.members = append(c.members, row)
	}
	sort.Slice(c.members, func(i, j int) bool {
		return c.members[i].Membership.MembershipID < c.members[j].Membership.MembershipID
	})
	return nil
}

func captureInvitationRows(a domain.Aggregate, org domain.EntityID, state string, now time.Time, c *organizationCapture) error {
	for _, invitation := range a.Invitations {
		if invitation.OrgID != org {
			continue
		}
		if invitation.State == "pending" && !before(now, invitation.ExpiresAt) {
			invitation.State = "expired"
		}
		if state != "all" && invitation.State != state {
			continue
		}
		size := 2048 + len(invitation.Email) + len(invitation.ComparisonEmail) + len(invitation.Assignments)*512
		if len(c.invitations) >= organizationPageRows || size > organizationPageBytes-c.bytes {
			return ErrLimitExceeded
		}
		c.bytes += size
		row := InvitationListRow{Invitation: invitation, ResendAllowed: invitation.State == "pending" && before(now, invitation.ExpiresAt) && !before(now, invitation.ResendAvailableAt)}
		order := int64(0)
		var latest time.Time
		for _, j := range a.MailJobs {
			if j.Purpose != "invitation_link" || j.InvitationID != invitation.InvitationID {
				continue
			}
			n, ok := domain.VersionNumber(j.EnqueueOrder)
			if !ok {
				return ErrStorageUnavailable
			}
			accepted, err := time.Parse(time.RFC3339Nano, string(j.AcceptedAt))
			if err != nil {
				return ErrStorageUnavailable
			}
			if accepted.After(latest) || accepted.Equal(latest) && n > order {
				latest = accepted
				order = n
				job := safeLinkJob(j)
				row.LinkDelivery = &job
			}
		}
		c.invitations = append(c.invitations, row)
	}
	sort.Slice(c.invitations, func(i, j int) bool {
		return c.invitations[i].Invitation.InvitationID < c.invitations[j].Invitation.InvitationID
	})
	return nil
}

func (s *Accounts) organizationCursorLocked(c *organizationCapture, end, count int) (string, error) {
	if end >= count {
		return "", nil
	}
	if cursor := c.pages[end]; cursor != "" {
		return cursor, nil
	}
	cursor, err := s.opts.Tokens.NewToken()
	if err != nil || cursor == "" || len(cursor) > 128 || !utf8.ValidString(cursor) {
		s.removeOrganizationPageLocked(c)
		return "", ErrAuthUnavailable
	}
	if _, exists := s.organizationPages.cursors[cursor]; exists {
		s.removeOrganizationPageLocked(c)
		return "", ErrAuthUnavailable
	}
	c.pages[end] = cursor
	s.organizationPages.cursors[cursor] = organizationCursor{c, end}
	return cursor, nil
}

func (s *Accounts) removeOrganizationPageLocked(c *organizationCapture) {
	p := &s.organizationPages
	if !p.captures[c] {
		return
	}
	delete(p.captures, c)
	p.orgCounts[c.identity.OrgID]--
	p.orgBytes[c.identity.OrgID] -= c.bytes
	p.bytes -= c.bytes
	for _, cursor := range c.pages {
		delete(p.cursors, cursor)
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	c.members, c.invitations = nil, nil
}

func (s *Accounts) purgeOrganizationPagesLocked() {
	for c := range s.organizationPages.captures {
		if !s.opts.PageClock.Now().Before(c.expires) {
			s.removeOrganizationPageLocked(c)
		}
	}
}

func (s *Accounts) CloseReadPages() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.organizationPages.captures {
		s.removeOrganizationPageLocked(c)
	}
}
