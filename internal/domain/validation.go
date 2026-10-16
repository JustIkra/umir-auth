package domain

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var instantPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.[0-9]{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$`)
var zonePattern = regexp.MustCompile(`^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$`)
var verifierPattern = regexp.MustCompile(`^\$argon2id\$v=19\$m=[1-9][0-9]*,t=[1-9][0-9]*,p=[1-9][0-9]*\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$`)

func VersionNumber(v Version) (int64, bool) {
	n, err := strconv.ParseInt(string(v), 10, 64)
	return n, err == nil && n > 0 && strconv.FormatInt(n, 10) == string(v)
}
func validID(id EntityID) bool       { return uuidPattern.MatchString(string(id)) }
func ValidEntityID(id EntityID) bool { return validID(id) }
func validDigest(s string) bool      { return digestPattern.MatchString(s) }
func text(s string, min, max int) bool {
	n := utf8.RuneCountInString(s)
	return utf8.ValidString(s) && n >= min && n <= max && !strings.ContainsAny(s, "\x00\r\n")
}
func ValidClientCommandID(s string) bool { return commandText(s) && utf8.RuneCountInString(s) <= 256 }
func commandText(s string) bool {
	return s != "" && utf8.ValidString(s) && !strings.HasPrefix(s, "expiration/")
}
func email(s string) bool {
	at := strings.LastIndexByte(s, '@')
	if !text(s, 3, 254) || len(s) > 254 || at <= 0 || at >= len(s)-1 || strings.Count(s, "@") != 1 || !strings.Contains(s[at+1:], ".") {
		return false
	}
	local, host := s[:at], s[at+1:]
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}
	for _, r := range local {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune(".!#$%&'*+-/=?^_`{|}~", r) {
			return false
		}
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
				return false
			}
		}
	}
	return true
}
func ValidEmail(s string) bool { return email(s) }
func ComparisonEmail(s string) string {
	local, host, ok := strings.Cut(s, "@")
	if !ok {
		return ""
	}
	return local + "@" + strings.ToLower(host)
}
func version(v Version) bool { _, ok := VersionNumber(v); return ok }
func instant(i Instant) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, string(i))
	return t, err == nil && instantPattern.MatchString(string(i))
}
func ordered(a, b Instant) bool {
	x, ok := instant(a)
	y, ok2 := instant(b)
	return ok && ok2 && !x.After(y)
}
func oneOf(s string, values ...string) bool { return slices.Contains(values, s) }
func roles(r []string) bool {
	return len(r) > 0 && len(r) <= 2 && unique(r) && all(r, func(s string) bool { return oneOf(s, "Warehouse", "Waiter") })
}
func all[T any](values []T, check func(T) bool) bool {
	for _, v := range values {
		if !check(v) {
			return false
		}
	}
	return true
}
func unique[T comparable](values []T) bool {
	seen := map[T]bool{}
	for _, v := range values {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

type validation struct {
	ids         map[EntityID]bool
	users       map[EntityID]User
	orgs        map[EntityID]Organization
	restaurants map[EntityID]Restaurant
	invites     map[EntityID]Invitation
	challenges  map[EntityID]Challenge
	jobs        map[EntityID]MailJob
}

func (v *validation) identity(id EntityID) bool {
	if !validID(id) || v.ids[id] {
		return false
	}
	v.ids[id] = true
	return true
}
func (v *validation) restaurant(id, org EntityID) bool {
	r, ok := v.restaurants[id]
	return ok && r.OrgID == org
}
func Validate(a Aggregate) (ValidatedAggregate, error) {
	if (a.SchemaVersion != 1 && a.SchemaVersion != 2 && a.SchemaVersion != 3) || !version(a.AggregateRevision) || a.Users == nil || a.Organizations == nil || a.Restaurants == nil || a.Memberships == nil || a.Sessions == nil || a.Invitations == nil || a.Challenges == nil || a.MailJobs == nil || a.Idempotency == nil || a.LifecycleIntents == nil || a.Tombstones == nil {
		return ValidatedAggregate{}, ErrInvalidAggregate
	}
	v := validation{ids: map[EntityID]bool{}, users: map[EntityID]User{}, orgs: map[EntityID]Organization{}, restaurants: map[EntityID]Restaurant{}, invites: map[EntityID]Invitation{}, challenges: map[EntityID]Challenge{}, jobs: map[EntityID]MailJob{}}
	if !v.authority(a) || !v.memberships(a) || !v.sessions(a) || !v.invitations(a) || !v.challengeRecords(a) || !v.mail(a) || !v.commands(a) || !v.lifecycle(a) || !v.tombstones(a) {
		return ValidatedAggregate{}, ErrInvalidAggregate
	}
	return ValidatedAggregate{data: clone(a)}, nil
}
func (v *validation) authority(a Aggregate) bool {
	logins := map[string]bool{}
	emails := map[string]bool{}
	for _, u := range a.Users {
		normalized := ComparisonEmail(u.Email)
		if !v.identity(u.UserID) || !text(u.Login, 1, 128) || !text(u.DisplayName, 2, 80) || !version(u.CredentialVersion) || !verifierPattern.MatchString(u.Verifier) || logins[u.Login] || (u.Email != "" && (!email(u.Email) || emails[normalized])) {
			return false
		}
		logins[u.Login] = true
		if u.Email != "" {
			emails[normalized] = true
		}
		v.users[u.UserID] = u
	}
	for _, o := range a.Organizations {
		if !v.identity(o.OrgID) || !text(o.Name, 1, 100) || !version(o.LifecycleVersion) || !version(o.Settings.SettingsVersion) || !zonePattern.MatchString(o.Settings.TimeZone) || o.Settings.TimeZone == "Local" || !oneOf(o.Lifecycle, "active", "deleting", "deleted") {
			return false
		}
		v.orgs[o.OrgID] = o
	}
	for _, r := range a.Restaurants {
		_, org := v.orgs[r.OrgID]
		if !v.identity(r.RestaurantID) || !org || !text(r.Name, 1, 100) || !version(r.LifecycleVersion) || !oneOf(r.Lifecycle, "registering", "ready", "deleting", "deleted") {
			return false
		}
		v.restaurants[r.RestaurantID] = r
	}
	return true
}
func (v *validation) memberships(a Aggregate) bool {
	admins := map[EntityID]int{}
	pairs := map[[2]EntityID]bool{}
	for _, m := range a.Memberships {
		_, user := v.users[m.UserID]
		o, org := v.orgs[m.OrgID]
		pair := [2]EntityID{m.UserID, m.OrgID}
		if !v.identity(m.MembershipID) || !version(m.MembershipVersion) || !user || !org || m.OrgRoles == nil || len(m.OrgRoles) > 1 || !all(m.OrgRoles, func(s string) bool { return s == "Admin" }) || m.Assignments == nil || len(m.Assignments) > 500 || !oneOf(m.State, "active", "revoked") || pairs[pair] {
			return false
		}
		pairs[pair] = true
		if m.State == "active" {
			if o.Lifecycle != "active" {
				return false
			}
			if slices.Contains(m.OrgRoles, "Admin") {
				admins[m.OrgID]++
			}
		}
		assigned := map[EntityID]bool{}
		for _, as := range m.Assignments {
			r := v.restaurants[as.RestaurantID]
			if !v.identity(as.AssignmentID) || !version(as.AssignmentVersion) || !v.restaurant(as.RestaurantID, m.OrgID) || !roles(as.Roles) || assigned[as.RestaurantID] || (m.State == "active" && oneOf(r.Lifecycle, "deleting", "deleted")) {
				return false
			}
			assigned[as.RestaurantID] = true
		}
	}
	for _, o := range a.Organizations {
		if o.Lifecycle == "active" && admins[o.OrgID] == 0 {
			return false
		}
	}
	return true
}
func (v *validation) sessions(a Aggregate) bool {
	digests := map[string]bool{}
	counts := map[EntityID]int{}
	for _, s := range a.Sessions {
		u, user := v.users[s.UserID]
		cv, cvok := VersionNumber(s.CredentialVersion)
		uv, _ := VersionNumber(u.CredentialVersion)
		if !v.identity(s.SessionID) || !user || !version(s.SessionVersion) || !cvok || cv > uv || !validDigest(s.Digest) || !validSessionCSRF(s) || digests[s.Digest] || !ordered(s.CreatedAt, s.IdleExpiresAt) || !ordered(s.IdleExpiresAt, s.AbsoluteExpiresAt) {
			return false
		}
		created, _ := instant(s.CreatedAt)
		absolute, _ := instant(s.AbsoluteExpiresAt)
		idle, _ := instant(s.IdleExpiresAt)
		if !absolute.After(created) || !idle.After(created) {
			return false
		}
		if s.RememberMe {
			if absolute.Sub(created) != 30*24*time.Hour || !absolute.Equal(idle) {
				return false
			}
		} else if absolute.Sub(created) != 8*time.Hour {
			return false
		}
		digests[s.Digest] = true
		if !s.Revoked {
			counts[s.UserID]++
			if counts[s.UserID] > 32 {
				return false
			}
		}
	}
	return true
}
func (v *validation) invitations(a Aggregate) bool {
	active := map[[2]string]bool{}
	for _, i := range a.Invitations {
		o, org := v.orgs[i.OrgID]
		if !v.identity(i.InvitationID) || !org || !email(i.Email) || !email(i.ComparisonEmail) || i.ComparisonEmail != ComparisonEmail(i.Email) || !version(i.Version) || !oneOf(i.State, "pending", "accepted", "expired", "revoked", "suppressed") || i.Assignments == nil || len(i.Assignments) == 0 || len(i.Assignments) > 500 || !ordered(i.ResendAvailableAt, i.ExpiresAt) {
			return false
		}
		pair := [2]string{string(i.OrgID), i.ComparisonEmail}
		if i.State == "pending" {
			if active[pair] || o.Lifecycle != "active" {
				return false
			}
			active[pair] = true
		}
		assigned := map[EntityID]bool{}
		for _, as := range i.Assignments {
			if !v.restaurant(as.RestaurantID, i.OrgID) || !roles(as.Roles) || assigned[as.RestaurantID] || (i.State == "pending" && oneOf(v.restaurants[as.RestaurantID].Lifecycle, "deleting", "deleted")) {
				return false
			}
			assigned[as.RestaurantID] = true
		}
		v.invites[i.InvitationID] = i
	}
	return true
}
func (v *validation) challengeRecords(a Aggregate) bool {
	if len(a.Challenges) > 4096 {
		return false
	}
	for _, c := range a.Challenges {
		if !v.identity(c.ChallengeID) || !oneOf(c.Purpose, "invitation", "login", "password_reset", "registration") || !validDigest(c.InitiatorDigest) || !validDigest(c.CodeDigest) || (c.EncryptedCode != "" && !text(c.EncryptedCode, 1, 16384)) || (c.State == "pending" && c.EncryptedCode == "") || !ordered(c.ResendAvailableAt, c.ExpiresAt) || !oneOf(c.State, "pending", "verified", "completed", "expired", "locked") || c.IssueCount < 1 || c.IssueCount > 4 || c.WrongAttempts < 0 || c.WrongAttempts > 5 {
			return false
		}
		if c.Purpose != "registration" && (c.RegistrationEmail != "" || c.RegistrationSuppressed) {
			return false
		}
		if c.SuppressedEmail != "" {
			if a.SchemaVersion != 3 || !oneOf(c.Purpose, "login", "password_reset") || !email(c.SuppressedEmail) || c.SuppressedEmail != ComparisonEmail(c.SuppressedEmail) || c.UserID != "" || c.CredentialVersion != "" || c.InvitationID != "" || oneOf(c.State, "verified", "completed") {
				return false
			}
		}
		if len(c.WrongAttemptTimes) > c.WrongAttempts || a.SchemaVersion < 3 && len(c.WrongAttemptTimes) > 0 {
			return false
		}
		for i, at := range c.WrongAttemptTimes {
			if _, ok := instant(at); !ok || i > 0 && !ordered(c.WrongAttemptTimes[i-1], at) {
				return false
			}
		}
		switch c.Purpose {
		case "registration":
			if a.SchemaVersion != 3 || !email(c.RegistrationEmail) || c.RegistrationEmail != ComparisonEmail(c.RegistrationEmail) || c.UserID != "" || c.CredentialVersion != "" || c.InvitationID != "" || c.RegistrationSuppressed && oneOf(c.State, "verified", "completed") {
				return false
			}
		case "invitation":
			if _, ok := v.invites[c.InvitationID]; !ok || c.UserID != "" || c.CredentialVersion != "" {
				return false
			}
		default:
			u, ok := v.users[c.UserID]
			cv, cvok := VersionNumber(c.CredentialVersion)
			uv, _ := VersionNumber(u.CredentialVersion)
			if c.SuppressedEmail == "" && (!ok || !cvok || cv > uv || c.InvitationID != "") {
				return false
			}
		}
		hasProof := c.ProofDigest != "" || c.EncryptedProof != "" || c.ProofExpiresAt != ""
		if hasProof && (!validDigest(c.ProofDigest) || !text(c.EncryptedProof, 1, 16384) || !ordered(c.ExpiresAt, c.ProofExpiresAt)) {
			return false
		}
		if oneOf(c.State, "verified", "completed") && !hasProof {
			return false
		}
		if c.State == "locked" && c.WrongAttempts != 5 {
			return false
		}
		v.challenges[c.ChallengeID] = c
	}
	return true
}
func (v *validation) mail(a Aggregate) bool {
	order := int64(0)
	for _, j := range a.MailJobs {
		c, ok := v.challenges[j.ChallengeID]
		link := a.SchemaVersion >= 2 && j.Purpose == "invitation_link"
		if a.SchemaVersion == 1 && (j.Purpose != "" || j.EnqueueOrder != "") {
			return false
		}
		if a.SchemaVersion >= 2 {
			n, valid := VersionNumber(j.EnqueueOrder)
			if !valid || n <= order || !oneOf(j.Purpose, "otp", "invitation_link") {
				return false
			}
			order = n
		}
		_, timeok := instant(j.AcceptedAt)
		if !v.identity(j.JobID) || !link && !ok || !timeok || !oneOf(j.State, "queued", "sending", "delivered", "unknown", "failed", "suppressed") || (j.EncryptedPayload != "" && !text(j.EncryptedPayload, 1, 65536)) || (oneOf(j.State, "queued", "sending", "unknown") && j.EncryptedPayload == "") || j.Attempts < 0 || j.Attempts > 3 {
			return false
		}
		if j.LastAttemptAt != "" && !ordered(j.AcceptedAt, j.LastAttemptAt) || j.NextAttemptAt != "" && !ordered(j.AcceptedAt, j.NextAttemptAt) {
			return false
		}
		if link {
			i, exists := v.invites[j.InvitationID]
			if !exists || j.ChallengeID != "" || j.OrgID != i.OrgID {
				return false
			}
		} else if c.InvitationID != "" {
			i := v.invites[c.InvitationID]
			if j.InvitationID != i.InvitationID || j.OrgID != i.OrgID {
				return false
			}
		} else if j.InvitationID != "" || j.OrgID != "" {
			return false
		}
		v.jobs[j.JobID] = j
	}
	return true
}
func (v *validation) commands(a Aggregate) bool {
	type key struct {
		actor              EntityID
		preauth, operation string
		org, restaurant    EntityID
		command            string
	}
	keys := map[key]bool{}
	linkBindings := map[EntityID]int{}
	revision, _ := VersionNumber(a.AggregateRevision)
	for _, r := range a.Idempotency {
		if a.SchemaVersion == 1 && r.ContractProfile != "" || a.SchemaVersion >= 2 && !oneOf(r.ContractProfile, "C2", "UA1") {
			return false
		}
		_, actor := v.users[r.ActorID]
		if (r.ActorID != "" && !actor) || (r.ActorID == "" && !validDigest(r.PreauthDigest)) || (r.ActorID != "" && r.PreauthDigest != "") || !text(r.OperationID, 1, 128) || !commandText(r.CommandID) || !validDigest(r.Fingerprint) || !version(r.AggregateRevision) || r.HTTPStatus < 200 || r.HTTPStatus > 599 || !text(r.ResponseSchema, 1, 128) || !IsCommandTombstone(r) && !text(r.EncryptedResponse, 1, 1048576) || r.JobIDs == nil || !unique(r.JobIDs) {
			return false
		}
		rv, _ := VersionNumber(r.AggregateRevision)
		if rv > revision {
			return false
		}
		if r.OrgID != "" {
			if _, ok := v.orgs[r.OrgID]; !ok {
				return false
			}
		}
		if r.RestaurantID != "" && !v.restaurant(r.RestaurantID, r.OrgID) {
			return false
		}
		for _, id := range r.JobIDs {
			j, ok := v.jobs[id]
			if !ok {
				return false
			}
			if j.Purpose == "invitation_link" {
				if r.ContractProfile != "UA1" || !oneOf(r.OperationID, "createInvitation", "resendInvitationLink") || r.OrgID != j.OrgID || r.ActorID == "" || r.PreauthDigest != "" || len(r.JobIDs) != 1 {
					return false
				}
				linkBindings[id]++
			}
		}
		if r.ContractProfile == "UA1" {
			if len(r.JobIDs) != 1 || v.jobs[r.JobIDs[0]].Purpose != "invitation_link" || r.OperationID == "createInvitation" && (r.HTTPStatus != 201 || r.ResponseSchema != "Invitation") || r.OperationID == "resendInvitationLink" && (r.HTTPStatus != 200 || r.ResponseSchema != "DurableResult") || !oneOf(r.OperationID, "createInvitation", "resendInvitationLink") {
				return false
			}
		}
		if r.RecordedAt != "" {
			if _, ok := instant(r.RecordedAt); !ok {
				return false
			}
		}
		if oneOf(r.OperationID, "beginInvitationChallenge", "beginEmailChallenge", "resendChallenge") && (r.HTTPStatus != 200 || r.ResponseSchema != "Challenge" || len(r.JobIDs) != 1 && !IsCommandTombstone(r)) {
			return false
		}
		k := key{r.ActorID, r.PreauthDigest, r.OperationID, r.OrgID, r.RestaurantID, r.CommandID}
		if keys[k] {
			return false
		}
		keys[k] = true
	}
	for id, j := range v.jobs {
		if j.Purpose == "invitation_link" && linkBindings[id] != 1 {
			return false
		}
	}
	return true
}
func (v *validation) lifecycle(a Aggregate) bool {
	for _, l := range a.LifecycleIntents {
		_, actor := v.users[l.ActorID]
		_, org := v.orgs[l.OrgID]
		if !v.identity(l.OperationID) || !actor || !org || !commandText(l.CommandID) || !version(l.LifecycleVersion) || !oneOf(l.Lifecycle, "registering", "ready", "deleting", "deleted") || !oneOf(l.Cleanup, "not_required", "pending", "complete") || l.RestaurantIDs == nil || len(l.RestaurantIDs) > 10000 || !unique(l.RestaurantIDs) || l.Services == nil || len(l.Services) != 3*len(l.RestaurantIDs) {
			return false
		}
		if oneOf(l.Lifecycle, "registering", "ready") && l.Cleanup != "not_required" || l.Lifecycle == "deleting" && l.Cleanup != "pending" || l.Lifecycle == "deleted" && l.Cleanup != "complete" {
			return false
		}
		for i, id := range l.RestaurantIDs {
			if !v.restaurant(id, l.OrgID) {
				return false
			}
			for j, service := range []string{"warehouse", "serving", "gateway"} {
				p := l.Services[i*3+j]
				if p.RestaurantID != id || p.Service != service || p.LifecycleVersion != l.LifecycleVersion || !oneOf(p.State, "pending", "ready", "closed") || (p.Epoch != "" && !validID(p.Epoch)) || (p.State != "pending" && p.Epoch == "") || (l.Lifecycle == "ready" && p.State != "ready") || (l.Lifecycle == "deleted" && p.State != "closed") {
					return false
				}
			}
		}
	}
	return true
}
func (v *validation) tombstones(a Aggregate) bool {
	seen := map[EntityID]bool{}
	for _, t := range a.Tombstones {
		_, ok := instant(t.DeletedAt)
		if !validID(t.EntityID) || seen[t.EntityID] || !ok || !version(t.LifecycleVersion) || !oneOf(t.Kind, "organization", "restaurant") {
			return false
		}
		seen[t.EntityID] = true
		switch t.Kind {
		case "organization":
			o, exists := v.orgs[t.EntityID]
			if !exists || !oneOf(o.Lifecycle, "deleting", "deleted") || t.OrgID != o.OrgID || t.LifecycleVersion != o.LifecycleVersion {
				return false
			}
		case "restaurant":
			r, exists := v.restaurants[t.EntityID]
			if !exists || !oneOf(r.Lifecycle, "deleting", "deleted") || t.OrgID != r.OrgID || t.LifecycleVersion != r.LifecycleVersion {
				return false
			}
		}
	}
	for _, o := range a.Organizations {
		if oneOf(o.Lifecycle, "deleting", "deleted") && !seen[o.OrgID] {
			return false
		}
	}
	for _, r := range a.Restaurants {
		if oneOf(r.Lifecycle, "deleting", "deleted") && !seen[r.RestaurantID] {
			return false
		}
	}
	return true
}
func clone(a Aggregate) Aggregate {
	a.Users = slices.Clone(a.Users)
	a.Organizations = slices.Clone(a.Organizations)
	a.Restaurants = slices.Clone(a.Restaurants)
	a.Memberships = slices.Clone(a.Memberships)
	a.Sessions = slices.Clone(a.Sessions)
	a.Invitations = slices.Clone(a.Invitations)
	a.Challenges = slices.Clone(a.Challenges)
	for i := range a.Challenges {
		a.Challenges[i].WrongAttemptTimes = slices.Clone(a.Challenges[i].WrongAttemptTimes)
	}
	a.MailJobs = slices.Clone(a.MailJobs)
	a.Idempotency = slices.Clone(a.Idempotency)
	a.LifecycleIntents = slices.Clone(a.LifecycleIntents)
	a.Tombstones = slices.Clone(a.Tombstones)
	for i := range a.Memberships {
		m := &a.Memberships[i]
		m.OrgRoles = slices.Clone(m.OrgRoles)
		m.Assignments = slices.Clone(m.Assignments)
		for j := range m.Assignments {
			m.Assignments[j].Roles = slices.Clone(m.Assignments[j].Roles)
		}
	}
	for i := range a.Invitations {
		a.Invitations[i].Assignments = slices.Clone(a.Invitations[i].Assignments)
		for j := range a.Invitations[i].Assignments {
			a.Invitations[i].Assignments[j].Roles = slices.Clone(a.Invitations[i].Assignments[j].Roles)
		}
	}
	for i := range a.Idempotency {
		a.Idempotency[i].JobIDs = slices.Clone(a.Idempotency[i].JobIDs)
	}
	for i := range a.LifecycleIntents {
		a.LifecycleIntents[i].RestaurantIDs = slices.Clone(a.LifecycleIntents[i].RestaurantIDs)
		a.LifecycleIntents[i].Services = slices.Clone(a.LifecycleIntents[i].Services)
	}
	return a
}

func validSessionCSRF(s Session) bool {
	if s.LegacyCSRF {
		return s.CSRFTokenDigest == ""
	}
	return validDigest(s.CSRFTokenDigest)
}
