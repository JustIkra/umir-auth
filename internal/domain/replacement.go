package domain

import (
	"slices"
	"time"
)

type commandKey struct {
	actor              EntityID
	preauth, operation string
	org, restaurant    EntityID
	command            string
}

func commandIdentity(r IdempotencyRecord) commandKey {
	return commandKey{r.ActorID, r.PreauthDigest, r.OperationID, r.OrgID, r.RestaurantID, r.CommandID}
}
func sameCommand(a, b IdempotencyRecord) bool {
	return commandIdentity(a) == commandIdentity(b) && a.ContractProfile == b.ContractProfile && a.Fingerprint == b.Fingerprint && a.AggregateRevision == b.AggregateRevision && a.HTTPStatus == b.HTTPStatus && a.ResponseSchema == b.ResponseSchema && a.EncryptedResponse == b.EncryptedResponse && a.RecordedAt == b.RecordedAt && slices.Equal(a.JobIDs, b.JobIDs)
}

// Retention of e-mail challenges (auth spec 4.1, C18). A challenge without a
// proof may go one hour after the later of its expiry and its last wrong
// attempt, which is also the whole wrong-code budget window. A challenge with a
// proof may go 24 hours after the proof expires.
const (
	ChallengeRetentionWithoutProof = time.Hour
	ChallengeRetentionAfterProof   = 24 * time.Hour
)

// ChallengePurgeAt reports the first instant at which the challenge may be
// removed. It is false when the stored instants are unusable, in which case the
// challenge is never removed.
func ChallengePurgeAt(c Challenge) (time.Time, bool) {
	if c.ProofDigest != "" || c.EncryptedProof != "" || c.ProofExpiresAt != "" {
		at, ok := instant(c.ProofExpiresAt)
		return at.Add(ChallengeRetentionAfterProof), ok
	}
	at, ok := instant(c.ExpiresAt)
	for _, raw := range c.WrongAttemptTimes {
		wrong, valid := instant(raw)
		ok = ok && valid
		if wrong.After(at) {
			at = wrong
		}
	}
	return at.Add(ChallengeRetentionWithoutProof), ok
}

// ChallengePurgeable reports whether the retention of the challenge has ended.
func ChallengePurgeable(c Challenge, now time.Time) bool {
	at, ok := ChallengePurgeAt(c)
	return ok && !now.Before(at)
}

// ChallengeJobLive reports whether an OTP job may still send or be resolved.
func ChallengeJobLive(j MailJob) bool { return oneOf(j.State, "queued", "sending", "unknown") }

// IsChallengeCommand reports the operations whose records point at OTP jobs.
func IsChallengeCommand(operation string) bool {
	return oneOf(operation, "beginInvitationChallenge", "beginEmailChallenge", "resendChallenge")
}

// IsCommandTombstone reports a challenge command record whose result and jobs
// were removed together with the challenge.
func IsCommandTombstone(r IdempotencyRecord) bool {
	return IsChallengeCommand(r.OperationID) && r.EncryptedResponse == "" && len(r.JobIDs) == 0
}

// CommandTombstone keeps the key and fingerprint of a record and drops its
// result and job edges.
func CommandTombstone(r IdempotencyRecord) IdempotencyRecord {
	r.EncryptedResponse = ""
	r.JobIDs = []EntityID{}
	return r
}

// ValidateReplacement is ValidateReplacementAt with no instant, so nothing is
// ever removed.
func ValidateReplacement(previous, next ValidatedAggregate) error {
	return ValidateReplacementAt(previous, next, time.Time{})
}

// ValidateReplacementAt checks that next may replace previous. Besides the
// monotonic rules it allows exactly one removal, all or nothing: a challenge
// whose retention has ended at now, its OTP jobs (none of them live), and the
// challenge command records that point only at those jobs, which become
// tombstones.
func ValidateReplacementAt(previous, next ValidatedAggregate, now time.Time) error {
	before, after := previous.data, next.data
	if before.SchemaVersion != after.SchemaVersion {
		if before.SchemaVersion > after.SchemaVersion || after.SchemaVersion > 3 {
			return ErrInvalidAggregate
		}
		var err error
		if after.SchemaVersion == 2 {
			before, err = UpgradeV1(before)
		} else {
			before, err = UpgradeRegistration(before)
		}
		if err != nil {
			return err
		}
	}
	if err := ValidateMembershipReplacement(before, after); err != nil {
		return err
	}
	users := map[EntityID]User{}
	for _, u := range after.Users {
		users[u.UserID] = u
	}
	for _, u := range before.Users {
		n, ok := users[u.UserID]
		beforeVersion, _ := VersionNumber(u.CredentialVersion)
		afterVersion, _ := VersionNumber(n.CredentialVersion)
		if !ok || n.Login != u.Login || afterVersion < beforeVersion || n.Verifier != u.Verifier && afterVersion == beforeVersion {
			return ErrInvalidAggregate
		}
	}
	orgs := map[EntityID]Organization{}
	for _, o := range after.Organizations {
		orgs[o.OrgID] = o
	}
	for _, o := range before.Organizations {
		n, ok := orgs[o.OrgID]
		previousSettings, _ := VersionNumber(o.Settings.SettingsVersion)
		nextSettings, _ := VersionNumber(n.Settings.SettingsVersion)
		ov, _ := VersionNumber(o.LifecycleVersion)
		nv, _ := VersionNumber(n.LifecycleVersion)
		if !ok || nv < ov || o.Lifecycle == "deleting" && n.Lifecycle == "active" || o.Lifecycle == "deleted" && n.Lifecycle != "deleted" || nextSettings < previousSettings || o.Settings.TimeZone != n.Settings.TimeZone && nextSettings <= previousSettings {
			return ErrInvalidAggregate
		}
	}
	restaurants := map[EntityID]Restaurant{}
	for _, r := range after.Restaurants {
		restaurants[r.RestaurantID] = r
	}
	for _, r := range before.Restaurants {
		n, ok := restaurants[r.RestaurantID]
		rv, _ := VersionNumber(r.LifecycleVersion)
		nv, _ := VersionNumber(n.LifecycleVersion)
		if !ok || nv < rv || r.Lifecycle == "deleting" && oneOf(n.Lifecycle, "registering", "ready") || r.OrgID != n.OrgID || r.Lifecycle == "deleted" && n.Lifecycle != "deleted" {
			return ErrInvalidAggregate
		}
	}
	tombstones := map[EntityID]Tombstone{}
	for _, t := range after.Tombstones {
		tombstones[t.EntityID] = t
	}
	for _, t := range before.Tombstones {
		n, ok := tombstones[t.EntityID]
		if !ok || n != t {
			return ErrInvalidAggregate
		}
	}
	sessions := map[EntityID]Session{}
	for _, s := range after.Sessions {
		sessions[s.SessionID] = s
	}
	for _, s := range before.Sessions {
		n, ok := sessions[s.SessionID]
		if ok && (s.UserID != n.UserID || s.Digest != n.Digest || s.CSRFTokenDigest != n.CSRFTokenDigest || s.LegacyCSRF != n.LegacyCSRF || s.CreatedAt != n.CreatedAt || s.AbsoluteExpiresAt != n.AbsoluteExpiresAt || s.RememberMe != n.RememberMe || s.CredentialVersion != n.CredentialVersion || s.Revoked && !n.Revoked) {
			return ErrInvalidAggregate
		}
	}
	challenges := map[EntityID]Challenge{}
	for _, c := range after.Challenges {
		challenges[c.ChallengeID] = c
	}
	removedChallenges := map[EntityID]bool{}
	for _, c := range before.Challenges {
		if _, ok := challenges[c.ChallengeID]; !ok {
			if !ChallengePurgeable(c, now) {
				return ErrInvalidAggregate
			}
			removedChallenges[c.ChallengeID] = true
		}
	}
	jobs := map[EntityID]MailJob{}
	for _, j := range after.MailJobs {
		jobs[j.JobID] = j
	}
	removedJobs := map[EntityID]bool{}
	for _, j := range before.MailJobs {
		n, ok := jobs[j.JobID]
		if !ok && removedChallenges[j.ChallengeID] && j.Purpose != "invitation_link" && !ChallengeJobLive(j) {
			removedJobs[j.JobID] = true
			continue
		}
		if !ok || j.Purpose != n.Purpose || j.EnqueueOrder != n.EnqueueOrder || j.ChallengeID != n.ChallengeID || j.OrgID != n.OrgID || j.InvitationID != n.InvitationID || j.AcceptedAt != n.AcceptedAt || j.EncryptedPayload != n.EncryptedPayload && (n.EncryptedPayload != "" || !oneOf(n.State, "delivered", "failed", "suppressed")) || n.Attempts < j.Attempts || oneOf(j.State, "delivered", "failed", "suppressed") && n.State != j.State {
			return ErrInvalidAggregate
		}
	}
	for _, c := range before.Challenges {
		n, ok := challenges[c.ChallengeID]
		if removedChallenges[c.ChallengeID] {
			continue
		}
		if !ok || c.SuppressedEmail != n.SuppressedEmail || len(n.WrongAttemptTimes) < len(c.WrongAttemptTimes) || !slices.Equal(c.WrongAttemptTimes, n.WrongAttemptTimes[:len(c.WrongAttemptTimes)]) || c.RegistrationEmail != n.RegistrationEmail || c.RegistrationSuppressed != n.RegistrationSuppressed || c.Purpose != n.Purpose || c.InvitationID != n.InvitationID || c.UserID != n.UserID || c.CredentialVersion != n.CredentialVersion || c.InitiatorDigest != n.InitiatorDigest || c.ExpiresAt != n.ExpiresAt || c.CodeDigest != n.CodeDigest || c.EncryptedCode != n.EncryptedCode && (n.EncryptedCode != "" || n.State == "pending") || !ordered(c.ResendAvailableAt, n.ResendAvailableAt) || c.IssueCount > n.IssueCount || c.WrongAttempts > n.WrongAttempts || c.ProofDigest != "" && (c.ProofDigest != n.ProofDigest || c.EncryptedProof != n.EncryptedProof || c.ProofExpiresAt != n.ProofExpiresAt) || c.State == "verified" && !oneOf(n.State, "verified", "completed") || oneOf(c.State, "completed", "expired", "locked") && n.State != c.State {
			return ErrInvalidAggregate
		}
	}
	commands := map[commandKey]IdempotencyRecord{}
	for _, r := range after.Idempotency {
		commands[commandIdentity(r)] = r
	}
	for _, r := range before.Idempotency {
		n, ok := commands[commandIdentity(r)]
		if !ok || !sameCommand(r, n) && !tombstoned(r, n, removedJobs) {
			return ErrInvalidAggregate
		}
	}
	invites := map[EntityID]Invitation{}
	for _, i := range after.Invitations {
		invites[i.InvitationID] = i
	}
	for _, i := range before.Invitations {
		n, ok := invites[i.InvitationID]
		iv, _ := VersionNumber(i.Version)
		nv, _ := VersionNumber(n.Version)
		if !ok || i.OrgID != n.OrgID || i.Email != n.Email || i.ComparisonEmail != n.ComparisonEmail || i.ExpiresAt != n.ExpiresAt || !sameInviteAssignments(i.Assignments, n.Assignments) || i.State != "pending" && n.State != i.State || nv < iv || (i.State != n.State || i.ResendAvailableAt != n.ResendAvailableAt) && nv <= iv || !ordered(i.ResendAvailableAt, n.ResendAvailableAt) {
			return ErrInvalidAggregate
		}
	}
	intents := map[EntityID]LifecycleIntent{}
	for _, l := range after.LifecycleIntents {
		intents[l.OperationID] = l
	}
	for _, l := range before.LifecycleIntents {
		n, ok := intents[l.OperationID]
		if !ok || l.LifecycleVersion != n.LifecycleVersion || (l.Cleanup == "not_required") != (n.Cleanup == "not_required") || l.ActorID != n.ActorID || l.OrgID != n.OrgID || l.CommandID != n.CommandID || !slices.Equal(l.RestaurantIDs, n.RestaurantIDs) {
			return ErrInvalidAggregate
		}
	}
	return nil
}

// tombstoned reports whether next is exactly the tombstone of previous and every
// job previous pointed at was removed.
func tombstoned(previous, next IdempotencyRecord, removedJobs map[EntityID]bool) bool {
	if !IsChallengeCommand(previous.OperationID) || len(previous.JobIDs) == 0 || !IsCommandTombstone(next) {
		return false
	}
	for _, id := range previous.JobIDs {
		if !removedJobs[id] {
			return false
		}
	}
	return sameCommand(CommandTombstone(previous), next)
}
func sameInviteAssignments(a, b []InviteAssignment) bool {
	return slices.EqualFunc(a, b, func(x, y InviteAssignment) bool {
		return x.RestaurantID == y.RestaurantID && slices.Equal(x.Roles, y.Roles)
	})
}
