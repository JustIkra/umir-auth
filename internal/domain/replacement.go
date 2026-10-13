package domain

import "slices"

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
	return commandIdentity(a) == commandIdentity(b) && a.Fingerprint == b.Fingerprint && a.AggregateRevision == b.AggregateRevision && a.HTTPStatus == b.HTTPStatus && a.ResponseSchema == b.ResponseSchema && a.EncryptedResponse == b.EncryptedResponse && a.RecordedAt == b.RecordedAt && slices.Equal(a.JobIDs, b.JobIDs)
}
func ValidateReplacement(previous, next ValidatedAggregate) error {
	before, after := previous.data, next.data
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
	commands := map[commandKey]IdempotencyRecord{}
	for _, r := range after.Idempotency {
		commands[commandIdentity(r)] = r
	}
	for _, r := range before.Idempotency {
		n, ok := commands[commandIdentity(r)]
		if !ok || !sameCommand(r, n) {
			return ErrInvalidAggregate
		}
	}
	jobs := map[EntityID]MailJob{}
	for _, j := range after.MailJobs {
		jobs[j.JobID] = j
	}
	for _, j := range before.MailJobs {
		n, ok := jobs[j.JobID]
		if !ok || j.ChallengeID != n.ChallengeID || j.OrgID != n.OrgID || j.InvitationID != n.InvitationID || j.AcceptedAt != n.AcceptedAt || j.EncryptedPayload != n.EncryptedPayload && (n.EncryptedPayload != "" || !oneOf(n.State, "delivered", "failed", "suppressed")) || n.Attempts < j.Attempts || oneOf(j.State, "delivered", "failed", "suppressed") && n.State != j.State {
			return ErrInvalidAggregate
		}
	}
	challenges := map[EntityID]Challenge{}
	for _, c := range after.Challenges {
		challenges[c.ChallengeID] = c
	}
	for _, c := range before.Challenges {
		n, ok := challenges[c.ChallengeID]
		if !ok || c.Purpose != n.Purpose || c.InvitationID != n.InvitationID || c.UserID != n.UserID || c.CredentialVersion != n.CredentialVersion || c.InitiatorDigest != n.InitiatorDigest || c.ExpiresAt != n.ExpiresAt || c.CodeDigest != n.CodeDigest || c.EncryptedCode != n.EncryptedCode && (n.EncryptedCode != "" || n.State == "pending") || !ordered(c.ResendAvailableAt, n.ResendAvailableAt) || c.IssueCount > n.IssueCount || c.WrongAttempts > n.WrongAttempts || c.ProofDigest != "" && (c.ProofDigest != n.ProofDigest || c.EncryptedProof != n.EncryptedProof || c.ProofExpiresAt != n.ProofExpiresAt) || c.State == "verified" && !oneOf(n.State, "verified", "completed") || oneOf(c.State, "completed", "expired", "locked") && n.State != c.State {
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
func sameInviteAssignments(a, b []InviteAssignment) bool {
	return slices.EqualFunc(a, b, func(x, y InviteAssignment) bool {
		return x.RestaurantID == y.RestaurantID && slices.Equal(x.Roles, y.Roles)
	})
}
