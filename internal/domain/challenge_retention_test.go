package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/domain"
)

// retentionFixture is a settled aggregate: an expired invitation challenge
// whose only job is suppressed, and the command record that created both.
func retentionFixture(t *testing.T) (domain.Aggregate, time.Time) {
	t.Helper()
	a := fixture(t)
	a.Challenges[0].State = "expired"
	a.Challenges[0].EncryptedCode = ""
	a.MailJobs[0].State = "suppressed"
	a.MailJobs[0].EncryptedPayload = ""
	a.Idempotency = append(a.Idempotency, domain.IdempotencyRecord{
		PreauthDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		OperationID:   "beginInvitationChallenge", CommandID: "begin-once",
		Fingerprint:       "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		AggregateRevision: "1", HTTPStatus: 200, ResponseSchema: "Challenge",
		EncryptedResponse: "synthetic-encrypted-challenge", JobIDs: []domain.EntityID{a.MailJobs[0].JobID},
	})
	expires, err := time.Parse(time.RFC3339Nano, string(a.Challenges[0].ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	return a, expires.Add(time.Hour)
}
func validated(t *testing.T, a domain.Aggregate) domain.ValidatedAggregate {
	t.Helper()
	v, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// purged removes the challenge and its job and tombstones the command record.
func purged(a domain.Aggregate) domain.Aggregate {
	a.Challenges = []domain.Challenge{}
	a.MailJobs = []domain.MailJob{}
	a.Idempotency = append([]domain.IdempotencyRecord(nil), a.Idempotency...)
	last := len(a.Idempotency) - 1
	a.Idempotency[last].EncryptedResponse = ""
	a.Idempotency[last].JobIDs = []domain.EntityID{}
	return a
}
func TestValidateReplacementAtAllowsExactlyThePurge(t *testing.T) {
	a, due := retentionFixture(t)
	before := validated(t, a)
	after := validated(t, purged(a))
	if err := domain.ValidateReplacementAt(before, after, due); err != nil {
		t.Fatalf("purge at the end of retention refused: %v", err)
	}
	if err := domain.ValidateReplacementAt(before, after, due.Add(-time.Nanosecond)); !errors.Is(err, domain.ErrInvalidAggregate) {
		t.Fatalf("purge before the end of retention = %v", err)
	}
	if err := domain.ValidateReplacement(before, after); !errors.Is(err, domain.ErrInvalidAggregate) {
		t.Fatalf("purge without an instant = %v", err)
	}
}
func TestValidateReplacementAtRetentionUsesProofAndWrongCodes(t *testing.T) {
	a, due := retentionFixture(t)
	a.Challenges[0].WrongAttempts = 1
	a.Challenges[0].WrongAttemptTimes = []domain.Instant{"2026-10-13T01:09:00+03:00"}
	if at, ok := domain.ChallengePurgeAt(a.Challenges[0]); !ok || !at.Equal(due) {
		t.Fatalf("wrong code before expiry moved the purge to %v", at)
	}
	a.Challenges[0].WrongAttemptTimes = []domain.Instant{"2026-10-13T01:20:00+03:00"}
	if at, ok := domain.ChallengePurgeAt(a.Challenges[0]); !ok || !at.Equal(due.Add(10*time.Minute)) {
		t.Fatalf("late wrong code purge = %v", at)
	}
	a.Challenges[0].WrongAttemptTimes = nil
	a.Challenges[0].WrongAttempts = 0
	a.Challenges[0].ProofDigest = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	a.Challenges[0].EncryptedProof = "synthetic-encrypted-proof"
	a.Challenges[0].ProofExpiresAt = "2026-10-14T01:00:00+03:00"
	a.Challenges[0].State = "completed"
	if at, ok := domain.ChallengePurgeAt(a.Challenges[0]); !ok || !at.Equal(time.Date(2026, 10, 15, 1, 0, 0, 0, time.FixedZone("", 3*3600))) {
		t.Fatalf("proof purge = %v", at)
	}
}
func TestValidateReplacementAtRefusesEverythingElse(t *testing.T) {
	a, due := retentionFixture(t)
	before := validated(t, a)
	cases := map[string]func(domain.Aggregate) domain.Aggregate{
		"challenge removed, job and record kept": func(a domain.Aggregate) domain.Aggregate {
			a.Challenges = []domain.Challenge{}
			return a
		},
		"challenge and job removed, record kept": func(a domain.Aggregate) domain.Aggregate {
			a.Challenges, a.MailJobs = []domain.Challenge{}, []domain.MailJob{}
			return a
		},
		"job removed alone": func(a domain.Aggregate) domain.Aggregate {
			a.MailJobs = []domain.MailJob{}
			return a
		},
		"record tombstoned, challenge and job kept": func(a domain.Aggregate) domain.Aggregate {
			return withTombstone(a, func(r *domain.IdempotencyRecord) {})
		},
		"tombstone keeps its job edge": func(a domain.Aggregate) domain.Aggregate {
			a = purged(a)
			a.Idempotency[len(a.Idempotency)-1].JobIDs = []domain.EntityID{"00000009-1111-4111-8111-111111111111"}
			return a
		},
		"tombstone changes the fingerprint": func(a domain.Aggregate) domain.Aggregate {
			a = purged(a)
			a.Idempotency[len(a.Idempotency)-1].Fingerprint = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
			return a
		},
		"another command record is cleared": func(a domain.Aggregate) domain.Aggregate {
			a = purged(a)
			a.Idempotency[0].EncryptedResponse = ""
			return a
		},
		"command record dropped": func(a domain.Aggregate) domain.Aggregate {
			a = purged(a)
			a.Idempotency = a.Idempotency[:len(a.Idempotency)-1]
			return a
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			next, err := domain.Validate(change(a))
			if err != nil {
				if !errors.Is(err, domain.ErrInvalidAggregate) {
					t.Fatal(err)
				}
				return
			}
			if err := domain.ValidateReplacementAt(before, next, due.Add(24*time.Hour)); !errors.Is(err, domain.ErrInvalidAggregate) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}
func withTombstone(a domain.Aggregate, change func(*domain.IdempotencyRecord)) domain.Aggregate {
	a.Idempotency = append([]domain.IdempotencyRecord(nil), a.Idempotency...)
	r := &a.Idempotency[len(a.Idempotency)-1]
	r.EncryptedResponse = ""
	r.JobIDs = []domain.EntityID{}
	change(r)
	return a
}
func TestValidateReplacementAtRefusesLiveJobs(t *testing.T) {
	for _, state := range []string{"queued", "sending", "unknown"} {
		t.Run(state, func(t *testing.T) {
			a, due := retentionFixture(t)
			a.Challenges[0].State = "pending"
			a.Challenges[0].EncryptedCode = "synthetic-encrypted-code"
			a.MailJobs[0].State = state
			a.MailJobs[0].EncryptedPayload = "synthetic-encrypted-mail"
			if state == "sending" || state == "unknown" {
				a.MailJobs[0].Attempts = 1
				a.MailJobs[0].LastAttemptAt = a.MailJobs[0].AcceptedAt
			}
			before := validated(t, a)
			next := validated(t, purged(a))
			if err := domain.ValidateReplacementAt(before, next, due.Add(24*time.Hour)); !errors.Is(err, domain.ErrInvalidAggregate) {
				t.Fatalf("live %s job removed with its challenge: %v", state, err)
			}
		})
	}
}
