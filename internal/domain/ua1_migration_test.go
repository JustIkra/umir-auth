package domain_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestUA1FormatUpgradePreservesLegacyFacts(t *testing.T) {
	old := fixture(t)
	v, err := domain.UpgradeV1(old)
	if err != nil {
		t.Fatal(err)
	}
	if v.SchemaVersion != 2 || v.AggregateRevision != old.AggregateRevision || !reflect.DeepEqual(v.Users, old.Users) || !reflect.DeepEqual(v.Invitations, old.Invitations) || !reflect.DeepEqual(v.Challenges, old.Challenges) {
		t.Fatal("migration changed authority, deadline or identity facts")
	}
	for i, j := range v.MailJobs {
		if j.Purpose != "otp" || j.EnqueueOrder == "" || j.JobID != old.MailJobs[i].JobID || j.EncryptedPayload != old.MailJobs[i].EncryptedPayload || j.AcceptedAt != old.MailJobs[i].AcceptedAt {
			t.Fatal("legacy OTP edge or ciphertext changed")
		}
	}
	for i, r := range v.Idempotency {
		if r.ContractProfile != "C2" || r.EncryptedResponse != old.Idempotency[i].EncryptedResponse || r.Fingerprint != old.Idempotency[i].Fingerprint {
			t.Fatal("legacy result changed")
		}
	}
	if _, err := domain.Validate(v); err != nil {
		t.Fatal(err)
	}
	v.MailJobs[0].EncryptedPayload = "modified output"
	if old.MailJobs[0].EncryptedPayload == "modified output" {
		t.Fatal("migration aliases the input")
	}
	old.SchemaVersion = 3
	if _, err := domain.UpgradeV1(old); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestUA1TypedLinkJobRequiresOneOwnedCommand(t *testing.T) {
	a, err := domain.UpgradeV1(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	a.AggregateRevision = "2"
	invite := a.Invitations[0]
	j := domain.MailJob{JobID: id(100), Purpose: "invitation_link", EnqueueOrder: "2", OrgID: invite.OrgID, InvitationID: invite.InvitationID, State: "queued", EncryptedPayload: "test-only-ciphertext", AcceptedAt: fixtureInstant}
	a.MailJobs = append(a.MailJobs, j)
	a.Idempotency = append(a.Idempotency, domain.IdempotencyRecord{ActorID: a.Users[0].UserID, OrgID: invite.OrgID, OperationID: "createInvitation", CommandID: "ua1-link-create", ContractProfile: "UA1", Fingerprint: strings.Repeat("c", 64), AggregateRevision: "2", HTTPStatus: 201, ResponseSchema: "Invitation", EncryptedResponse: "test-only-encrypted-response", JobIDs: []domain.EntityID{j.JobID}, RecordedAt: fixtureInstant})
	if _, err := domain.Validate(a); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*domain.Aggregate){
		"fabricated challenge": func(v *domain.Aggregate) { v.MailJobs[1].ChallengeID = v.Challenges[0].ChallengeID },
		"wrong organization":   func(v *domain.Aggregate) { v.MailJobs[1].OrgID = id(999) },
		"missing invitation":   func(v *domain.Aggregate) { v.MailJobs[1].InvitationID = "" },
		"unknown purpose":      func(v *domain.Aggregate) { v.MailJobs[1].Purpose = "other" },
		"reordered enqueue":    func(v *domain.Aggregate) { v.MailJobs[1].EnqueueOrder = "1" },
		"missing command job":  func(v *domain.Aggregate) { v.Idempotency[len(v.Idempotency)-1].JobIDs = []domain.EntityID{} },
		"wrong command scope":  func(v *domain.Aggregate) { v.Idempotency[len(v.Idempotency)-1].OrgID = "" },
		"changed profile":      func(v *domain.Aggregate) { v.Idempotency[len(v.Idempotency)-1].ContractProfile = "C2" },
	} {
		t.Run(name, func(t *testing.T) {
			validated, err := domain.Validate(a)
			if err != nil {
				t.Fatal(err)
			}
			bad := validated.Snapshot()
			mutate(&bad)
			if _, err := domain.Validate(bad); err == nil {
				t.Fatal("malformed link linkage accepted")
			}
		})
	}
}
