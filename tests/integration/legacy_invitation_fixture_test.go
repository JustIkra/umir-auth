package integration_test

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func legacyInvitationFixture(t *testing.T, f *membershipFixture) domain.Invitation {
	t.Helper()
	a := f.snapshot(t)
	id, err := f.opts.IDs.NewID()
	if err != nil {
		t.Fatal(err)
	}
	now := f.opts.Clock.Now()
	assignments := []domain.InviteAssignment{{RestaurantID: f.r1, Roles: []string{"Waiter", "Warehouse"}}}
	v := domain.Invitation{InvitationID: id, OrgID: f.org, Email: "Invited@UMIR.INVALID", ComparisonEmail: "Invited@umir.invalid", Assignments: assignments, ExpiresAt: domain.Instant(now.Add(7 * 24 * time.Hour).Format(time.RFC3339Nano)), ResendAvailableAt: domain.Instant(now.Add(time.Minute).Format(time.RFC3339Nano)), State: "pending", Version: "1"}
	in := application.CreateInvitationInput{CommandID: "invite-1", Email: v.ComparisonEmail, Assignments: assignments}
	encoded, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := f.opts.Results.Digest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	tuple, err := json.Marshal(struct{ Version, Operation, Actor, Initiator, Org, Input string }{"1", "createInvitation", string(f.owner.User.UserID), "", string(f.org), digest})
	if err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := f.opts.Results.Seal(response)
	clear(response)
	if err != nil {
		t.Fatal(err)
	}
	a.SchemaVersion = 1
	for i := range a.MailJobs {
		a.MailJobs[i].Purpose, a.MailJobs[i].EnqueueOrder = "", ""
	}
	for i := range a.Idempotency {
		a.Idempotency[i].ContractProfile = ""
	}
	revision, ok := domain.VersionNumber(a.AggregateRevision)
	if !ok {
		t.Fatal("invalid fixture revision")
	}
	a.AggregateRevision = domain.Version(strconv.FormatInt(revision+1, 10))
	a.Invitations = append(a.Invitations, v)
	a.Idempotency = append(a.Idempotency, domain.IdempotencyRecord{ActorID: f.owner.User.UserID, OperationID: "createInvitation", OrgID: f.org, CommandID: in.CommandID, Fingerprint: application.TokenDigest(string(tuple)), AggregateRevision: a.AggregateRevision, HTTPStatus: 201, ResponseSchema: "Invitation", EncryptedResponse: sealed, JobIDs: []domain.EntityID{}, RecordedAt: domain.Instant(now.Format(time.RFC3339Nano))})
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.path = filepath.Join(t.TempDir(), "auth.json")
	f.store, err = jsonstore.Initialize(ctx, f.path, validate(t, a))
	if err != nil {
		t.Fatal(err)
	}
	f.opts.Repository = f.store
	f.accounts, err = application.NewAccounts(ctx, f.opts)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
