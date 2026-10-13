package ownermail_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/challengesecrets"
	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	mailadapter "github.com/JustIkra/umir-auth/internal/adapters/mail"
	"github.com/JustIkra/umir-auth/internal/adapters/password"
	"github.com/JustIkra/umir-auth/internal/adapters/sessionsecrets"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
	"github.com/JustIkra/umir-auth/tests/mailobserver"
	"github.com/JustIkra/umir-auth/tests/smtpsink"
)

type ownerClock struct{ at time.Time }

func (c *ownerClock) Now() time.Time { return c.at }

type ownerIDs struct {
	crypto *challengesecrets.ChallengeCrypto
}

func (g ownerIDs) NewID() (domain.EntityID, error) {
	id, err := g.crypto.NewID()
	return domain.EntityID(id), err
}
func (g ownerIDs) NewToken() (string, error) { return g.crypto.NewProof() }
func TestA4RealSMTPUsesDurableOwnerCorrelation(t *testing.T) {
	ctx := context.Background()
	a := domain.Empty()
	data, err := os.ReadFile("../testdata/aggregate.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	a.Sessions = []domain.Session{}
	a.Invitations = []domain.Invitation{}
	a.Challenges = []domain.Challenge{}
	a.MailJobs = []domain.MailJob{}
	a.Idempotency = []domain.IdempotencyRecord{}
	a.LifecycleIntents = []domain.LifecycleIntent{}
	a.Restaurants[0].Lifecycle = "ready"
	hasher, err := password.New(password.Selected, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a.Users[0].Verifier, err = hasher.Hash("synthetic-password")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	store, err := jsonstore.Initialize(ctx, filepath.Join(t.TempDir(), "auth.json"), initial)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	crypto, err := challengesecrets.New([]byte(strings.Repeat("p", 32)), []byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	results, err := sessionsecrets.New([]byte(strings.Repeat("r", 32)), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := &ownerClock{at: time.Date(2026, 10, 13, 9, 0, 0, 0, time.FixedZone("Europe/Moscow", 3*3600))}
	ids := ownerIDs{crypto}
	accounts, err := application.NewAccounts(ctx, application.AccountOptions{Repository: store, Passwords: hasher, Clock: clock, IDs: ids, Tokens: ids, Results: results, Challenges: crypto})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := accounts.Login(ctx, application.LoginInput{Login: a.Users[0].Login, Password: "synthetic-password"})
	if err != nil {
		t.Fatal(err)
	}
	invite, err := accounts.CreateInvitation(ctx, admin.Token, admin.CSRFToken, a.Organizations[0].OrgID, application.CreateInvitationInput{CommandID: "smtp-invite", Email: "invited@umir.invalid", Assignments: []domain.InviteAssignment{{RestaurantID: a.Restaurants[0].RestaurantID, Roles: []string{"Waiter"}}}})
	if err != nil {
		t.Fatal(err)
	}
	actor := application.ChallengeActor{PreauthDigest: application.TokenDigest("synthetic-browser")}
	challenge, err := accounts.BeginInvitationChallenge(ctx, actor, application.ChallengeBeginInput{CommandID: "smtp-begin", InvitationID: invite.InvitationID})
	if err != nil {
		t.Fatal(err)
	}
	server, roots := smtpsink.New(t, "starttls", 250)
	config := mailadapter.SMTPConfig{Host: "localhost", TLSMode: "starttls", Username: "umir-e2e", Password: "synthetic-password"}
	config.Port = server.Port()
	config.TLSMode = "starttls"
	config.From = "sender@umir.invalid"
	config.To = "unused@umir.invalid"
	config.RootCAs = roots
	transport, err := mailadapter.NewSMTP(config)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := mailadapter.NewRegistrationSMTP(transport, mailadapter.RegistrationMailConfig{OperatorName: "Тестовая организация", OperatorAddress: "Тестовый адрес, дом 1", SenderName: "Ровный ход"}, clock.Now, mailobserver.Observer{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	if worked, err := accounts.ProcessMail(ctx, sender); err != nil || !worked {
		t.Fatal("real owner worker/SMTP failed")
	}
	message := <-server.Messages()
	parsed, err := mail.ReadMessage(strings.NewReader(message))
	if err != nil {
		t.Fatal("MIME invalid")
	}
	snapshot, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	saved := snapshot.Snapshot()
	job := saved.MailJobs[0]
	if job.State != "delivered" || job.Attempts != 1 || parsed.Header.Get("X-Umir-Fixture-Job-ID") != string(job.JobID) || parsed.Header.Get("X-Umir-Fixture-Challenge-ID") != string(challenge.ChallengeID) {
		t.Fatal("captured MIME did not match real durable job/challenge")
	}
	if job.EncryptedPayload != "" {
		t.Fatal("delivered payload not scrubbed")
	}
}
