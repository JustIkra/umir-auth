package integration_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/JustIkra/umir-auth/internal/adapters/jsonstore"
	"github.com/JustIkra/umir-auth/internal/adapters/sessionsecrets"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func TestLongCommandIDsPersistAndReplayAfterRestart(t *testing.T) {
	commands := []struct{ name, id string }{
		{"ascii129", strings.Repeat("c", 129)},
		{"unicode129", strings.Repeat("я", 129)},
		{"ascii256", strings.Repeat("c", 256)},
		{"unicode256", strings.Repeat("я", 256)},
		{"emoji256", strings.Repeat("🚀", 256)},
	}
	testCommandIDsPersistAndReplay(t, commands)
}

func TestEscapedCommandIDsPersistAndReplayAfterRestart(t *testing.T) {
	cases := []struct{ name, wire, want string }{
		{"nul", `"\u0000"`, "\x00"},
		{"cr", `"\r"`, "\r"},
		{"lf", `"\n"`, "\n"},
		{"mixed", `"Я\u0000\r\n\u0065\u0301\ud83d\ude80"`, "Я\x00\r\ne\u0301🚀"},
		{"unicode", `"é/e\u0301/日本語/\ud83d\ude80"`, "é/e\u0301/日本語/🚀"},
		{"whitespace", `" \t "`, " \t "},
		{"caseSensitivePrefix", `"Expiration/\u0000\r\n"`, "Expiration/\x00\r\n"},
		{"nonPrefix", `"xexpiration/\u0000"`, "xexpiration/\x00"},
		{"longLF", `"` + strings.Repeat("c", 129) + `\n"`, strings.Repeat("c", 129) + "\n"},
	}
	commands := make([]struct{ name, id string }, 0, len(cases))
	for _, tc := range cases {
		var id string
		if err := json.Unmarshal([]byte(tc.wire), &id); err != nil {
			t.Fatal(err)
		}
		if id != tc.want {
			t.Fatalf("%s: decoded value changed", tc.name)
		}
		commands = append(commands, struct{ name, id string }{tc.name, id})
	}
	testCommandIDsPersistAndReplay(t, commands)
}

func testCommandIDsPersistAndReplay(t *testing.T, commands []struct{ name, id string }) {
	t.Helper()
	for _, command := range commands {
		for _, operation := range []string{"login", "displayName", "password"} {
			t.Run(command.name+"/"+operation, func(t *testing.T) {
				_, r, c, m, path := setup(t)
				key, err := sessionsecrets.New([]byte(strings.Repeat("s", 32)), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				newService := func(repo application.AggregateRepository) *application.Accounts {
					s, err := application.NewAccounts(ctx, application.AccountOptions{Repository: repo, Passwords: m, Clock: c, IDs: m, Tokens: m, Results: key})
					if err != nil {
						t.Fatal(err)
					}
					return s
				}
				s := newService(r)
				in := application.LoginInput{Login: "owner", Password: "password", CommandID: command.id, PreauthDigest: application.TokenDigest("initiating-browser")}
				var issued application.SessionView
				var profile application.UserView
				var token string
				switch operation {
				case "login":
					issued, err = s.Login(ctx, in)
				case "displayName":
					token = login(t, s, "owner", false).Token
					profile, err = s.UpdateDisplayNameCommand(ctx, token, "Updated", command.id)
				case "password":
					token = login(t, s, "owner", false).Token
					err = s.ChangePasswordCommand(ctx, token, "password", "newpassword", command.id)
				}
				if err != nil {
					t.Fatalf("wire-valid command ID %q rejected: %v", command.id, err)
				}
				if operation == "password" {
					if _, err := s.Peek(ctx, token); !errors.Is(err, application.ErrUnauthenticated) {
						t.Fatal("password command did not revoke the old session")
					}
					token = login(t, s, "owner", false).Token
				}
				before, err := r.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				records := before.Snapshot().Idempotency
				if len(records) != 1 || records[0].CommandID != command.id {
					t.Fatal("committed command ID was changed")
				}
				diskBefore, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				r, err = jsonstore.Open(ctx, path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := r.Close(); err != nil {
						t.Error(err)
					}
				}()
				s = newService(r)
				reopened, err := r.Load(ctx)
				if err != nil || !reflect.DeepEqual(reopened.Snapshot(), before.Snapshot()) {
					t.Fatalf("restart changed the retained authority: %v", err)
				}
				verifications, hashes := m.verifications, m.hashes
				switch operation {
				case "login":
					var replay application.SessionView
					replay, err = s.Login(ctx, in)
					if err == nil && replay != issued {
						t.Fatal("long login ID did not restore the original session")
					}
				case "displayName":
					var replay application.UserView
					replay, err = s.UpdateDisplayNameCommand(ctx, token, "Updated", command.id)
					if err == nil && (replay != profile || replay.DisplayName != "Updated") {
						t.Fatal("long profile ID did not restore the original result")
					}
				case "password":
					err = s.ChangePasswordCommand(ctx, token, "password", "newpassword", command.id)
					if _, peekErr := s.Peek(ctx, token); peekErr != nil {
						t.Fatal("long password ID replay revoked the new device session")
					}
				}
				if err != nil {
					t.Fatalf("long command ID replay failed: %v", err)
				}
				after, err := r.Load(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if after.Revision() != before.Revision() || !reflect.DeepEqual(after.Snapshot(), before.Snapshot()) || m.verifications != verifications || m.hashes != hashes {
					t.Fatal("exact replay changed authority or repeated credential work")
				}
				switch operation {
				case "login":
					in.Password = "different"
					_, err = s.Login(ctx, in)
				case "displayName":
					_, err = s.UpdateDisplayNameCommand(ctx, token, "Changed", command.id)
				case "password":
					err = s.ChangePasswordCommand(ctx, token, "different", "newpassword", command.id)
				}
				if !errors.Is(err, application.ErrCommandConflict) {
					t.Fatal("changed input with a long command ID did not conflict")
				}
				afterConflict, err := r.Load(ctx)
				if err != nil || !reflect.DeepEqual(afterConflict.Snapshot(), before.Snapshot()) {
					t.Fatalf("conflict changed authority: %v", err)
				}
				diskAfter, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(diskAfter, diskBefore) {
					t.Fatalf("replay or conflict rewrote the JSON store: %v", err)
				}
			})
		}
	}
}

func TestInvalidCommandIDsDoNotCommit(t *testing.T) {
	commands := []struct{ name, id string }{
		{"ascii257", strings.Repeat("c", 257)},
		{"unicode257", strings.Repeat("я", 257)},
		{"legacy4096", strings.Repeat("c", 4096)},
		{"reserved", "expiration/"},
		{"reservedWithControls", "expiration/\x00\r\n"},
		{"invalidByte", string([]byte{0xff})},
		{"overlongUTF8", string([]byte{0xc0, 0xaf})},
		{"surrogateUTF8", string([]byte{0xed, 0xa0, 0x80})},
		{"truncatedUTF8", string([]byte{0xf0, 0x9f, 0x9a})},
	}
	for _, command := range commands {
		for _, operation := range []string{"login", "displayName", "password"} {
			t.Run(command.name+"/"+operation, func(t *testing.T) {
				_, r, c, m, path := setup(t)
				key, err := sessionsecrets.New([]byte(strings.Repeat("s", 32)), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				s, err := application.NewAccounts(ctx, application.AccountOptions{Repository: r, Passwords: m, Clock: c, IDs: m, Tokens: m, Results: key})
				if err != nil {
					t.Fatal(err)
				}
				token := ""
				if operation != "login" {
					token = login(t, s, "owner", false).Token
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				verifications, hashes := m.verifications, m.hashes
				switch operation {
				case "login":
					_, err = s.Login(ctx, application.LoginInput{Login: "owner", Password: "password", CommandID: command.id, PreauthDigest: application.TokenDigest("browser")})
				case "displayName":
					_, err = s.UpdateDisplayNameCommand(ctx, token, "Updated", command.id)
				case "password":
					err = s.ChangePasswordCommand(ctx, token, "password", "newpassword", command.id)
				}
				var field *application.FieldError
				if !errors.As(err, &field) || field.Field != "commandID" || field.Code != "InvalidFormat" {
					t.Fatalf("invalid command ID was not refused at admission: %v", err)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) || m.verifications != verifications || m.hashes != hashes {
					t.Fatalf("refused command changed durable state or verified credentials: %v", err)
				}
			})
		}
	}
}

func commandAggregate(t *testing.T, commandID string) domain.Aggregate {
	t.Helper()
	a := fixture(t)
	a.Idempotency = []domain.IdempotencyRecord{{ActorID: a.Users[0].UserID, OperationID: "displayName", CommandID: commandID, Fingerprint: strings.Repeat("a", 64), AggregateRevision: "1", HTTPStatus: 200, ResponseSchema: "User", EncryptedResponse: "sealed", JobIDs: []domain.EntityID{}}}
	return a
}

func TestDurableCommandBoundaryRejectsInvalidValues(t *testing.T) {
	if _, err := domain.Validate(commandAggregate(t, "valid")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"", "expiration/", "expiration/\x00", string([]byte{0xff}), string([]byte{0xc0, 0xaf}), string([]byte{0xed, 0xa0, 0x80}), string([]byte{0xf0, 0x9f, 0x9a})} {
		t.Run(fmt.Sprintf("%q", command), func(t *testing.T) {
			if _, err := domain.Validate(commandAggregate(t, command)); !errors.Is(err, domain.ErrInvalidAggregate) {
				t.Fatalf("invalid durable command ID accepted: %v", err)
			}
		})
	}
}

func TestOtherDurableTextStillRejectsControls(t *testing.T) {
	for _, control := range []string{"\x00", "\r", "\n"} {
		for _, field := range []string{"login", "displayName", "organization", "restaurant", "operation", "schema", "response"} {
			t.Run(fmt.Sprintf("%s/%q", field, control), func(t *testing.T) {
				a := commandAggregate(t, "valid")
				switch field {
				case "login":
					a.Users[0].Login += control
				case "displayName":
					a.Users[0].DisplayName += control
				case "organization":
					a.Organizations[0].Name += control
				case "restaurant":
					a.Restaurants[0].Name += control
				case "operation":
					a.Idempotency[0].OperationID += control
				case "schema":
					a.Idempotency[0].ResponseSchema += control
				case "response":
					a.Idempotency[0].EncryptedResponse += control
				}
				if _, err := domain.Validate(a); !errors.Is(err, domain.ErrInvalidAggregate) {
					t.Fatalf("other text validator admitted controls: %v", err)
				}
			})
		}
	}
}

func TestJSONStoreRefusesMalformedCommandUTF8(t *testing.T) {
	valid, err := json.Marshal(commandAggregate(t, "command-marker"))
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{{0xff}, {0xc0, 0xaf}, {0xed, 0xa0, 0x80}, {0xf0, 0x9f, 0x9a}} {
		t.Run(fmt.Sprintf("%x", invalid), func(t *testing.T) {
			path := t.TempDir() + "/auth.json"
			corrupt := bytes.Replace(valid, []byte("command-marker"), invalid, 1)
			if err := os.WriteFile(path, corrupt, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := jsonstore.Open(ctx, path)
			if err == nil {
				if closeErr := r.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if !errors.Is(err, application.ErrStorageUnavailable) || !errors.Is(err, domain.ErrInvalidAggregate) {
				t.Fatalf("malformed UTF-8 in persisted command ID was not refused: %v", err)
			}
		})
	}
}

func TestLegacyLongCommandRecordsSurviveRegistrationMigration(t *testing.T) {
	old := commandAggregate(t, strings.Repeat("c", 4096))
	next, err := domain.UpgradeRegistration(old)
	if err != nil {
		t.Fatal(err)
	}
	if next.Idempotency[0].CommandID != old.Idempotency[0].CommandID || next.Idempotency[0].Fingerprint != old.Idempotency[0].Fingerprint || next.Idempotency[0].EncryptedResponse != old.Idempotency[0].EncryptedResponse {
		t.Fatal("legacy command facts changed")
	}
}
