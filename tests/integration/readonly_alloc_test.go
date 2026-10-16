package integration_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/adapters/jwt"
	"github.com/JustIkra/umir-auth/internal/adapters/timezones"
	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

// readonlyFixture gives an Accounts over an in-memory repository that holds
// extra sessions, so the cost of the read-only paths can be compared by size.
func readonlyFixture(t testing.TB, e *enrollmentFixture, sessions int) *application.Accounts {
	t.Helper()
	current, err := e.store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := current.Snapshot()
	if len(a.Users) == 0 {
		t.Fatal("fixture has no user")
	}
	now := e.opts.Clock.Now()
	for i := 0; i < sessions; i++ {
		digest := fmt.Sprintf("%064x", i+1)
		a.Sessions = append(a.Sessions, domain.Session{SessionID: uid(500000 + i), UserID: a.Users[0].UserID, SessionVersion: "1", CredentialVersion: a.Users[0].CredentialVersion, Digest: digest, CSRFTokenDigest: digest, CreatedAt: instant(now), IdleExpiresAt: instant(now.Add(time.Hour)), AbsoluteExpiresAt: instant(now.Add(8 * time.Hour)), Revoked: true})
	}
	data, err := os.ReadFile("../testdata/zoneinfo.zip")
	if err != nil {
		t.Fatal(err)
	}
	if e.opts.TimeZones, err = timezones.New(data, "go1.26.9-packaged"); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if e.opts.Issuer, err = jwt.New(jwt.Options{Clock: e.opts.Clock, IDs: e.opts.IDs, Active: jwt.SigningKey{KID: "a5", PrivateKey: key}}); err != nil {
		t.Fatal(err)
	}
	validated, err := domain.Validate(a)
	if err != nil {
		t.Fatal(err)
	}
	e.opts.Repository = &memoryRepo{current: validated, clock: e.opts.Clock}
	accounts, err := application.NewAccounts(ctx, e.opts)
	if err != nil {
		t.Fatal(err)
	}
	return accounts
}

// bytesPerRun is the heap volume one call allocates. Counting allocations is not
// enough here: cloning a slice is one allocation whatever its length.
func bytesPerRun(runs int, f func()) float64 {
	f()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < runs; i++ {
		f()
	}
	runtime.ReadMemStats(&after)
	return float64(after.TotalAlloc-before.TotalAlloc) / float64(runs)
}

// Readiness and an idle worker tick only look at the stored state; their cost
// must not grow with the number of stored sessions (K2).
func TestReadinessAndIdleTickDoNotCloneTheAggregate(t *testing.T) {
	e := registrationSetup(t)
	idle := mailSenderFunc(func() application.DeliveryResult { return application.DeliveryResult{Success: true} })
	measure := func(sessions int) (ready, tick float64) {
		accounts := readonlyFixture(t, e, sessions)
		if err := accounts.Ready(ctx); err != nil {
			t.Fatal(err)
		}
		if worked, err := accounts.ProcessMail(ctx, idle); err != nil || worked {
			t.Fatalf("fixture is not idle: %v %v", worked, err)
		}
		ready = bytesPerRun(20, func() {
			if err := accounts.Ready(ctx); err != nil {
				t.Fatal(err)
			}
		})
		tick = bytesPerRun(20, func() {
			if _, err := accounts.ProcessMail(ctx, idle); err != nil {
				t.Fatal(err)
			}
		})
		return
	}
	const slack = 4096 // bytes; the cost of 100000 cloned sessions is megabytes
	smallReady, smallTick := measure(100)
	largeReady, largeTick := measure(100000)
	if largeReady > smallReady+slack {
		t.Fatalf("Ready allocated bytes grow with the state: %v with 100 sessions, %v with 100000", smallReady, largeReady)
	}
	if largeTick > smallTick+slack {
		t.Fatalf("idle tick allocated bytes grow with the state: %v with 100 sessions, %v with 100000", smallTick, largeTick)
	}
}

func BenchmarkReady100k(b *testing.B) {
	e := registrationSetup(&testing.T{})
	accounts := readonlyFixture(b, e, 100000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := accounts.Ready(ctx); err != nil {
			b.Fatal(err)
		}
	}
}
