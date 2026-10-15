package integration_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
)

func TestUnknownLoginHasTheSameIsolatedCooldown(t *testing.T) {
	s, _, c, m, _ := setup(t)
	for range 5 {
		if _, err := s.Login(ctx, application.LoginInput{Login: "unknown", Password: "wrong"}); !errors.Is(err, application.ErrInvalidCredentials) {
			t.Fatal(err)
		}
	}
	before := m.verifications
	if _, err := s.Login(ctx, application.LoginInput{Login: "second", Password: "password"}); err != nil {
		t.Fatal("unknown login blocked an independent account", err)
	}
	var limit *application.RateLimitError
	if _, err := s.Login(ctx, application.LoginInput{Login: "unknown", Password: "password"}); !errors.As(err, &limit) || limit.RetryAfter != time.Minute || m.verifications != before+1 {
		t.Fatal("unknown login did not keep its own bounded cooldown", err)
	}
	c.advance(time.Minute)
	if _, err := s.Login(ctx, application.LoginInput{Login: "unknown", Password: "password"}); !errors.Is(err, application.ErrInvalidCredentials) || m.verifications != before+2 {
		t.Fatal("unknown login did not resume normal verification", err)
	}
}

func TestLoginCooldownAppliesToAnInFlightVerification(t *testing.T) {
	s, _, _, m, _ := setup(t)
	for range 4 {
		if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "wrong"}); !errors.Is(err, application.ErrInvalidCredentials) {
			t.Fatal(err)
		}
	}
	entered, released := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	t.Cleanup(release)
	var first atomic.Bool
	m.mu.Lock()
	m.hook = func() {
		if first.CompareAndSwap(false, true) {
			close(entered)
			<-released
		}
	}
	m.mu.Unlock()
	result := make(chan error, 1)
	go func() {
		_, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "password"})
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("password verification did not reach its barrier")
	}
	if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "wrong"}); !errors.Is(err, application.ErrInvalidCredentials) {
		t.Fatal(err)
	}
	release()
	select {
	case err := <-result:
		if !errors.Is(err, application.ErrLoginRateLimited) {
			t.Fatal("in-flight login bypassed the current cooldown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("password verification did not finish")
	}
}
