package integration_test

import (
	"errors"
	"fmt"
	"strings"
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

// Passwords the hasher can never accept (over 32 characters, invalid UTF-8) are
// refused before any throttle entry exists: they cost no Argon2 work, so they
// must neither fill the table of tracked logins nor start a cooldown.
func TestLengthAndUTF8RejectedLoginsDoNotMoveTheThrottle(t *testing.T) {
	long := strings.Repeat("a", 33)
	broken := "short\xff"
	t.Run("distinct logins do not fill the table", func(t *testing.T) {
		s, _, _, m, _ := setup(t)
		for i := range 4097 {
			if _, err := s.Login(ctx, application.LoginInput{Login: fmt.Sprintf("nobody-%d", i), Password: long}); !errors.Is(err, application.ErrInvalidCredentials) {
				t.Fatalf("attempt %d: %v", i, err)
			}
		}
		if m.verifications != 0 {
			t.Fatalf("%d verifications for refused passwords", m.verifications)
		}
		if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "password"}); err != nil {
			t.Fatalf("a correct login was refused after the flood: %v", err)
		}
	})
	t.Run("five attempts on a real login start no cooldown", func(t *testing.T) {
		s, _, _, _, _ := setup(t)
		for i, password := range []string{long, broken, long, broken, long, broken} {
			if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: password}); !errors.Is(err, application.ErrInvalidCredentials) || errors.Is(err, application.ErrLoginRateLimited) {
				t.Fatalf("attempt %d: %v", i, err)
			}
		}
		if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "password"}); err != nil {
			t.Fatalf("the real login is in cooldown: %v", err)
		}
	})
	t.Run("ordinary wrong passwords still count", func(t *testing.T) {
		s, _, _, _, _ := setup(t)
		for i := range 5 {
			if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "wrong"}); !errors.Is(err, application.ErrInvalidCredentials) {
				t.Fatalf("attempt %d: %v", i, err)
			}
		}
		if _, err := s.Login(ctx, application.LoginInput{Login: "owner", Password: "password"}); !errors.Is(err, application.ErrLoginRateLimited) {
			t.Fatalf("five wrong passwords started no cooldown: %v", err)
		}
	})
}
