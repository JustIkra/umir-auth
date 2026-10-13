package application

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	DefaultMaxVerifications = 2
	DefaultMaxQueuedLogins  = 8
	DefaultFailureLimit     = 5
	DefaultFailureWindow    = 60 * time.Second
	DefaultCooldown         = 60 * time.Second
	queueFullRetryAfter     = time.Second
)

var (
	ErrLoginRateLimited          = errors.New("login rate limited")
	ErrPasswordChangeRateLimited = errors.New("password change rate limited")
)

type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string { return ErrLoginRateLimited.Error() }

func (e *RateLimitError) Unwrap() error { return ErrLoginRateLimited }

func rateLimited(wait time.Duration) *RateLimitError {
	return &RateLimitError{RetryAfter: wholeSeconds(wait)}
}

type PasswordChangeLimitError struct {
	RetryAfter     time.Duration
	SessionRevoked bool
}

func (e *PasswordChangeLimitError) Error() string { return ErrPasswordChangeRateLimited.Error() }

func (e *PasswordChangeLimitError) Unwrap() error { return ErrPasswordChangeRateLimited }

func wholeSeconds(wait time.Duration) time.Duration {
	return max(time.Second, (wait+time.Second-1)/time.Second*time.Second)
}

type verificationGate struct {
	slots     chan struct{}
	maxQueued int

	mu             sync.Mutex
	waitingLogins  int
	waitingChanges int
}

func newVerificationGate(running, queued int) *verificationGate {
	return &verificationGate{slots: make(chan struct{}, running), maxQueued: queued}
}

func (g *verificationGate) acquire(ctx context.Context, bounded bool) (release func(), err error) {
	select {
	case g.slots <- struct{}{}:
		return g.release, nil
	default:
	}
	waiting := &g.waitingChanges
	if bounded {
		waiting = &g.waitingLogins
	}
	g.mu.Lock()
	if bounded && *waiting >= g.maxQueued {
		g.mu.Unlock()
		return nil, rateLimited(queueFullRetryAfter)
	}
	*waiting++
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		*waiting--
		g.mu.Unlock()
	}()
	select {
	case g.slots <- struct{}{}:
		return g.release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (g *verificationGate) release() { <-g.slots }

type failureThrottle struct {
	failures []time.Time
	until    time.Time
}

func (t *failureThrottle) wait(now time.Time) time.Duration {
	if now.Before(t.until) {
		return t.until.Sub(now)
	}
	return 0
}

func (t *failureThrottle) fail(now time.Time, limit int, window, cooldown time.Duration) bool {
	kept := t.failures[:0]
	for _, at := range t.failures {
		if now.Sub(at) < window {
			kept = append(kept, at)
		}
	}
	kept = append(kept, now)
	if len(kept) >= limit {
		t.until = now.Add(cooldown)
		t.failures = kept[:0]
		return true
	}
	t.failures = kept
	return false
}
