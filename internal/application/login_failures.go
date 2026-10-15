package application

import "time"

const maxLoginFailureKeys = 4096

type loginFailure struct {
	failureThrottle
	active int
}

type loginThrottles struct {
	entries map[string]*loginFailure
}

func (t *loginThrottles) acquire(login string, now time.Time) (*loginFailure, error) {
	key := TokenDigest(login)
	if entry := t.entries[key]; entry != nil {
		entry.active++
		return entry, nil
	}
	if len(t.entries) >= maxLoginFailureKeys {
		for key, entry := range t.entries {
			if entry.expired(now) {
				delete(t.entries, key)
			}
		}
		if len(t.entries) >= maxLoginFailureKeys {
			return nil, rateLimited(queueFullRetryAfter)
		}
	}
	if t.entries == nil {
		t.entries = make(map[string]*loginFailure)
	}
	entry := &loginFailure{active: 1}
	t.entries[key] = entry
	return entry, nil
}

func (t *loginThrottles) release(entry *loginFailure) {
	entry.active--
}

func (e *loginFailure) expired(now time.Time) bool {
	if e.active != 0 || e.wait(now) > 0 {
		return false
	}
	for _, at := range e.failures {
		if now.Sub(at) < DefaultFailureWindow {
			return false
		}
	}
	return true
}
