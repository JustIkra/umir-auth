package application

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestLoginFailureCapacityRetainsLiveCounters(t *testing.T) {
	now := time.Date(2026, 10, 15, 1, 0, 0, 0, time.FixedZone("Europe/Moscow", 10800))
	var throttles loginThrottles
	for i := range 4096 {
		entry, err := throttles.acquire(fmt.Sprintf("login-%d", i), now)
		if err != nil {
			t.Fatal("capacity exhausted before its declared bound", err)
		}
		entry.fail(now, 5, time.Minute, time.Minute)
		throttles.release(entry)
	}
	if _, err := throttles.acquire("additional-login", now); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatal("live failure counters were evicted to admit another key", err)
	}
	entry, err := throttles.acquire("login-0", now)
	if err != nil {
		t.Fatal("full capacity refused an existing key", err)
	}
	for range 4 {
		entry.fail(now, 5, time.Minute, time.Minute)
	}
	if entry.wait(now) != time.Minute {
		t.Fatal("capacity pressure reset the existing failure count")
	}
	throttles.release(entry)
	replacement, err := throttles.acquire("additional-login", now.Add(time.Minute))
	if err != nil {
		t.Fatal("expired failure counters did not free capacity", err)
	}
	throttles.release(replacement)
}

func TestLoginFailureCapacityPinsInFlightVerifications(t *testing.T) {
	now := time.Date(2026, 10, 15, 1, 0, 0, 0, time.FixedZone("Europe/Moscow", 10800))
	var throttles loginThrottles
	entries := make([]*loginFailure, 0, 4096)
	for i := range 4096 {
		entry, err := throttles.acquire(fmt.Sprintf("login-%d", i), now)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, entry)
	}
	if _, err := throttles.acquire("additional-login", now.Add(2*time.Minute)); !errors.Is(err, ErrLoginRateLimited) {
		t.Fatal("in-flight verifications lost their retained counters", err)
	}
	throttles.release(entries[0])
	entry, err := throttles.acquire("additional-login", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal("completed verification did not release capacity", err)
	}
	throttles.release(entry)
	for _, held := range entries[1:] {
		throttles.release(held)
	}
}
