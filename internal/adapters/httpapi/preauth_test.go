package httpapi

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

func TestPreauthIssueHasNoTableAndNoCap(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	p, err := NewPreauth([]byte(strings.Repeat("k", 32)), clock)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 1100; i++ {
		issued, err := p.Issue("")
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		if seen[issued.PreauthToken] {
			t.Fatalf("issue %d repeated a token", i)
		}
		seen[issued.PreauthToken] = true
		if err := p.Verify(issued.PreauthToken, issued.CSRFToken); err != nil {
			t.Fatalf("token %d does not verify: %v", i, err)
		}
	}
	var fields []string
	for i, typ := 0, reflect.TypeOf(*p); i < typ.NumField(); i++ {
		fields = append(fields, typ.Field(i).Name)
	}
	slices.Sort(fields)
	if !slices.Equal(fields, []string{"clock", "key"}) {
		t.Fatalf("Preauth holds mutable state: fields %v", fields)
	}
}

func TestPreauthExpiresAndRefreshesWithoutState(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	p, err := NewPreauth([]byte(strings.Repeat("k", 32)), clock)
	if err != nil {
		t.Fatal(err)
	}
	first, err := p.Issue("")
	if err != nil {
		t.Fatal(err)
	}
	again, err := p.Issue(first.PreauthToken)
	if err != nil || again.PreauthToken != first.PreauthToken || again.CSRFToken != first.CSRFToken {
		t.Fatalf("a live token was not returned as it is: %v", err)
	}
	clock.now = clock.now.Add(30 * time.Minute)
	if err := p.Verify(first.PreauthToken, first.CSRFToken); err == nil {
		t.Fatal("an expired token verifies")
	}
	fresh, err := p.Issue(first.PreauthToken)
	if err != nil || fresh.PreauthToken == first.PreauthToken {
		t.Fatalf("an expired token was not replaced: %v", err)
	}
}
