package domain_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/JustIkra/umir-auth/internal/domain"
)

const fixtureInstant domain.Instant = "2026-10-13T01:00:00+03:00"

func id(n int) domain.EntityID {
	return domain.EntityID(fmt.Sprintf("%08x-1111-4111-8111-111111111111", n))
}
func fixture(t *testing.T) domain.Aggregate {
	t.Helper()
	data, err := os.ReadFile("../../tests/testdata/aggregate.json")
	if err != nil {
		t.Fatal(err)
	}
	var a domain.Aggregate
	if err := json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	return a
}
