package storecontract_test

import (
	"testing"

	"github.com/JustIkra/umir-auth/tests/memstore"
	"github.com/JustIkra/umir-auth/tests/storecontract"
)

func TestMemoryStore(t *testing.T) {
	storecontract.Run(t, func(*testing.T) *memstore.Store { return memstore.New() })
}
