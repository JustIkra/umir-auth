package storecontract

import (
	"context"
	"errors"
	"testing"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
	"github.com/JustIkra/umir-auth/tests/memstore"
)

func TestMemoryStoreRollsBackFailedTransaction(t *testing.T) {
	checkFailedTransactionRollsBack(t, memstore.New())
}

func TestMemoryStoreRejectsEmailLoginHostCaseAlias(t *testing.T) {
	store := memstore.New()
	ctx := context.Background()
	for _, login := range []string{"owner@EXAMPLE.invalid", "owner@example.invalid"} {
		_, err := store.InTx(ctx, application.Scope{Actor: application.ActorSystem}, func(tx application.Tx) error {
			return tx.Users().Insert(ctx, domain.User{UserID: domain.EntityID(login), Login: login})
		})
		if login == "owner@EXAMPLE.invalid" && err != nil {
			t.Fatal(err)
		}
		if login == "owner@example.invalid" && !errors.Is(err, application.ErrEntityConflict) {
			t.Fatalf("case alias was not rejected: %v", err)
		}
	}
	if err := store.View(ctx, application.Scope{Actor: application.ActorSystem}, func(reader application.Reader) error {
		user, found, err := reader.Users().Get(ctx, "owner@EXAMPLE.invalid")
		if err != nil {
			return err
		}
		if !found || user.Login != "owner@EXAMPLE.invalid" {
			t.Fatal("committed user is not visible")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func checkFailedTransactionRollsBack(t *testing.T, store application.Store) {
	t.Helper()
	ctx := context.Background()
	user := domain.User{UserID: "user-1", Login: "owner@example.invalid"}
	_, err := store.InTx(ctx, application.Scope{Actor: application.ActorSystem}, func(tx application.Tx) error {
		if err := tx.Users().Insert(ctx, user); err != nil {
			return err
		}
		return errors.New("abort transaction")
	})
	if err == nil {
		t.Fatal("failed transaction committed")
	}
	if err := store.View(ctx, application.Scope{Actor: application.ActorSystem}, func(reader application.Reader) error {
		_, found, err := reader.Users().Get(ctx, user.UserID)
		if err != nil {
			return err
		}
		if found {
			t.Fatal("rolled back user is visible")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
