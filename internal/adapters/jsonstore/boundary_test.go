package jsonstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func acceptedDeletion(t *testing.T, kind string) domain.Aggregate {
	t.Helper()
	a := fixture(t)
	a.AggregateRevision = "2"
	a.Restaurants[0].Lifecycle = "deleting"
	a.Restaurants[0].LifecycleVersion = "2"
	a.Memberships[0].Assignments = []domain.Assignment{}
	a.Memberships[0].MembershipVersion = "2"
	a.Invitations[0].State = "suppressed"
	a.Invitations[0].Version = "2"
	a.MailJobs[0].State = "suppressed"
	previous := a.LifecycleIntents[0]
	previous.RestaurantIDs = append([]domain.EntityID{}, previous.RestaurantIDs...)
	previous.Services = append([]domain.PeerReadiness{}, previous.Services...)
	previous.OperationID = "0000000c-1111-4111-8111-111111111111"
	previous.CommandID = "delete-once"
	a.LifecycleIntents = append(a.LifecycleIntents, previous)
	a.LifecycleIntents[1].Lifecycle = "deleting"
	a.LifecycleIntents[1].LifecycleVersion = "2"
	a.LifecycleIntents[1].Cleanup = "pending"
	for i := range a.LifecycleIntents[1].Services {
		a.LifecycleIntents[1].Services[i].LifecycleVersion = "2"
	}
	a.Tombstones = []domain.Tombstone{{EntityID: a.Restaurants[0].RestaurantID, Kind: "restaurant", OrgID: a.Restaurants[0].OrgID, LifecycleVersion: "2", DeletedAt: "2026-10-13T01:00:00+03:00"}}
	if kind == "organization" {
		a.Organizations[0].Lifecycle = "deleting"
		a.Organizations[0].LifecycleVersion = "2"
		a.Memberships[0].State = "revoked"
		a.Tombstones = append(a.Tombstones, domain.Tombstone{EntityID: a.Organizations[0].OrgID, Kind: "organization", OrgID: a.Organizations[0].OrgID, LifecycleVersion: "2", DeletedAt: "2026-10-13T01:00:00+03:00"})
	}
	return a
}

func TestAcceptedDeletionPersistsAcrossRestart(t *testing.T) {
	for _, kind := range []string{"restaurant", "organization"} {
		t.Run(kind, func(t *testing.T) {
			s, p := seeded(t)
			a := acceptedDeletion(t, kind)
			r, err := s.Commit(context.Background(), "1", validated(t, a))
			if err != nil || r.Outcome != application.Committed || r.AggregateRevision != "2" {
				t.Fatalf("accept deletion: %+v %v", r, err)
			}
			closeStore(t, s)
			s, err = Open(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			defer closeStore(t, s)
			if !reflect.DeepEqual(load(t, s).Snapshot(), a) {
				t.Fatal("accepted deletion, tombstones or unrelated authority changed after restart")
			}
			completed := load(t, s).Snapshot()
			completed.AggregateRevision = "3"
			completed.Restaurants[0].Lifecycle = "deleted"
			if kind == "organization" {
				completed.Organizations[0].Lifecycle = "deleted"
			}
			completed.LifecycleIntents[1].Lifecycle = "deleted"
			completed.LifecycleIntents[1].Cleanup = "complete"
			for i := range completed.LifecycleIntents[1].Services {
				completed.LifecycleIntents[1].Services[i].State = "closed"
				completed.LifecycleIntents[1].Services[i].Epoch = "0000000b-1111-4111-8111-111111111111"
			}
			if _, err := s.Commit(context.Background(), "2", validated(t, completed)); err != nil {
				t.Fatalf("complete deletion with original tombstones: %v", err)
			}
		})
	}
}

func TestAcceptedDeletionRequiresTombstones(t *testing.T) {
	for _, kind := range []string{"restaurant", "organization"} {
		t.Run(kind, func(t *testing.T) {
			a := acceptedDeletion(t, kind)
			a.Tombstones = a.Tombstones[:len(a.Tombstones)-1]
			if _, err := domain.Validate(a); !errors.Is(err, domain.ErrInvalidAggregate) {
				t.Fatalf("deleting %s without durable tombstone accepted: %v", kind, err)
			}
		})
	}
}

func TestInitializationCancellationAfterCommit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.json")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	files := systemDisk()
	real := files.rename
	files.rename = func(a, b string) error {
		err := real(a, b)
		if err == nil {
			cancel()
		}
		return err
	}
	s, err := open(ctx, p, &initialization{aggregate: validated(t, fixture(t))}, files)
	if err != nil || s == nil {
		t.Fatalf("confirmed initialization lost after cancellation: %v", err)
	}
	if load(t, s).Revision() != "1" {
		t.Fatal("committed initialization not published")
	}
	closeStore(t, s)
	reopened, err := Open(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer closeStore(t, reopened)
	if !reflect.DeepEqual(load(t, reopened).Snapshot(), fixture(t)) {
		t.Fatal("confirmed initialization not durable")
	}
}

func TestNonRegularStartupFailsPromptly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.json")
	if err := syscall.Mkfifo(p, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		s, err := Open(ctx, p)
		if s != nil {
			err = errors.Join(err, s.Close())
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, application.ErrStorageUnavailable) {
			t.Fatalf("FIFO startup: %v", err)
		}
	case <-time.After(time.Second):
		writer, err := os.OpenFile(p, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		<-done
		t.Fatal("FIFO open blocks before file-type validation despite cancellation")
	}
	cancel()
	if _, err := Open(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled startup: %v", err)
	}
	lock, err := acquire(p + ".lock")
	if err != nil {
		t.Fatalf("failed startup leaked writer lock: %v", err)
	}
	if err := lock.close(); err != nil {
		t.Fatal(err)
	}
}
