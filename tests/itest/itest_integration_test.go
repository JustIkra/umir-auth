//go:build integration

package itest_test

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/JustIkra/umir-auth/internal/adapters/postgres"
	"github.com/JustIkra/umir-auth/internal/adapters/rabbitmq"
	"github.com/JustIkra/umir-auth/tests/itest"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestEnvHasOwnerAndRuntimeRoles(t *testing.T) {
	e := itest.NewEnv(t)
	ctx := context.Background()
	owner, err := postgres.Open(ctx, postgres.Config{URL: e.OwnerURL, MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	spec := postgres.Spec{Service: "auth", Dir: "m", FS: fstest.MapFS{"m/0001_base.sql": {Data: []byte("-- umir:include storage_meta\n-- umir:include worker_leases\n-- umir:include outbox\n-- umir:include inbox\n")}}}
	if err := postgres.Migrate(ctx, owner, spec); err != nil {
		t.Fatal(err)
	}
	rt, err := postgres.Open(ctx, postgres.Config{URL: e.RuntimeURL, MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if err := postgres.AssertRuntimeRole(ctx, rt); err != nil {
		t.Fatalf("runtime role: %v", err)
	}
	if err := postgres.AssertRuntimeRole(ctx, owner); err == nil {
		t.Fatal("the owner role passed AssertRuntimeRole")
	}
	if _, err := postgres.Generation(ctx, rt); err != nil {
		t.Fatal(err)
	}
}

func TestVHostAcceptsConnections(t *testing.T) {
	url := itest.NewVHost(t)
	c := &rabbitmq.Connector{URL: rabbitmq.BrokerURL(url), Name: "t-auth"}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	up := make(chan struct{}, 1)
	go func() {
		_ = c.Run(ctx, func(ctx context.Context, _ *amqp.Connection, upFn func()) error {
			upFn()
			up <- struct{}{}
			<-ctx.Done()
			return nil
		})
	}()
	<-up
}
