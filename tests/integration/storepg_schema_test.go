//go:build integration

package integration_test

import (
	"context"
	"testing"

	"github.com/JustIkra/umir-auth/internal/adapters/postgres"
	"github.com/JustIkra/umir-auth/internal/adapters/storepg"
	"github.com/JustIkra/umir-auth/tests/itest"
	"github.com/jackc/pgx/v5"
)

func TestStorePGSchemaUsesRealOwnerRuntimeRoles(t *testing.T) {
	env := itest.NewEnv(t)
	owner, err := postgres.Open(t.Context(), postgres.Config{URL: env.OwnerURL, MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	spec := storepg.MigrationSpec()
	if err := postgres.Migrate(t.Context(), owner, spec); err != nil {
		t.Fatal(err)
	}
	if err := postgres.Migrate(t.Context(), owner, spec); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	runtime, err := postgres.Open(t.Context(), postgres.Config{URL: env.RuntimeURL, MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if err := postgres.AssertRuntimeRole(t.Context(), runtime); err != nil {
		t.Fatalf("runtime role: %v", err)
	}
	if err := postgres.AssertRuntimeRole(t.Context(), owner); err == nil {
		t.Fatal("owner role passed runtime role check")
	}
	if err := postgres.VerifySchema(t.Context(), runtime, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := storepg.Generation(t.Context(), runtime); err != nil {
		t.Fatal(err)
	}
}

func TestStorePGRLSContextDoesNotLeakAcrossPooledTransactions(t *testing.T) {
	env := itest.NewEnv(t)
	owner, err := postgres.Open(t.Context(), postgres.Config{URL: env.OwnerURL, MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	spec := storepg.MigrationSpec()
	if err := postgres.Migrate(t.Context(), owner, spec); err != nil {
		t.Fatal(err)
	}
	runtime, err := postgres.Open(t.Context(), postgres.Config{URL: env.RuntimeURL, MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	userID := "11111111-1111-4111-8111-111111111111"
	userB := "44444444-4444-4444-8444-444444444444"
	if err := runtime.InSystemTx(t.Context(), "auth.test.seed", pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO users(user_id, login, login_key, display_name, credential_version, verifier) VALUES ($1, 'rls@example.invalid', 'rls@example.invalid', 'RLS Test', 1, 'test')`, userID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO users(user_id, login, login_key, display_name, credential_version, verifier) VALUES ($1, 'other@example.invalid', 'other@example.invalid', 'Other', 1, 'test')`, userB)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	orgA := "22222222-2222-4222-8222-222222222222"
	orgB := "33333333-3333-4333-8333-333333333333"
	for _, orgID := range []string{orgA, orgB} {
		if err := runtime.InScopedTx(t.Context(), postgres.Scope{Actor: postgres.ActorTenant, OrgID: orgID}, pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO organizations(org_id, name, time_zone, settings_version, lifecycle, lifecycle_version, created_by, created_at) VALUES ($1, 'Test', 'Europe/Moscow', 1, 'active', 1, $2, '2026-10-16T00:00:00Z')`, orgID, userID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := runtime.InSystemTx(t.Context(), "auth.test.seed", pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO memberships(membership_id, user_id, org_id, org_admin, state, membership_version) VALUES ('55555555-5555-4555-8555-555555555555', $1, $2, true, 'active', 1)`, userID, orgA); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO memberships(membership_id, user_id, org_id, org_admin, state, membership_version) VALUES ('66666666-6666-4666-8666-666666666666', $1, $2, true, 'active', 1)`, userB, orgA)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		scope string
		want  int
	}{{orgA, 1}, {orgB, 1}, {"", 0}} {
		var count int
		var err error
		if tc.scope == "" {
			err = runtime.InTx(t.Context(), pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(ctx context.Context, tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM organizations`).Scan(&count)
			})
		} else {
			err = runtime.InScopedTx(t.Context(), postgres.Scope{Actor: postgres.ActorTenant, OrgID: tc.scope}, pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM organizations`).Scan(&count)
			})
		}
		if err != nil {
			t.Fatal(err)
		}
		if count != tc.want {
			t.Fatalf("scope %q saw %d organizations, want %d", tc.scope, count, tc.want)
		}
	}
	var membershipCount int
	if err := runtime.InScopedTx(t.Context(), postgres.Scope{Actor: postgres.ActorUser, UserID: userID}, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM memberships`).Scan(&membershipCount)
	}); err != nil {
		t.Fatal(err)
	}
	if membershipCount != 1 {
		t.Fatalf("user scope saw %d memberships, want 1", membershipCount)
	}
}

func TestStorePGRLSRestrictsGlobalTablesAndOutbox(t *testing.T) {
	env := itest.NewEnv(t)
	owner, err := postgres.Open(t.Context(), postgres.Config{URL: env.OwnerURL, MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := postgres.Migrate(t.Context(), owner, storepg.MigrationSpec()); err != nil {
		t.Fatal(err)
	}
	runtime, err := postgres.Open(t.Context(), postgres.Config{URL: env.RuntimeURL, MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	orgA, orgB := "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	restaurantA, restaurantASibling, restaurantB := "77777777-7777-4777-8777-777777777777", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", "88888888-8888-4888-8888-888888888888"
	if err := runtime.InSystemTx(t.Context(), "auth.test.seed", pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO worker_leases(name, holder, fence, expires_at) VALUES ('auth.test', 'test', 1, 'infinity')`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO outbox(id, exchange, routing_key, body, org_id, restaurant_id) VALUES
			('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'umir.auth', 'auth.restaurant.deleted', '{}', $1, $2),
			('abababab-abab-4bab-8bab-abababababab', 'umir.auth', 'auth.restaurant.deleted', '{}', $1, $5),
			('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'umir.auth', 'auth.restaurant.deleted', '{}', $3, $4),
			('cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'umir.tasks', 'auth.mail', '{}', NULL, NULL)`, orgA, restaurantA, orgB, restaurantB, restaurantASibling)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	tenantA := postgres.Scope{Actor: postgres.ActorTenant, OrgID: orgA, RestaurantID: restaurantA}
	var outboxCount, registryCount, leaseCount int
	if err := runtime.InScopedTx(t.Context(), tenantA, pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM outbox`).Scan(&outboxCount); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM registry_state`).Scan(&registryCount); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM worker_leases`).Scan(&leaseCount)
	}); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 || registryCount != 0 || leaseCount != 0 {
		t.Fatalf("tenant saw outbox=%d registry=%d leases=%d; want 1,0,0", outboxCount, registryCount, leaseCount)
	}
	if err := runtime.InScopedTx(t.Context(), tenantA, pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox(id, exchange, routing_key, body, org_id, restaurant_id) VALUES ('ffffffff-ffff-4fff-8fff-ffffffffffff', 'umir.auth', 'auth.restaurant.deleted', '{}', $1, $2)`, orgA, restaurantA)
		return err
	}); err != nil {
		t.Fatalf("tenant exact-scope insert: %v", err)
	}
	if err := runtime.InScopedTx(t.Context(), postgres.Scope{Actor: postgres.ActorAnonymous}, pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM outbox`).Scan(&outboxCount); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM registry_state`).Scan(&registryCount); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM worker_leases`).Scan(&leaseCount); err != nil {
			return err
		}
		if outboxCount != 0 {
			t.Fatalf("anonymous scope read %d outbox rows", outboxCount)
		}
		if registryCount != 0 || leaseCount != 0 {
			t.Fatalf("anonymous scope read registry=%d leases=%d", registryCount, leaseCount)
		}
		_, err := tx.Exec(ctx, `INSERT INTO outbox(id, exchange, routing_key, body) VALUES ('dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'umir.tasks', 'auth.mail', '{}')`)
		return err
	}); err != nil {
		t.Fatalf("anonymous mail-reference insert: %v", err)
	}
	if err := runtime.InScopedTx(t.Context(), postgres.Scope{Actor: postgres.ActorAnonymous}, pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox(id, exchange, routing_key, body) VALUES ('99999999-9999-4999-8999-999999999999', 'umir.auth', 'auth.restaurant.deleted', '{}')`)
		return err
	}); err == nil {
		t.Fatal("anonymous scope inserted a non-mail outbox row")
	}
	if err := runtime.InScopedTx(t.Context(), tenantA, pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox(id, exchange, routing_key, body, org_id, restaurant_id) VALUES ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'umir.auth', 'auth.restaurant.deleted', '{}', $1, $2)`, orgB, restaurantB)
		return err
	}); err == nil {
		t.Fatal("tenant inserted an outbox row for another organization")
	}
	if err := runtime.InScopedTx(t.Context(), tenantA, pgx.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO outbox(id, exchange, routing_key, body, org_id, restaurant_id) VALUES ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeea', 'umir.auth', 'auth.restaurant.deleted', '{}', $1, $2)`, orgA, restaurantASibling)
		return err
	}); err == nil {
		t.Fatal("tenant inserted an outbox row for another restaurant in its organization")
	}
	if err := runtime.InSystemTx(t.Context(), "auth.test.verify", pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM outbox WHERE id = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'`).Scan(&outboxCount)
	}); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 {
		t.Fatalf("system scope saw %d anonymous mail-reference rows, want 1", outboxCount)
	}
	if err := runtime.InSystemTx(t.Context(), "auth.test.verify", pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM registry_state`).Scan(&registryCount); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM worker_leases`).Scan(&leaseCount)
	}); err != nil {
		t.Fatal(err)
	}
	if registryCount != 1 || leaseCount != 1 {
		t.Fatalf("system saw registry=%d leases=%d; want 1,1", registryCount, leaseCount)
	}
}
