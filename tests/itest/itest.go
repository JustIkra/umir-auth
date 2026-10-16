// Package itest creates the isolated PostgreSQL databases (with a real owner
// role and a real runtime role) and RabbitMQ virtual hosts of the integration
// tests. Names are t_auth_<rand>; only objects created here are dropped. A
// missing UMIR_TEST_* variable fails the test: the suite never skips.
package itest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	prefix         = "t_auth_"
	cleanupTimeout = 30 * time.Second
)

func requireEnv(tb testing.TB, name string) string {
	tb.Helper()
	v := os.Getenv(name)
	if v == "" {
		tb.Fatalf("%s is not set: the integration tests need the durable test infrastructure "+
			"(eval \"$(bash scripts/durable-test-infra.sh env)\" in umir-factory); the suite never skips", name)
	}
	return v
}

func randHex(tb testing.TB) string {
	tb.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		tb.Fatalf("random: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// DatabaseURL is the administrative PostgreSQL URL.
func DatabaseURL(tb testing.TB) string { return requireEnv(tb, "UMIR_TEST_DATABASE_URL") }

// AMQPURL is the RabbitMQ URL of the default virtual host.
func AMQPURL(tb testing.TB) string { return requireEnv(tb, "UMIR_TEST_AMQP_URL") }

// Env is a temporary database with the roles of production (C8): the owner
// creates tables, the runtime role is not the owner and has NOBYPASSRLS.
type Env struct {
	AdminURL    string
	OwnerURL    string
	RuntimeURL  string
	OwnerRole   string
	RuntimeRole string
	Name        string
	password    string
	cluster     string
}

// NewEnv creates the database and both roles; everything is removed with the test.
func NewEnv(t testing.TB) *Env {
	t.Helper()
	ctx := t.Context()
	e := &Env{password: randHex(t) + randHex(t), cluster: DatabaseURL(t)}
	base := prefix + randHex(t)
	e.Name = base
	e.OwnerRole, e.RuntimeRole = base+"_owner", base+"_rt"
	conn, err := pgx.Connect(ctx, e.cluster)
	if err != nil {
		t.Fatalf("connect to the cluster: %v", err)
	}
	defer closeConn(conn)
	t.Cleanup(func() { e.dropAll(t) })
	for _, role := range []string{e.OwnerRole, e.RuntimeRole} {
		stmt := fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS", pgx.Identifier{role}.Sanitize(), e.password)
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("create role: %v", err)
		}
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{e.Name}.Sanitize()); err != nil {
		t.Fatalf("create database: %v", err)
	}
	e.AdminURL = withDB(t, e.cluster, e.Name)
	admin, err := pgx.Connect(ctx, e.AdminURL)
	if err != nil {
		t.Fatalf("connect to the temporary database: %v", err)
	}
	defer closeConn(admin)
	owner, rt := pgx.Identifier{e.OwnerRole}.Sanitize(), pgx.Identifier{e.RuntimeRole}.Sanitize()
	for _, stmt := range []string{
		fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s, %s", pgx.Identifier{e.Name}.Sanitize(), owner, rt),
		"REVOKE CREATE ON SCHEMA public FROM PUBLIC",
		fmt.Sprintf("GRANT USAGE, CREATE ON SCHEMA public TO %s", owner),
		fmt.Sprintf("GRANT USAGE ON SCHEMA public TO %s", rt),
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %s", owner, rt),
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %s", owner, rt),
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	e.OwnerURL = withUser(t, e.AdminURL, e.OwnerRole, e.password)
	e.RuntimeURL = withUser(t, e.AdminURL, e.RuntimeRole, e.password)
	return e
}

func (e *Env) dropAll(t testing.TB) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	conn, err := pgx.Connect(ctx, e.cluster)
	if err != nil {
		t.Errorf("connect to clean up: %v", err)
		return
	}
	defer closeConn(conn)
	if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{e.Name}.Sanitize()+" WITH (FORCE)"); err != nil {
		t.Errorf("drop database: %v", err)
	}
	for _, role := range []string{e.OwnerRole, e.RuntimeRole} {
		if _, err := conn.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Errorf("drop role: %v", err)
		}
	}
}

func closeConn(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Close(ctx); err != nil {
		return
	}
}

func withUser(t testing.TB, raw, user, password string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse database URL: %v", err)
	}
	u.User = url.UserPassword(user, password)
	return u.String()
}

func withDB(t testing.TB, raw, name string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse database URL: %v", err)
	}
	u.Path = "/" + name
	u.RawPath = ""
	return u.String()
}

// NewVHost creates a temporary virtual host t_auth_<rand> through the
// management API and returns the AMQP URL of it. It is deleted with the test.
// Topology (exchanges, queues) is not declared here; tests declare it with the
// reference Declare, as the mq-init job does.
func NewVHost(t testing.TB) string {
	t.Helper()
	raw := AMQPURL(t)
	u, err := url.Parse(raw)
	if err != nil || u.User == nil || u.User.Username() == "" {
		t.Fatalf("UMIR_TEST_AMQP_URL must be an amqp URL with a user name")
	}
	if u.Hostname() != "127.0.0.1" || u.Port() != "55672" {
		t.Fatalf("the management URL can only be derived for the local test broker")
	}
	user := u.User.Username()
	password, _ := u.User.Password()
	base := url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", "55673")}
	name := prefix + randHex(t)
	do := func(method string, segments []string, body any) int {
		var payload []byte
		if body != nil {
			var err error
			if payload, err = json.Marshal(body); err != nil {
				t.Fatalf("marshal: %v", err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, method, base.JoinPath(segments...).String(), bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("management request: %v", err)
		}
		req.SetBasicAuth(user, password)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("management %s: %v", method, err)
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Logf("close: %v", err)
			}
		}()
		return resp.StatusCode
	}
	t.Cleanup(func() {
		if !strings.HasPrefix(name, prefix) {
			return
		}
		if s := do(http.MethodDelete, []string{"api", "vhosts", name}, nil); s != http.StatusNoContent && s != http.StatusNotFound {
			t.Errorf("delete virtual host: status %d", s)
		}
	})
	if s := do(http.MethodPut, []string{"api", "vhosts", name}, struct{}{}); s != http.StatusCreated && s != http.StatusNoContent {
		t.Fatalf("create virtual host: status %d", s)
	}
	perms := map[string]string{"configure": ".*", "write": ".*", "read": ".*"}
	if s := do(http.MethodPut, []string{"api", "permissions", name, user}, perms); s != http.StatusCreated && s != http.StatusNoContent {
		t.Fatalf("grant permissions: status %d", s)
	}
	u.Path = "/" + name
	u.RawPath = ""
	return u.String()
}
