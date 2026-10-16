-- umir:include storage_meta
-- umir:include worker_leases
-- umir:include outbox

CREATE SEQUENCE auth_revision_seq AS bigint;

CREATE TABLE users (
    user_id uuid PRIMARY KEY,
    login text NOT NULL,
    login_key text NOT NULL UNIQUE,
    email text,
    email_key text UNIQUE,
    display_name text NOT NULL,
    credential_version bigint NOT NULL CHECK (credential_version > 0),
    verifier text NOT NULL
);

CREATE TABLE sessions (
    session_id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(user_id),
    digest text NOT NULL UNIQUE,
    csrf_digest text NOT NULL,
    session_version bigint NOT NULL CHECK (session_version > 0),
    credential_version bigint NOT NULL CHECK (credential_version > 0),
    created_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    remember_me boolean NOT NULL,
    revoked_at timestamptz
);
CREATE INDEX sessions_user_live_idx ON sessions(user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_absolute_expiry_idx ON sessions(absolute_expires_at);

CREATE TABLE organizations (
    org_id uuid PRIMARY KEY,
    name text NOT NULL,
    time_zone text NOT NULL,
    settings_version bigint NOT NULL CHECK (settings_version > 0),
    lifecycle text NOT NULL,
    lifecycle_version bigint NOT NULL CHECK (lifecycle_version > 0),
    created_by uuid NOT NULL REFERENCES users(user_id),
    created_at timestamptz NOT NULL
);
CREATE INDEX organizations_creator_idx ON organizations(created_by);

CREATE TABLE restaurants (
    restaurant_id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(org_id),
    name text NOT NULL,
    lifecycle text NOT NULL,
    lifecycle_version bigint NOT NULL CHECK (lifecycle_version > 0),
    intent_id uuid,
    registry_rev bigint NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX restaurants_id_org_unique ON restaurants(restaurant_id, org_id);
CREATE INDEX restaurants_org_idx ON restaurants(org_id);
CREATE INDEX restaurants_live_lifecycle_idx ON restaurants(lifecycle) WHERE lifecycle <> 'deleted';
CREATE INDEX restaurants_registry_rev_idx ON restaurants(registry_rev);

CREATE TABLE tombstones (
    entity_id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('organization', 'restaurant')),
    org_id uuid NOT NULL,
    lifecycle_version bigint NOT NULL CHECK (lifecycle_version > 0),
    registry_rev bigint NOT NULL,
    deleted_at timestamptz NOT NULL
);

CREATE TABLE memberships (
    membership_id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(user_id),
    org_id uuid NOT NULL REFERENCES organizations(org_id),
    org_admin boolean NOT NULL DEFAULT false,
    state text NOT NULL,
    membership_version bigint NOT NULL CHECK (membership_version > 0),
    UNIQUE (membership_id, org_id),
    UNIQUE (user_id, org_id)
);
CREATE INDEX memberships_admin_idx ON memberships(org_id) WHERE org_admin AND state = 'active';

CREATE TABLE assignments (
    assignment_id uuid PRIMARY KEY,
    membership_id uuid NOT NULL,
    org_id uuid NOT NULL,
    restaurant_id uuid NOT NULL,
    assignment_version bigint NOT NULL CHECK (assignment_version > 0),
    roles text[] NOT NULL CHECK (cardinality(roles) BETWEEN 1 AND 2),
    UNIQUE (membership_id, restaurant_id),
    FOREIGN KEY (membership_id, org_id) REFERENCES memberships(membership_id, org_id),
    FOREIGN KEY (restaurant_id, org_id) REFERENCES restaurants(restaurant_id, org_id),
    CHECK (roles <@ ARRAY['Warehouse', 'Waiter']::text[])
);

CREATE TABLE invitations (
    invitation_id uuid PRIMARY KEY,
    org_id uuid NOT NULL REFERENCES organizations(org_id),
    email text NOT NULL,
    email_key text NOT NULL,
    expires_at timestamptz NOT NULL,
    resend_available_at timestamptz NOT NULL,
    state text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    UNIQUE (invitation_id, org_id)
);
CREATE UNIQUE INDEX invitations_pending_email_unique ON invitations(org_id, email_key) WHERE state = 'pending';

CREATE TABLE invitation_assignments (
    invitation_id uuid NOT NULL,
    org_id uuid NOT NULL REFERENCES organizations(org_id),
    restaurant_id uuid NOT NULL REFERENCES restaurants(restaurant_id),
    roles text[] NOT NULL CHECK (cardinality(roles) BETWEEN 1 AND 2),
    PRIMARY KEY (invitation_id, restaurant_id),
    FOREIGN KEY (invitation_id, org_id) REFERENCES invitations(invitation_id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (restaurant_id, org_id) REFERENCES restaurants(restaurant_id, org_id),
    CHECK (roles <@ ARRAY['Warehouse', 'Waiter']::text[])
);

CREATE TABLE challenges (
    challenge_id uuid PRIMARY KEY,
    purpose text NOT NULL,
    state text NOT NULL,
    invitation_id uuid REFERENCES invitations(invitation_id),
    user_id uuid REFERENCES users(user_id),
    credential_version bigint,
    address_digest text NOT NULL,
    registration_email text,
    initiator_digest text NOT NULL,
    code_digest text NOT NULL,
    encrypted_code text NOT NULL,
    proof_digest text,
    encrypted_proof text,
    proof_expires_at timestamptz,
    expires_at timestamptz NOT NULL,
    resend_available_at timestamptz NOT NULL,
    issue_count integer NOT NULL CHECK (issue_count >= 0),
    wrong_attempts integer NOT NULL CHECK (wrong_attempts >= 0)
);
CREATE INDEX challenges_state_expiry_idx ON challenges(state, expires_at);
CREATE INDEX challenges_address_idx ON challenges(address_digest);

CREATE TABLE challenge_tombstones (
    challenge_id uuid PRIMARY KEY,
    consumed_at timestamptz NOT NULL,
    purge_after timestamptz NOT NULL
);

CREATE TABLE wrong_code_attempts (
    address_digest text NOT NULL,
    attempted_at timestamptz NOT NULL,
    challenge_id uuid NOT NULL,
    PRIMARY KEY (address_digest, attempted_at, challenge_id)
);
CREATE INDEX wrong_code_attempts_window_idx ON wrong_code_attempts(address_digest, attempted_at);

CREATE TABLE code_issuances (
    class text NOT NULL,
    address_digest text NOT NULL,
    issued_at timestamptz NOT NULL,
    challenge_id uuid NOT NULL,
    PRIMARY KEY (class, address_digest, issued_at, challenge_id)
);
CREATE INDEX code_issuances_global_window_idx ON code_issuances(class, issued_at);
CREATE INDEX code_issuances_address_window_idx ON code_issuances(address_digest, issued_at);

CREATE TABLE budget_events (
    kind text NOT NULL,
    key_digest text NOT NULL,
    at timestamptz NOT NULL,
    PRIMARY KEY (kind, key_digest, at)
);
CREATE INDEX budget_events_window_idx ON budget_events(kind, key_digest, at);

CREATE TABLE budget_cooldowns (
    kind text NOT NULL,
    key_digest text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (kind, key_digest)
);

CREATE TABLE commands (
    actor_id uuid NOT NULL,
    preauth_digest text NOT NULL,
    operation_id text NOT NULL,
    org_id uuid NOT NULL,
    restaurant_id uuid NOT NULL,
    command_id text NOT NULL,
    fingerprint text NOT NULL,
    http_status integer NOT NULL,
    response_schema text NOT NULL,
    key_id text,
    encrypted_response text,
    aggregate_revision bigint NOT NULL,
    job_ids uuid[] NOT NULL DEFAULT '{}',
    session_id uuid REFERENCES sessions(session_id) ON DELETE SET NULL,
    recorded_at timestamptz NOT NULL,
    result_purge_at timestamptz,
    row_purge_at timestamptz,
    PRIMARY KEY (actor_id, preauth_digest, operation_id, org_id, restaurant_id, command_id),
    CHECK ((actor_id = '00000000-0000-0000-0000-000000000000'::uuid) <> (preauth_digest = ''))
);
CREATE INDEX commands_actor_operation_idx ON commands(actor_id, operation_id, recorded_at);
CREATE INDEX commands_operation_idx ON commands(operation_id, recorded_at);

CREATE TABLE mail_jobs (
    job_id uuid PRIMARY KEY,
    purpose text NOT NULL,
    challenge_id uuid REFERENCES challenges(challenge_id) ON DELETE SET NULL,
    invitation_id uuid REFERENCES invitations(invitation_id),
    org_id uuid REFERENCES organizations(org_id),
    enqueue_order bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    state text NOT NULL,
    encrypted_payload text,
    accepted_at timestamptz NOT NULL,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    last_attempt_at timestamptz,
    next_attempt_at timestamptz,
    lease_owner text,
    lease_until timestamptz,
    purge_after timestamptz
);
CREATE INDEX mail_jobs_due_idx ON mail_jobs(next_attempt_at) WHERE state IN ('queued', 'unknown');
CREATE INDEX mail_jobs_lease_idx ON mail_jobs(lease_until) WHERE state = 'sending';

CREATE TABLE lifecycle_intents (
    operation_id uuid PRIMARY KEY,
    command_id text NOT NULL,
    actor_id uuid,
    org_id uuid NOT NULL,
    lifecycle text NOT NULL,
    lifecycle_version bigint NOT NULL,
    cleanup text NOT NULL,
    UNIQUE (operation_id, org_id)
);
CREATE TABLE lifecycle_restaurants (
    operation_id uuid NOT NULL,
    org_id uuid NOT NULL REFERENCES organizations(org_id),
    restaurant_id uuid NOT NULL REFERENCES restaurants(restaurant_id),
    PRIMARY KEY (operation_id, restaurant_id),
    FOREIGN KEY (operation_id, org_id) REFERENCES lifecycle_intents(operation_id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (restaurant_id, org_id) REFERENCES restaurants(restaurant_id, org_id)
);
CREATE TABLE peer_readiness (
    operation_id uuid NOT NULL,
    org_id uuid NOT NULL REFERENCES organizations(org_id),
    restaurant_id uuid NOT NULL REFERENCES restaurants(restaurant_id),
    service text NOT NULL CHECK (service IN ('warehouse', 'serving')),
    epoch uuid,
    state text NOT NULL,
    lifecycle_version bigint NOT NULL,
    PRIMARY KEY (operation_id, restaurant_id, service),
    FOREIGN KEY (operation_id, org_id) REFERENCES lifecycle_intents(operation_id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (restaurant_id, org_id) REFERENCES restaurants(restaurant_id, org_id)
);
CREATE INDEX peer_readiness_work_idx ON peer_readiness(service, epoch, state);

CREATE TABLE registry_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision bigint NOT NULL CHECK (revision > 0)
);
INSERT INTO registry_state(singleton, revision) VALUES (true, 1);

DO $$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'users', 'sessions', 'organizations', 'restaurants', 'tombstones',
        'memberships', 'assignments', 'invitations', 'invitation_assignments',
        'challenges', 'challenge_tombstones', 'wrong_code_attempts', 'code_issuances',
        'budget_events', 'budget_cooldowns', 'commands', 'mail_jobs',
        'lifecycle_intents', 'lifecycle_restaurants', 'peer_readiness', 'registry_state',
        'storage_meta', 'worker_leases', 'outbox'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('CREATE POLICY %I ON %I USING (NULLIF(current_setting(''umir.actor'', true), '''') IN (''tenant'', ''user'', ''anonymous'', ''system'')) WITH CHECK (NULLIF(current_setting(''umir.actor'', true), '''') IN (''tenant'', ''user'', ''anonymous'', ''system''))', table_name || '_actor', table_name);
    END LOOP;

    FOREACH table_name IN ARRAY ARRAY[
        'organizations', 'restaurants', 'tombstones', 'memberships', 'assignments',
        'invitations', 'invitation_assignments', 'mail_jobs', 'lifecycle_intents',
        'lifecycle_restaurants', 'peer_readiness'
    ] LOOP
        EXECUTE format('DROP POLICY %I ON %I', table_name || '_actor', table_name);
        EXECUTE format('CREATE POLICY %I ON %I USING (NULLIF(current_setting(''umir.actor'', true), '''') = ''system'' OR (NULLIF(current_setting(''umir.actor'', true), '''') = ''tenant'' AND org_id = NULLIF(current_setting(''umir.org_id'', true), '''')::uuid)) WITH CHECK (NULLIF(current_setting(''umir.actor'', true), '''') = ''system'' OR (NULLIF(current_setting(''umir.actor'', true), '''') = ''tenant'' AND org_id = NULLIF(current_setting(''umir.org_id'', true), '''')::uuid))', table_name || '_org_scope', table_name);
    END LOOP;
END $$;

DROP POLICY memberships_org_scope ON memberships;
CREATE POLICY memberships_scope ON memberships
    USING (
        NULLIF(current_setting('umir.actor', true), '') = 'system'
        OR (NULLIF(current_setting('umir.actor', true), '') = 'tenant' AND org_id = NULLIF(current_setting('umir.org_id', true), '')::uuid)
        OR (NULLIF(current_setting('umir.actor', true), '') = 'user' AND user_id = NULLIF(current_setting('umir.user_id', true), '')::uuid)
    )
    WITH CHECK (
        NULLIF(current_setting('umir.actor', true), '') = 'system'
        OR (NULLIF(current_setting('umir.actor', true), '') = 'tenant' AND org_id = NULLIF(current_setting('umir.org_id', true), '')::uuid)
        OR (NULLIF(current_setting('umir.actor', true), '') = 'user' AND user_id = NULLIF(current_setting('umir.user_id', true), '')::uuid)
    );
