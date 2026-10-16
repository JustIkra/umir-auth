# Changelog

## Unreleased

- Add the durable-stack foundation (wave 2): reference adapters `postgres`, `rabbitmq` and `relay` copied from `umir-factory reference/durable`, pgx and amqp091 dependencies with architecture rules, the `make integration` target and the `tests/itest` helper that creates a temporary database with owner and runtime roles and a temporary RabbitMQ virtual host.

- Add the first Postgres migration for Auth's normalized tables, constraints, indexes, reference metadata and forced RLS policies. Integration checks use isolated owner/runtime roles, assert the runtime cannot own tables or bypass RLS, verify generation reads through an explicit system transaction, and verify tenant context does not leak across a reused pool connection.

- Add the initial consumer-owned `application.Store` transaction and user/session/command/organization/restaurant/membership/invitation/challenge/mail-job/budget/outbox/lifecycle/registry repository contracts with a test-only memory implementation. System transactions require a reason. Contract tests cover rollback, user visibility, normalized email-login uniqueness, session user references and digest uniqueness, command-key uniqueness, restaurant organization references, membership assignment scope, pending invitation uniqueness, single-use proof consumption, fenced mail-job claims, rolling budget cutoffs, outbox transaction atomicity, lifecycle copy isolation, and bounded keyset registry pages; the runtime is not wired to this seam yet.

- Enforce tenant scope in memory Store repositories. Make `registry_state` and `worker_leases` system-only under RLS. Give system transactions global outbox access; tenant transactions can read and insert only exact organization/restaurant rows, and anonymous transactions can only insert unscoped `umir.tasks` / `auth.mail` references. Use deterministic UUIDs in shared Store contract fixtures. Relay and worker activation remains blocked while shared global methods use unscoped transactions.

- Apply the Auth organization scope to memory mail-job reads, inserts, claims and finishes. User-scoped transactions cannot read or mutate organization mail jobs.

- Read the log `instance_id` from `AUTH_INSTANCE_ID` (C19); a random identifier is only the fallback when it is unset.

- Retry the dummy verifier hash after a failure instead of caching the error until restart.

- Stop the process when a request leaves Accounts in recovery (unknown update outcome): `Accounts.RecoveryPending` makes the worker supervisor treat the next worker error as unrecoverable, so the container restarts instead of staying alive and answering 503.

- Document the OTP threat model and pin the OTP budgets (ten wrong codes per address per hour, three issues per address per ten minutes shared with invitations) and the signer's clock-step and zero-`iat`-leeway behaviour with tests. No behaviour change.

- Treat invitation addresses that differ only in case as one pending invitation per organization.

- Treat an SMTP dial failure as a retryable delivery failure instead of an unknown outcome; failures after the connection is established stay unknown.

- Verify an unknown login against a dummy verifier made by the selected hasher instead of the first account's stored verifier, so its cost no longer depends on that account's parameters.

- Hash passwords outside the Accounts mutex for invited-user completion and password reset, as registration already did: the hash runs behind the bounded password gate after a read-only precheck, an exact repeat needs no hash, and the command re-checks proof, credentials and identity at commit time.

- Supervise background workers: unrecoverable errors (`ErrRecoveryRequired`, `ErrUpdateOutcomeUnknown`, `ErrClosed`) stop `Serve` with the error so the process exits and is restarted; other errors back off 1 to 30 seconds and retry. `Ready` no longer fails because of a worker, and the JWKS route is gated only by signing readiness. Add structured JSON logging (observability section 3 fields) with `auth.worker.degraded|recovered|fatal` and `auth.mail.attempt` events that carry no codes, addresses or tokens. `MailDelivery` gains `Attempt` and `Age`.

- Coalesce peer Status calls: concurrent callers share one call per service, services are asked in parallel, and a revision change during the call reloads the aggregate and re-evaluates against the same answers instead of asking again. A reconciliation pass asks each service once, records the readiness of one restaurant in one commit and no longer re-checks status after every registration (the final observation does).

- Refuse login passwords over 32 code points or with invalid UTF-8 before the failure throttle, so they no longer fill its 4096 counters or start a cooldown. The response is still InvalidCredentials.

- Drop the stateful preauth issuance table and its 1024-entry cap and mutex; preauth tokens stay self-contained (HMAC and time), and the per-client issue limit belongs to Gateway.

- Stop cloning the whole aggregate for readiness and for idle mail-worker ticks: `ValidatedAggregate.Inspect` gives read-only access, and the sweep and the claim only copy the state when they have work. Session and command-result retention are unchanged.

- Replay stored verify and complete results of an enrollment command even after its challenge was purged, instead of answering an unknown challenge.

- Purge expired email challenges and their OTP jobs in the outbox sweep (one hour after expiry or the last wrong attempt, 24 hours after proof expiry; never while a job is queued, sending or unknown) and replace their begin/resend command records with tombstones. A repeat of such a command answers the existing 409 CommandConflict with outcome unknown and issues no challenge. Keeps the 4096 cap as a defensive limit that password-reset floods no longer reach. The file store now takes the Auth clock to validate removals.

- Resolve registration review issues #5–7: separate mail budget, persisted per-address wrong-code budget, creator organization quota/rate, neutral password reset, default-disabled email-code login, disabled outbox suppression, case-insensitive address ownership, bounded command IDs and registration hashing outside the aggregate lock. Preserve stored identities and replay fingerprints. Document v3 backup-only rollback and the deferred challenge-storage cap.

- Add opt-in public registration through existing email challenges, neutral occupied-address responses, atomic account/session completion and schema-v3 forward migration. Preserve challenge limits, replay results and password login.

- Restore Gateway SSE access checks for the existing `live` operation without adding a bearer-token policy or changing session activity. Retain current scope, role, revocation and runtime checks.

- Add FIN1 supply authorization through existing stock.read and replace the recommendation token's menu-evaluation grant with narrow consumer.recommendations.read. Preserve the dual-service audience, role checks and restaurant boundaries. Consumers must use the composed FIN1 profile.

- Move peer status IO outside the Auth mutex and revalidate authority revisions, sessions and registration settings before using observations. Preserve admission cutoff during concurrent logout, expiry and scope deletion.
- Recover interrupted mail attempts without restarting Auth, retaining durable unknown/retry identities. Keep authority failures fail-closed and stop reconciliation on storage errors.
- Resolve the short Unix-socket test root portably on Darwin and Linux without weakening socket or malformed-response checks.

- Add pinned Auth CI with complete Go quality/race gates, dependency checks and a real production-image startup/readiness smoke. Publish exact main-source production images to GHCR only after those gates pass; branch and pull-request checks do not publish.
- Isolate password-login cooldowns by exact Login, bound retained counters to 4096 without evicting live attempts, and recheck cooldown after verification. Preserve the global verification queue limits.
- Read one optional LF/CRLF from text password and SMTP credential files. Preserve spaces, raw key bytes and private-file admission. Report safe startup stages while retaining wrapped diagnostic causes.

- Add a separate closed UA1 control wire/CLI in serve-ui-ua1, exact actual
  business-body/actor observation, non-evicting request replay and strict client
  validation. Route the one mail worker through an additive bootstrap processor
  port while preserving ordinary Serve and operational RPC signatures.
- Add a separate test-only typed UA1 storage/mail control library with bounded
  physical lifetimes, cancellation and identity-preserving observations. Exercise
  real committed/unknown results, durable claim barriers and owned-process crash
  recovery. Keep wire, server worker and runner integration explicitly pending.
- Add a separate test-only UA1 job discovery endpoint for actual invitation-link
  and OTP identities, durable allocation, deadlines and synthetic Message-ID.
  Bind the reviewed supplement and current owner identity; reject mixed kinds,
  foreign scope and stale clocks. Preserve operational RPC and production routes.
- Correct the owner-profile README to describe the existing eight-hour legacy-v2
  fixture while retaining the rejected four-hour evidence and pending profile gate.

- Add UA1 Admin member/invitation snapshot reads and atomic invitation-link jobs.
  Preserve OTP routes, legacy command replay and original invitation deadlines.
- Upgrade validated Auth storage v1 to v2 with explicit command profiles, typed
  mail purposes and retained identities. Reject malformed linkage and rollback.
- Add trusted-origin configuration, shared resend cooldown and issue budgets,
  stable SMTP identities and bounded unknown retry/restart handling.

- Generate valid eight-hour nonpersistent session deadlines in the test-only
  legacy-v2 profile. Preserve migration guards and exact source deadline checks;
  the former four-hour fixture was rejected before import.

- Preserve password cooldown sessionRevoked and consistent Retry-After/delay
  fields at the private HTTP boundary, including wrapped application errors.

- Reject partial bootstrap authority before reseeding; validate private secret creation paths and required original-profile metadata on every start.
- Separate mail transport deadlines from durable outcome recording; retain healthy retry/readiness and stable jobs through timeout and restart.
- Bind test-only faults to all frozen command-bearing Auth routes and reject unsupported selectors before arming.

- Add the private Auth HTTP process, explicit real Argon2id bootstrap, retained owner secrets and single-writer shutdown.
- Compose real lifecycle HTTP transport and minimum Ed25519 service/anonymous credentials; separate Serving discovery from lifecycle and fixture credentials.
- Add test-owned authenticated Unix controls, injected clocks, durable job discovery, bounded fault decorators and production/fixture container builds.
- Preserve original settings and command results across private wire replay; document stopped-writer migration and rollback.

- Deny business access and JWT issuance without a runtime provider and current reconciled readiness, including migrated scopes.
- Keep earlier Restaurant cleanup independent of later Organization cascades; bind Organization-wide dependencies to the exact accepted operation UUID.

- Add atomic Organization/Restaurant creation with creator Admin authority and immutable encrypted lifecycle acceptance.
- Add current-epoch registration/reconciliation, complete bounded registry, cancellable bounded retry and fresh peer readiness admission.
- Add durable cascade cutoff/tombstones, scoped invitation/mail suppression, initiating-User deletion replay and separate cleanup progress across restart.
- Preserve lifecycle versions and intent purpose; accept frozen opaque long command identities without the old 128-character lifecycle cap.

- Add real Auth-only Ed25519 user-token signing, public JWKS, exact operation audiences/permissions and injected-clock key overlap with restart restoration.
- Add bounded strict user-token validation and fresh current-session/member/Restaurant authorization.
- Add explicit packaged IANA catalog and durable Admin settings updates with monotonic versions, concurrent refusal and exact encrypted replay after restart.
- Preserve existing expiry instants and captured token settings across zone changes.

- Preserve the existing verified delivery address and queued login/reset mail when accepting an equivalent invitation address.
- Accept eligible administrative resends in the final invitation minute without extending its fixed expiry.

- Added durable invitation-bound enrollment, OTP verification/recoverable proof, email login/reset and exact command-to-mail-job edges.
- Transferred the approved registration mail and verified SMTP transport from Feedback; added injected-clock worker recovery, stable ambiguous retries and terminal payload scrubbing.
- Added test-only synthetic delivery correlation and an offline UID-65532 container smoke.

- Add current-authority Organization membership administration and per-Restaurant Warehouse/Waiter capability unions, including scoped Admin and human writeoff boundaries.
- Protect the last active Admin with atomic final-state checks and fresh authority after aggregate revision conflicts.
- Persist exact scoped membership/assignment commands and encrypted original results atomically; preserve global sessions and unrelated scopes.
- Enforce membership/assignment identity and monotonic replacement versions.

- Preserve escaped NUL, CR, LF and exact Unicode command IDs in durable login/profile/password results and restart replay. Reject the reserved case-sensitive `expiration/` prefix in durable records; retain malformed UTF-8 refusal and all other text validation.
- Preserve wire-valid command IDs longer than 128 characters in durable login/profile/password retry results.
- Add global User/device sessions, durable logout/password revocation, bounded verification and preserved credential/session policies.
- Add command-aware encrypted login/profile/password results with exact retry and fail-closed recovery.
- Add strict explicit legacy account/session migration, original CSRF compatibility and a rollback guard that rejects changed authority.
- Prevent credential-version rollback and compare session eviction timestamps as instants.
- Preserve source Argon2id costs and NFC display-name validation with explicit pinned vendor boundaries.

- Require durable tombstones at deletion acceptance and preserve them through restart and cleanup completion.
- Preserve confirmed initialization success when cancellation arrives after rename.
- Reject nonregular authority files without blocking startup or retaining the writer lock.

- Add the Auth module and pinned Go quality policy for backend contract 2.0.0-draft.2.
- Add a typed, validated identity aggregate with isolated snapshots and preserved durable outcomes.
- Add a lifetime single-writer JSON store with atomic file replacement and explicit committed, not_committed and unknown outcomes.
- Add synthetic tests for corruption, concurrency, restart recovery, writer exclusion and filesystem failure classification.
