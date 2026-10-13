# Changelog

## Unreleased

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
