# Umir Auth

Auth owns the durable identity aggregate. The module identity is `github.com/JustIkra/umir-auth`. The required Go version is 1.26.9. The module provides the private Auth process, durable accounts and sessions, scoped membership, enrollment mail, Ed25519 tokens, organization settings and lifecycle reconciliation. Feedback and real service assembly remain separate owners.

The implementation consumes Factory contract `2.0.0-draft.2`, approved by C2 with content SHA-256 `733e102ff0b4f52bb49d435716f9f1720642c8fad3a8a5d0685847071950e9e6`. Storage field names inside records are private to Auth. The module is unreleased and has no selected assembly pin. Production and fixture images keep separate revision identities.

The [FIN1 supplement](https://github.com/JustIkra/umir-factory/blob/5a3ab9cb7a2a48801f07024d5b5c205577211e75/docs/completion-api-amendment.md) adds operation `supplySuggestions`, authorized by the existing `stock.read` capability with only the Warehouse audience. The `recommendations` token keeps the Serving and Warehouse audiences and now contains exactly `recommendations.read` and `consumer.recommendations.read`. The narrow permission replaces the predecessor `consumer.menu.evaluate` grant for this operation. Menu and stop-list policies keep their existing menu permission. Role membership and restaurant scope do not change; Waiter alone cannot request supply suggestions or arbitrary stock/history reads. Deploy consumers of the composed FIN1 profile together. Original C2/UA1 schemas and evidence remain separate.

## Architecture

Private Auth error responses preserve password cooldown revocation state. A
PasswordChangeRateLimited response includes sessionRevoked even when false. Its
positive retry delay is rounded up to seconds and returned in both details and
Retry-After. Gateway can then clear a durably revoked session cookie and preserve
a session that only has an active cooldown. Login throttling also preserves its
retry delay. An unknown storage outcome does not claim a committed revocation.

`internal/domain` contains typed identity records and aggregate validation. Domain code receives instants and does not read the clock, environment or filesystem. `internal/application` defines the consumer-owned repository and mechanism ports, commit outcomes, account/session and scoped membership use cases, and explicit legacy migration. `internal/adapters/jsonstore` implements that port. Adapter dependencies point toward application and domain. Fixtures and fault injection are in tests.

The current aggregate has `schemaVersion: 2` and a canonical positive int64 decimal `aggregateRevision` string. Its complete collections are users, organizations, restaurants, memberships, sessions, invitations, challenges, mailJobs, idempotency, lifecycleIntents and tombstones. Empty collections are arrays. Missing collections and null values are invalid.

Validation checks canonical UUIDv4 identities, unique identities and references, restaurant assignment scope, role sets, active organization administration, versions, session digests and deadlines, challenge bindings, job references, command namespaces, peer associations and durable deletion markers. The adapter also validates IANA zones with packaged timezone data. The application implements password/session admission, scoped membership management and current-state restaurant capabilities. The application also implements fresh user-token authorization and durable organization settings. A6 implements durable lifecycle intents, bounded reconciliation and current peer epoch admission. A7 supplies the authenticated private HTTP dispatch.

`ValidatedAggregate` holds a private snapshot. Validation and `Snapshot()` copy all collection and nested slice data. Callers cannot mutate stored authority through a retained input or returned slice. `Commit` accepts the complete next aggregate and its expected previous revision. Exactly one concurrent commit for that revision can succeed. The next revision must equal the previous revision plus one without overflow. Replacement checks preserve membership and assignment identity, require monotonic versions and version increments for changed membership/assignment content, and preserve scope identities, tombstones, completed command results, stable mail/lifecycle references and existing session identity and absolute instants. Idempotency responses and delivery material are encrypted and authenticated by the real result and challenge-secret adapters.

## Durable store lifecycle

The target parent directory must exist on a durable filesystem that supports advisory flock, atomic rename, file fsync and directory fsync. Darwin and Linux are supported. Data and lock files must be regular, private `0600` files with one hard link. Data and lock symlinks are rejected. Parent directory aliases resolve to the same lock path. Other processes must obey this lock protocol. Only Auth may access the durable directory.

1. Use `jsonstore.Initialize(ctx, path, validatedInitialAggregate)` for explicit first provisioning.
2. Use `jsonstore.Open(ctx, path)` for every subsequent startup.
3. Keep the returned store open for the entire runtime lifetime.
4. Stop consumers before calling `Close()` at shutdown.

Initialization refuses to replace an existing file. Opening a missing, corrupt, unknown-version or invalid aggregate fails closed. Startup also rejects duplicate or unknown JSON keys, missing required record fields, nulls, malformed UTF-8 or Unicode escapes, case aliases and trailing JSON. Startup errors release the writer lock. The sidecar `.lock` inode remains after shutdown; do not remove it while a writer can run.

Startup opens the authority with nonblocking and no-follow flags, then checks the opened descriptor before reading. A FIFO is rejected without waiting for a writer. A canceled startup fails before opening the authority. Initialization returns a usable store after a confirmed durable replacement, even if cancellation arrived after rename. An ambiguous replacement still requires recovery.

Accepted deletion requires durable tombstones while entities are `deleting` and cleanup is pending. The same tombstones remain when cleanup completes and entities become `deleted`. Active or registering entities cannot carry these markers. Restart preserves the accepted deletion, its cleanup intent and unrelated global identity/session data.

Each commit writes a private temporary file in the same directory, checks the complete write, syncs and closes it, renames it to the aggregate path, then syncs and closes the directory. Cancellation is honored before rename. After rename starts, persistence finishes independently of cancellation.

- `committed` returns the confirmed new aggregate revision after directory sync.
- `not_committed` preserves the previous revision when validation, revision comparison or pre-replacement IO fails.
- `unknown` returns no confirmed revision when rename or subsequent directory operations fail. The store blocks all loads and further commits until closed and reopened. In-memory state is never published from an ambiguous replacement. Recovery validates the actual stored aggregate before it can serve callers.

Errors expose a generic classification. Wrapped causes remain available through `errors.Is` and `errors.As`; do not log their raw values or aggregate content. Auth signing keys are external secrets and are not stored in this aggregate. No public schema exposes storage secrets.

## Memberships and scoped administration

A membership binds one global User to one Organization. Its optional Admin role grants management only in that active Organization. Restaurant assignments contain Warehouse, Waiter or both. Warehouse includes writeoff.confirm. Waiter alone cannot confirm writeoffs. The working-role union is calculated independently for the explicitly selected Restaurant. Admin has both working roles in each ready Restaurant of its own active Organization, plus the frozen organization and Feedback management capabilities. No user role grants runtime, scheduler, anonymous or service-consumer capabilities.

Use Accounts.RestaurantAccess with a live global session and an explicit Restaurant ID for a passive current-state capability query. It rejects missing, registering, deleting, deleted and unauthorized scopes. It does not issue a JWT or extend a session. It requires AccountOptions.Runtimes and a current lifecycle intent with every saved readiness acknowledgment matching a fresh healthy peer epoch. Missing runtime providers and unreconciled migrated scopes return ErrRuntimeNotReady. The process configures the real authenticated runtime port for scoped admission. Accounts.Memberships returns isolated current membership records only to a current own-Organization Admin.

UpdateMembership, RevokeMembership and RevokeAssignment require a live session, its bound CSRF token, the explicit Organization and membership IDs, and a mandatory commandID. Updates use the expectedMembershipVersion. Assignment revocation also requires its immutable assignmentID and expectedAssignmentVersion. Existing assignments retain their ID; changed role sets increase their assignment version. New assignments receive a new UUID. Every accepted update or scoped revoke increases membershipVersion. A stale version cannot remove a newer replacement. Updates cannot reactivate a revoked membership or grant access to a foreign or deleted Restaurant. Duplicate Restaurant assignments and unknown/duplicate roles are refused.

Each command loads current durable authority and checks current Admin access before replay or mutation. It validates the proposed final membership set before committing. An active Organization must retain an active Admin. The last removal or self-demotion returns ErrLastAdmin without changing authority, sessions, mail or command evidence. Aggregate compare-and-swap makes this check atomic. A competing application instance retries a definite revision conflict by loading and checking current authority again. Revocation preserves global Users, credentials, sessions, unrelated Organization memberships and neighboring Restaurant assignments.

The durable namespace is actor User ID, public operation ID (updateMembership, revokeMembership or revokeAssignment), Organization ID and exact commandID. A versioned SHA-256 fingerprint includes that actor, Organization, target membership, optional assignment and the exact typed request input. It excludes the session token, CSRF token, current time and settings. Command IDs preserve Unicode, escaped controls and whitespace; the case-sensitive expiration/ prefix is reserved. A changed request or target under the same key returns ErrCommandConflict. Replay precedes expected-version checks, but still requires the original actor's current Admin authority and a live session. Self-demotion or revocation denies subsequent administrative replay without changing the retained outcome.

The membership change and encrypted original Membership or DurableResult are saved in one aggregate replacement. Revoke results use the frozen committed outcome, aggregateRevision, resourceID and an empty mailJobs array. A definite persistence failure leaves authority unchanged. An ambiguous commit returns ErrUpdateOutcomeUnknown and blocks fresh authorization until recovery. Reopening the store with the same ResultSecrets key recovers the original result without another mutation. Invitation acceptance, OTP, mail delivery, JWT signing, settings changes and lifecycle reconciliation are outside A3.

## Credentials and sessions

Construct `application.Accounts` with a repository, password hasher, clock, UUID source and unpredictable token source. Construction checks every stored PHC verifier. Auth does not copy sessions into restaurant scopes. Each operation loads current durable authority. Password verification runs outside the application mutex; admission rechecks the credential version and verifier before committing.

Passwords retain 8–32 Unicode code points without normalization, trimming or truncation. Oversized currentPassword is rejected before verification or wrong-password counting, after newPassword validation and an existing cooldown check. Display names retain Unicode trimming, NFC and the 2–80 code-point policy. The password adapter preserves the Gateway baseline: Argon2id v19; new hashes use 64 MiB, two iterations and parallelism one. Existing compliant PHC costs remain unchanged. Salt/key decoding and configured cost bounds fail closed.

Ordinary sessions have a 30-minute idle deadline capped by the immutable eight-hour absolute deadline. Remembered sessions have one immutable 30-day deadline. Background checks and session CSRF reads never extend expiry. Foreground activity commits an idle extension before returning authorization. Current/me can return the previous persisted deadline after a definite extension failure. Ambiguous outcomes block every authorization and new login until store reopening. A result is successful only after a confirmed complete aggregate replacement.

The process permits two concurrent credential verifications and eight queued logins. Five failed logins in a rolling minute impose a one-minute cooldown for that exact case-sensitive stored Login value. Unknown logins use the same verification and cooldown path. A successful login clears only its own failure count. The process retains at most 4096 hashed login counters; it removes only expired, inactive entries. Full counter capacity refuses new login keys uniformly with LoginRateLimited and a one-second retry delay. It does not evict live counters or in-flight verifications. This replaces the earlier process-wide cooldown policy; the two-verification/eight-queued-login resource limits are unchanged. Wrong current-password counters are per User, across its devices. The fifth wrong verification starts a one-minute cooldown and durably revokes its calling session; other devices remain live. Login does not clear password-change cooldown. Successful password change increments credentialVersion and revokes every session of that User. Logout and logout-all commit before success. Other Users remain live. Login keeps at most 32 unrevoked sessions per User and evicts the oldest instant, with a stable session-ID tie break.

Command-aware login, display-name and password operations persist their result in the same aggregate update. Durable retry results preserve the complete supplied command ID without a 128-character limit, through restart and exact replay. Client command IDs are nonempty valid UTF-8 strings excluding the case-sensitive `expiration/` prefix. Escaped NUL, CR and LF, whitespace and Unicode retain their exact values; command IDs are not trimmed or normalized. Malformed UTF-8 is rejected at application admission and when opening the JSON store. Other text fields retain their existing validation rules. Sensitive fingerprint input uses a keyed digest. A 32-byte externally supplied result key and a cryptographic random reader configure `sessionsecrets`; it stores AES-GCM authenticated ciphertext and HMAC-SHA256 fingerprints. Retain the key across restart. There is no default key. Exact login retry restores the same saved token only while its corresponding session is currently valid. Changed input conflicts; revoked/expired/stale sessions do not become new authorization. Password/profile replay requires a current session for the original actor and authenticates the saved result. It does not verify a password again, allocate a session or write another result.

These are private application values, not HTTP response schemas. SessionView contains authority metadata and private cookie material. The HTTP adapter maps the C2-approved fields and independently validates CSRF/preauth binding. Gateway installs browser cookies only after confirmed persistence. LoginInput.PreauthDigest is verified transport context, never a public body field. Old aliases use the command-free operations and keep their original recovery limitations. A login command stores private SessionIssued material; command lookup must emit the public UserView with requiresSessionRestore and never the raw token. Auth supplies anonymous preauth transport and private HTTP mapping. Gateway owns browser cookie and Origin enforcement.

## Legacy migration and rollback guard

Migration is an explicit offline preparation operation. It does not read/write a running Gateway store or deploy a cutover.

1. Stop the old identity writer and protect its private backup before preparing a migration.
2. Pass schema 1 (account only) or schema 2 (account and sessions) bytes to `legacy.Decode`. Unknown schemas, fields, case aliases, duplicate keys, nulls, trailing JSON and invalid Unicode are rejected.
3. Supply explicit UUIDs for the migrated User, legacy organization, restaurant and Admin membership, plus explicit organization/restaurant names, a UUID source for sessions and a PHC checker.
4. Call `MigrateLegacy`. Preserve the backup profileID-to-UserID mapping in the cutover record. Legacy profile IDs are opaque; the new alias operator.id is the explicitly designated UUID User ID under C2.
5. Validate the returned aggregate and initialize a new absent Auth path with the existing single-writer JSON store. Keep the source backup unchanged. An existing Auth file is never overwritten by initialization.
6. Open the persisted Auth authority and confirm credentials and deadlines before switching the private transport before the stopped-writer switch below.

The migration preserves login, display name, verifier, credential versions, session digests and the exact stored createdAt/absoluteExpiresAt strings. Ordinary idle expiry is the original lastSeenAt plus 30 physical minutes, capped by the original absolute deadline. Remembered idle expiry equals the saved absolute deadline. Invalid lifetimes fail migration; they are not repaired by extending access. Stale/expired sessions cannot authenticate. The explicit organization receives Europe/Moscow/settingsVersion 1 and the restaurant remains registering until later reconciliation. No email or business state is invented.

Legacy files cannot contain a raw bearer or its derived CSRF digest. Migrated sessions therefore carry the private legacyCSRF marker and an empty stored CSRF digest. Auth derives and checks the original synchronizer token from the presented bearer after validating its saved session digest. New sessions require the persisted digest of their derived CSRF token. Replacement cannot alter this mode or digest, bearer identity, creation instant or absolute deadline. User logins are immutable; credential versions cannot decrease or change a verifier without a version increase.

Retain the validated initial import as the rollback reference. `GuardRollback(imported, current)` permits rollback only when the complete validated authority is identical. Any persisted activity, profile, password, session, command or scope change rejects rollback. Never restore the old backup after a logout/revocation, or start both authoritative writers. A later coordinated reverse migration needs a separately reviewed procedure; this unit does not create one.

## Development checks

Effective policy is in `.go-quality-versions`, `.go-quality-modules`, `.golangci.yml` and `.go-arch-lint.yml`. Quality tools are pinned outside production dependencies. Use `GOWORK=off` for service checks.

```sh
make tools
make fmt FILES="path/to/changed.go"
GOWORK=off go test -race -count=1 ./internal/adapters/jsonstore/... ./internal/domain/...
make check
make quality-test
```

`make check` inventories modules, verifies formatting, builds the library, runs lint and architecture checks, and runs all tests with race detection. `make quality-test` checks quality enforcement with synthetic projects. Use writable `GOPATH`, `GOCACHE` and `GOLANGCI_LINT_CACHE` paths when the environment restricts default caches. Do not change the pinned tool versions to avoid a failed gate.

The A2 tests add real JSON-store account/session restart, real Argon2 credential changes, device/User isolation, fixed deadlines, CSRF, capacity/cooldown, exact encrypted retry, explicit legacy migration and rollback refusal. The A1 tests cover actual filesystem restart, process writer contention, alias isolation, concurrent expected-revision commits and test-only IO faults. They cover partial writes, file sync/close failures, rename failures before and after replacement, directory failures, ambiguous initialization and cancellation after rename. Synthetic fixture addresses use `.invalid`; no delivery transport runs in this unit. Real-service assembly acceptance belongs to the later Factory/J1/E tasks. Complete lane checks must run again on the final Auth and Feedback candidates at handoff.

## Continuous integration

`.github/workflows/ci.yml` runs on branch pushes, pull requests to main and manual runs. It uses the Go version in `go.mod`, repository-pinned quality tools and `GOWORK=off`. Dependency verification and `go mod tidy` must leave `go.mod` and `go.sum` unchanged. `make quality-test` and the complete `make check` must pass before the production image is built.

CI loads the real production image, verifies its OCI source/revision labels, starts `/server` with isolated synthetic private inputs, checks liveness and authenticated readiness, and requires graceful shutdown. `tests/container/production-smoke.sh <image> <revision>` runs the same check locally. It creates no restaurant, business state or mail job and needs no real SMTP or peer service. Test data remain under `tests` and never enter the production source or image. The workflow has only `contents:read`, receives no registry credentials and does not publish images. Authorized image delivery remains a separate main-source step.

## Invitations, OTP and mail (A4)

Accounts.CreateInvitation requires a live own-org Admin session, bound CSRF and explicit ready Restaurant assignments. Addresses use trimmed NFC and preserve the case-sensitive local part; only the comparison domain is lowercase. The original delivery address is retained. There is one pending invitation per comparison address and Organization. Its fixed lifetime is seven physical days. CancelInvitation suppresses undispatched mail and never revokes an accepted membership.

BeginInvitationChallenge binds a challenge to a pending invitation and the initiating browser session or preauth digest. BeginEmailChallenge only targets an existing verified User address for login or password_reset. Begin and ResendChallenge commit a Challenge, exactly one encrypted MailJob and the original IdempotencyRecord.JobIDs in one aggregate replacement. Replays and reopen preserve that edge. Administration ResendInvitation reissues only a uniquely identifiable live invitation challenge; absent or ambiguous challenge bindings fail closed. It never guesses a browser or invents a job. Recipient-controlled begin is required before code delivery. Fresh UA1 CreateInvitation also accepts one link mail job atomically. Its 201 body remains Invitation metadata; acceptance does not guarantee delivery.

Codes use crypto/rand rejection sampling, six digits, a fixed ten-minute deadline, a sixty-second resend gap, four issues per challenge, three target issues per ten minutes, sixty global issues per ten minutes, five wrong verifications and three hundred verification events per minute. Admission history is durable. At most 4096 challenges are retained; capacity fails closed instead of deleting completion evidence. Verification stores wrong-code outcomes by exact command so a retry does not increment attempts twice. Verification consumes no proof; it persists a recoverable proof with twenty-four-hour retention. Fresh completion after proof expiry is rejected. A committed completion replays before expiry checks, but the saved issued session must still be live.

CompleteInvitedUser atomically creates one User, saved Restaurant assignments, a session and proof consumption. Login defaults to the verified comparison address, or the new User ID if the address exceeds the frozen login bound. AcceptInvitation binds the verified address to the current authenticated User when no address is set. It preserves an existing equivalent verified delivery/display address, its verifier and queued mail recipients, and creates the saved membership. CompleteEmailChallenge creates a real session; password_reset validates the new password, advances credential version and revokes old sessions in the same commit. A foreign browser cannot use a proof. Credential changes, canceled/deleted scopes and expired invitations deny fresh transitions.

Administrative resend caps its next availability at the fixed invitation expiry. A permitted resend in the final minute still accepts one durable job. Fresh resends at or after expiry fail; neither the invitation nor challenge deadline is extended.

Set AccountOptions.Challenges to the real challengesecrets adapter with separate private 32-byte HMAC and AES-GCM keys. AccountOptions.Results uses the retained result-encryption secret. Keep these secrets in Auth only. Startup authenticates every retained secret and encrypted mail payload; a wrong key fails closed. It converts interrupted sending jobs to unknown while retaining job ID, attempts and original retry schedule. ProcessMail evaluates the injected owner clock, suppresses expired/canceled/consumed work and scrubs unused code and terminal mail ciphertext. The same stable job can be delivered more than once after an uncertain SMTP reply. Retries use sixty and three hundred physical seconds and at most three attempts. No automatic purge of command, proof-result or completed job evidence is added.

The approved registration HTML/plain-text/PNG assets are transferred without visual edits. RegistrationSMTP requires an injected clock and uses verified TLS/hostname checks, explicit Hello and advertised PLAIN/LOGIN. Its MessageTransport port carries the real owner invocation and rendered MIME. Only tests/mailobserver adds bounded synthetic correlation headers after rendering; it refuses non-.invalid recipients. Production imports no observer or fixture. No Auth HTTP listener, fixture RPC provider, signer or deployment is claimed by A4. A7 must compose the real Accounts/store/worker and publish the reviewed fixture projection over that live store.

Run GOWORK=off go test -race ./... and make check. The standalone offline smoke replaces Feedback's former OTP probe:

1. Build docker build -f tests/container/Dockerfile -t <owned-local-image> .
2. Run bash tests/container/otp-smoke.sh <owned-local-image>.

The smoke runs UID/GID 65532 on network none, uses local synthetic verified STARTTLS, the real Argon2/store/crypto/renderer/worker, and reopens durable files for replay and interrupted-send checks. It proves the A4 library/container scope only. J1/E service assembly and real private transport acceptance remain separate. The test image and binary identities must be recorded; no source publication or selected pin change is authorized.

## User tokens and organization timezone (A5)

Accounts.AuthorizeToken loads the real authority for every request. It validates the current global session, credential version, active membership, ready Restaurant and active Organization. The operation selects a fixed audience set and minimum permission set from the C2 public operation IDs. The caller cannot supply roles, permissions, organization or timezone. Foreground successful authorization may advance the ordinary idle deadline and session version. Background requests and access checks do not extend it. Absolute deadlines remain fixed. The result is private; public responses must never expose its token.

Set AccountOptions.Issuer to jwt.Signer and AccountOptions.TimeZones to timezones.Catalog. Supply the same owner Clock to Accounts and the signer. The signer receives the captured decision instant from Accounts. Its own injected clock controls signing readiness, key publication and retention. Missing, invalid or backward clocks fail closed. Configuring a signer without a ready packaged catalog also fails Accounts startup; every stored Organization zone is validated against that catalog. There is no host-clock fallback.

Configure jwt.New with explicit Ed25519 private material and a UUIDv4 generator. The signer copies and validates the key. No transport or control credential is a signing key. Only Auth may hold signing material. SignUser emits alg EdDSA, typ JWT, issuer urn:umir:auth, kind user and azp umir-gateway. Claims bind the User, session/credential/membership versions, Organization, Restaurant, settings/lifecycle versions and captured zone. JWT timestamps use whole Unix seconds: nbf equals iat and exp equals iat plus 60. JWKS returns public OKP/Ed25519 keys only. The bounded VerifyUser helper validates signatures, exact claim/header shapes, audience, operation/permission pairing and the zero-leeway time window. Consumers still own route, caller, runtime-epoch and packaged-zone validation.

PublishNext exposes a distinct next key. ActivateNext refuses a switch before 60 seconds of publication and while an older retained key still overlaps. The previous key remains discoverable for at least 60 seconds after its last issuance. JWKS contains at most active, next and previous keys. Process composition must retain the selected private keys and publication/retention metadata privately across restart. jwt.Options accepts Next, Previous and ActiveLastIssued to restore those windows. A7 owns private mounted-key provisioning, authenticated discovery transport and runtime persistence; A5 does not provide a service listener or advertise fixture RPC readiness.

Construct timezones.New with explicit packaged IANA zip bytes and a recorded package version. It validates the complete bounded archive with LoadLocationFromTZData, never Local or environment lookup. Ready returns its package version and exact archive SHA-256. Missing/corrupt data fails readiness; unknown zones fail validation. Production composition must load the declared archive and enforce a common data version across time-consuming services. The unmodified Go 1.26.9 archive under tests/testdata is test input only.

Accounts.UpdateSettings requires a live own-Organization Admin and bound CSRF. It atomically stores the zone, incremented settingsVersion and encrypted original Settings result. Unknown zones, stale expected versions, foreign administrators and concurrent losing writers leave the original authority intact. Store replacement refuses version rollback or a changed zone without a version advance. A retained exact command resolves before current settings/zone checks but still requires current actor access. Changed input conflicts. Reopen returns the original version without another mutation. New tokens inherit current settings; accepted earlier tokens retain their original zone/version and expiry. Session, invitation, OTP and recorded business expiry instants are not recalculated.

A5 checks add real JSON-store concurrency/reopen, scoped authorization, Ed25519 verification/JWKS, rotation/restart overlap, bounded malformed tokens and explicit missing-data refusals. Run the normal make check and the focused command GOWORK=off go test -race ./internal/adapters/jwt/... ./internal/application/...; tests/integration also exercises the complete A5 application path. An offline test image can use tests/container/Dockerfile and /enrollment.test with -test.run=TestA5. It is library evidence only. Private HTTP, bootstrap, control credentials, fixture protocols, service/J1/E acceptance and deployment remain pending.

## Creation, reconciliation and cascade (A6)

Accounts.CreateOrganization requires a live global session and its CSRF token. It atomically saves the Organization, first registering Restaurant, creator Admin membership, independent UUID operation, registration intent and encrypted original LifecycleResult. Accounts.CreateRestaurant requires current own-Organization Admin authority. Unknown zones, invalid names, reserved command prefixes and ID collisions leave authority unchanged. Original accepted results replay after reopen with the same result key. Changed input conflicts. A creation replay requires surviving scope authority.

Accounts.DeleteRestaurant and DeleteOrganization atomically save cutoff, increasing lifecycle versions, durable tombstones, scoped membership removal, invitation revocation, undelivered scoped-mail suppression, cleanup intent and original acceptance. Pending invitation challenges expire; previously verified proofs cannot complete against a deleted scope. A send already claimed may finish. Global Users, credentials, sessions, neighboring scopes and Feedback facts remain. Deleted IDs stay reserved.

A new cascade affects surviving scopes. Previously deleting/deleted Restaurants retain their own immutable tombstones, operation identities and cleanup intents. Organization cleanup waits for current closure of these earlier intents as well as its newly affected Restaurants. Earlier Restaurant operations complete independently once their own current peers close, even while sibling cleanup remains pending. The immutable encrypted acceptance identifies the Organization operation by its exact operation UUID, not by a shared command ID or cutoff version. It does not rewrite an earlier cutoff version or recreate an old runtime.

LifecycleResult has the eight frozen public fields and omits internal actor metadata. Creation acceptance is registering/not_required; deletion acceptance is deleting/pending. The HTTP layer maps these to 201 and 202. Accounts.Lifecycle reports later peer progress. Only the initiating User with a valid global session or a current own-Organization Admin can poll accepted deletion. The original initiating User can replay its exact deletion after cutoff. These exceptions grant no business or invitation capability. Accepted command responses remain unchanged after cleanup and restart.

AccountOptions.Runtimes is a consumer-owned port for the frozen status, RegisterRuntime and CloseRuntime contracts. The runtime HTTP adapter supplies authenticated transport and Auth-only service signing. Calls carry the saved operation, explicit Restaurant, exact current epoch, lifecycle version and current settings. Peer acknowledgments must match all associations. No business state is reconstructed. Same-epoch reconciliation retains acknowledgment and does not reinstall a runtime.

Peer status IO runs outside the global Accounts mutex. Auth reloads the authority after each observation and retries a decision when its aggregate revision changed. Session validity is checked again after IO. Registration acknowledgments for old organization settings are discarded. Independent account reads, logout and scope deletion remain available while a peer is slow.

Accounts.Reconcile performs one serialized pass. It first creates missing registration intents for migrated scopes and closes their admission. It persists pending/current epoch state before external calls, then checks current intent/version before and after each acknowledgment. Deletion can commit while registration is in flight; a late acknowledgment cannot restore access. It rechecks all current status epochs before completing the pass. Unavailable status keeps pending with no invented epoch. RestaurantAccess and AuthorizeToken check fresh healthy peer epochs before granting access or extending foreground idle time. Registry returns one complete bounded revision with current settings, peer associations and durable tombstones; more than 10,000 Restaurants fails closed.

Accounts.RunReconciliation needs an injected ReconciliationWaiter. Run one worker with an owned cancellation context and join it before closing the store. Each network call receives a five-second context deadline. The transport and waiter must honor cancellation. Pending attempts use delays 1, 2, 4, 8, 16 and 30 seconds, then 30 seconds indefinitely. Complete passes poll every second for restarts. These are mechanism timers; business instants, deletion timestamps and authorization use AccountOptions.Clock. Ambiguous persistence requires store reopen; the worker cannot manufacture a committed result. Authority/storage and worker-invariant failures stop reconciliation and close process admission. Peer unavailability remains a bounded retry with the existing backoff.

A6 tests use local typed peer transport doubles with the real JSON store, encryption, session admission and injected owner clock. They do not prove peer runtime or J1/E behavior. Run the affected checks with GOWORK=off go test -race ./internal/application/... ./tests/integration/.... Full make check and make quality-test cover the complete module. A7 supplies HTTP composition and the Auth fixture. Real peer assembly and J1/E acceptance remain separate checks.

## A7 private process and bootstrap

Run `go run ./cmd/server` with `UMIR_AUTH_CONFIG_FILE` naming a private configuration file. The default reference is `/etc/umir-auth/config.json`. The file and credential files must be regular mode 0600 files owned by the process UID/GID. Symlinks, including parent symlinks, fail admission. No credential is supplied in a command argument or ordinary log.

Configuration fields are privateAddress, stateFile, secretsDir, initialUser, passwordFile, serviceKeyFiles, peerKeyFiles, peerURLs, zoneDataFile, zoneDataVersion, isolatedHTTP, tlsCertFile, tlsKeyFile, smtp, registrationMail, smtpUsernameFile, smtpPasswordFile and smtpCAFile. serviceKeyFiles names gateway, serving and optional warehouse. peerKeyFiles and peerURLs name warehouse, serving and gateway. Every transport key is 64 lowercase hexadecimal characters. Serving discovery uses serving-auth; auth-serving remains its distinct outbound lifecycle key. The configuration references files and never gives peers an Auth signing key. smtp contains transport settings; username and password are loaded from their separate files. registrationMail supplies the existing operator/address/sender template metadata.

Use TLS with certificate and hostname validation outside an isolated test network. isolatedHTTP permits the explicitly isolated local transport only. The authenticated listener has healthz and readyz probes. Health is process liveness. Readiness validates the live store, account mechanisms, secrets and packaged timezone catalog; it does not assert Restaurant readiness or availability of unfinished peers. Every business scope still requires fresh exact peer acknowledgments. SIGTERM cancels workers, drains the HTTP server and releases the lifetime writer lock. Reconciliation has one serial bounded retry owner. Mail uses one serial worker with the existing real outbox and SMTP adapter. Background storage failure closes runtime admission until recovery/restart. A mail-attempt deadline alone does not permanently close readiness: the worker performs bounded durable recovery of interrupted sending jobs and continues. It preserves the original job ID, attempts and retry deadline. Confirmed outcomes remain unchanged; ambiguous authority replacement still requires reopen and does not enter this retry path.

For a missing state file, supply one explicit initialUser and a private password file. Text password and SMTP credential files may have one final LF or CRLF. Auth removes exactly that ending, preserves every other byte and significant space, and rejects an empty value. The existing 128-byte password and 256-byte SMTP credential limits apply to the value, with at most two additional line-ending bytes in the file. Raw service credentials, signing and owner keys keep their exact bytes. File permissions, ownership and symlink checks remain required. Startup failures name the failed stage without exposing private paths or file content; wrapped causes remain available to controlled diagnostics. The password follows the unchanged 8–32 code-point policy. Bootstrap uses the selected real Argon2id policy, crypto/rand, domain validation and jsonstore.Initialize. It creates no email, session, membership, Organization, Restaurant or mail job. Auth privately persists its signing seed, unique signing kid, result encryption key, challenge encryption key/pepper and original bootstrap binding in one mode 0600 owner-secret file. Keep this directory on the protected Auth volume. The store remains the sole business authority. A present store is opened without reseeding or rehashing. Original User ID/login and bootstrap binding must agree; later legitimate profile/password changes are retained. Missing or partial owner secrets and corrupt stores fail closed. Ambiguous initialization/replacement requires reopen and validation, never overwrite.

The private façade mirrors the frozen /internal/auth/v1/public routes. Only Gateway's transport credential can use it. Auth independently verifies session/preauth CSRF; Gateway owns browser Origin, cookies and public routing. Preauth is authenticated with retained Auth-owned key material, has a 30-minute owner-clock lifetime and a bounded 1024-entry issuance table per process. No façade response contains a verifier, encrypted payload or signing material. Raw session material is confined to the frozen private SessionIssued response. Public discovery exposes only real Ed25519 JWKS. Anonymous Feedback and due-only scheduler tokens retain their separate minimum claim shapes; Gateway cannot request Auth lifecycle tokens.

Command lookup uses a canonical unpadded base64url encoding of UTF-8 JSON with properties operationID, orgID, restaurantID in that order. Empty scope strings represent an unscoped operation. The actor or original preauth is authenticated independently and is never accepted from this namespace string. `application.Namespace` generates this representation. Lookup returns the original representable typed success and revision; login/completion results use public UserView and requiresSessionRestore, without the raw cookie token. An unavailable or nonrepresentable result fails closed. Exact settings replay preserves original Settings in the Organization wire result. Lifecycle wire results omit pending peer rows without an observed epoch; they never invent epochs.

## Stopped-writer switch and rollback

1. Stop the old Gateway identity writer and the old Auth-related Feedback OTP/mail owner. Retain the original checkout and selected assembly. Do not run two identity writers.
2. Protect an offline backup of legacy identity/session state and Auth encryption/signing material. Record file modes, original deadlines, credential versions and explicit legacy User/Organization/Restaurant mapping.
3. Run the existing MigrateLegacy preparation and complete validation checks. Preserve verifier, deadlines, revocations, command results, challenges and mail-job identity. A present Auth store requires its retained owner secrets; do not generate replacement secrets for an existing authority. Missing authority with retained owner secrets is a partial-state failure, even across repeated starts. Keep admission closed. Recover offline from a mutually consistent authority and owner-secret backup under the stopped-writer procedure; never initialize or delete retained secrets to bypass this failure.
4. Start the candidate Auth authority privately. Verify one-writer rejection, store readiness, private caller separation, packaged timezone data and session readback. Configure real runtime ports before admitting any Restaurant.
5. Switch Gateway's private Auth client and stop/remove the replaced identity, signer and OTP owners at that coordinated switch. The candidate Feedback auth-mail replacement was removed in A4; its independent intake/notification journal remains. Original selected checkouts are historical inputs, not extra active owners.
6. Run the real Factory assembly and acceptance commands at J1/E before any publication or deployment. A7 local tests and peer doubles do not establish that acceptance.

Rollback stops the candidate writer first. Preserve the current Auth volume, owner secrets, accepted commands, revocations, tombstones and outbox evidence. Reopen a compatible authority; never replace it with an earlier backup that discards acknowledged changes. If the old process cannot consume the evolved authority safely, keep admission closed and repair offline. No automatic purge, restore or deployment is performed here.

## Auth operational fixture

The test-owned paths are tests/fixtures/server, tests/fixtures/control, tests/fixtures/protocol and tests/fixtures/Dockerfile. Build with Go 1.26.9 and GOWORK=off. Production cmd/server and its image contain no fixture control route, synthetic profile, test clock or fault flag. The dedicated fixture image runs /fixture-server serve and reads only /run/umir-fixtures/config/config.json. /fixture-server healthcheck checks real owner/fixture readiness. /fixture-control request reads one bounded JSON request from stdin and returns only schema-checked redacted output.

The normative inventory is operational Feedback observation revision 1f585cce70d8aaf9422d769c1c804ccb3e7b6e0e318c383a8cedbc5cf91310de, bindings af215b378140b8e690523fc537007679b8c2599ed3039f7f2a0c651a64c59410. Protocol remains umir-operational-fixtures/1.1.0 and C2 business wire remains unchanged. Auth implements fixture.ready, bootstrap.read, clock.read/set/checkpoint, owner.jobs, owner.jobs.discover and owner.fault.arm/read/clear. No Feedback, sink, Warehouse or scheduler capability is advertised by Auth.

Controls use a separate mode 0600 Unix socket under the mode 0700 /run/umir-fixtures directory, plus the distinct fixture-auth credential. Controls are absent from the private business TCP mux. Fixed Auth state is /var/lib/umir-auth/auth.json. The exact supplied initial User and private 32-character random hexadecimal password use the real bootstrap constructor. Secret-directory creation and reopen require a real mode 0700 directory owned by the process UID/GID and no symlink in its path. Startup requires the persisted original User metadata and binding to equal the configured original input. Current profile/password changes remain separate and survive restart. Bootstrap observation reports the current real User and original binding, not a session or an authorization grant. The owner clock is injected into accounts, session/OTP/authorization, real signing, preauth and mail expiry. IO/retry deadlines use bounded host timers. Each mail delivery has a five-second transport deadline within a ten-second processing bound. The remaining processing context records the actual transport result durably. A transport timeout does not stop retries or fail healthy Auth readiness; storage and recovery errors still fail closed. Restart uses the runner's saved instant/generation, a new process instance and the real reopened authority.

Job discovery reads one immutable snapshot from the same live writer store. Challenge selection returns all retained jobs. Command selection joins the exact challenge, operation, original command and durable JobIDs; namespace ambiguity fails. It does not decrypt, parse raw files, open a second writer, run a worker or create a job. Original acceptedAt, expiry, command revision and job identities survive replay/reopen. Missing edges return bounded NotFound/WaitExpired, never non-commit proof. Exact control-request replay returns its original cached response; fresh observations require fresh request UUIDs. The cache holds at most 256 entries with no silent eviction. Request/response/depth/concurrency/wait bounds follow the frozen schema.

Faults decorate the real repository and HTTP transport under tests. before-commit does not call the writer. after-real-commit-return-unknown requires a real committed result and loses only its return. after-durable-before-reply drops the actual committed reply. Match one operation/command once with a bounded host TTL. Fault selectors cover the 22 frozen command-bearing Auth façade routes, with exact method and path matching. Read routes, logout without a command ID, non-Auth operations and unsupported points return UnsupportedOperation without arming. Test mail reuses the real SMTP/rendering adapter and existing mailobserver correlation headers. Only .invalid recipient content is accepted, through the synthetic verified-CA smtp endpoint; no external delivery is enabled.

Run make check, make quality-test, full fresh go test -race -count=1 ./..., go mod verify, Linux amd64/arm64 builds and focused bootstrap/fixture races. Build both production and dedicated fixture images. Record complete source/binary/config/image identities and actual controls. Local Auth-only readback proves that binding only; real Gateway login, peer services, Feedback journal and Factory J1/E remain separate.

## Unpublished owner profile integration

The test wrapper has a separate `POST /owner-profile/v1` endpoint on its private Unix socket. Production has no profile endpoint. The fixed command is `fixture-server serve-profile --profile <name>`. Its strict mode-0600 `/run/umir-fixtures/profile.json` binds the project, profile and approved profile contract. Control uses `fixture-control profile --request /run/umir-fixtures/profile-request.json`. The ordinary operational RPC and its capabilities remain unchanged.

Auth owns the closed rotation, corrupt JSON, unknown schema, invalid aggregate, schema-v1/schema-v2 import and second-writer profiles. Preparation, private signer checkpoints, verifier/session HMAC proofs and writer probes stay under `tests/fixtures/profiles`. Only Auth generates signing keys. The general signer `Snapshot` copies private key state; `bootstrap.OpenImported` initializes an absent store from a validated aggregate and preserves its verifier. Reopen uses normal `Open`.

This integration is incomplete. The corrected schema-v2 fixture preserves the real eight-hour ordinary session lifetime and the original remembered deadline. The former four-hour fixture remains rejected evidence; production migration validation was not relaxed. Current owner-profile approval and the complete eleven-run profile suite remain required. Passing local mechanics or individual image checks does not establish profile, J1 or E2E acceptance.

The amended isolated backend wrapper requires a separate `feedback-auth` credential in its exact six-key transport map. Auth authenticates Feedback only for exact `GET /internal/auth/v1/jwks`; HEAD, query/path aliases, health, registry, readiness and every other route/method are forbidden. It derives caller identity from the credential. Other caller permissions remain intact. This provisioning is bound separately to discovery overlay `b2e3b3824e622d68360d73854f24920c827b9c1aefadf013241ec69262daa02f`; it does not modify base FOC binding `af215b378140b8e690523fc537007679b8c2599ed3039f7f2a0c651a64c59410` or RPC 1.1.0.

## UA1 collection reads and invitation links

The additive UA1 profile supplies GET organization members and invitations, and POST invitation resend-link. Only a current own-organization Admin can read these collections. Each page joins one aggregate snapshot. Legacy Users without a verified email return null. Invitation delivery observations include only link jobs. Expired pending invitations are projected as expired without changing their stored version.

Collection queries accept limit (default 100, maximum 500), cursor, and state. Captures last five physical minutes and bind the current actor, organization, list kind, filter and limit. Every page rechecks current session and Admin authority. Captures retain at most 10000 rows, 128 active captures per organization, 16 MiB per organization and 64 MiB across the process. Capacity returns LimitExceeded; an unavailable cursor returns RefreshRequired with details.refreshRequired. No partial list is returned. Process restart invalidates every cursor.

Configure invitationMail.frontendOrigin in the private process JSON. Use an HTTPS origin with no credentials, path, query or fragment. For isolated loopback tests, allowLoopbackHTTP may explicitly permit HTTP localhost or a loopback IP. Missing or invalid configuration rejects fresh create/resend-link before mutation. It does not prevent exact legacy replay. The captured link contains only /invite/{invitationID}; opening it does not grant membership or replace email-bound OTP verification.

Fresh creates and resend-link atomically persist one typed invitation_link job and its original command result. Exact retries preserve the same invitation, job and captured URL. The existing resend route continues to send OTP and requires a live challenge. Both resend paths share the invitation's 60-second cooldown. Link resends have a five-per-invitation rolling-hour ceiling. OTP and links share three accepted issues per comparison-email target and 60 globally per rolling ten minutes. The existing three-create organization/email limit remains. Retrying the same command or transport attempt consumes no new issue.

SMTP uses the registration brand assets, a separate invitation template and a stable Message-ID for each link job. Attempts are limited to three, with one- and five-minute delays. A lost reply remains unknown; after the third uncertain attempt the same job remains unknown with no next attempt. Cancellation, acceptance and deletion suppress unclaimed work in the same authority update. A previously claimed bounded SMTP operation may finish, but its result cannot restore access.

### Auth storage format upgrade

Startup accepts a validated v1 aggregate and commits its explicit v2 upgrade before admission. Retain the existing result, challenge and session keys. The upgrade preserves identities, original deadlines, ciphertext and command results. Existing jobs become otp jobs with recorded enqueue order; existing command records retain the C2 profile. Fresh link commands use UA1 and require exactly one owned link job. Legacy zero-job create replay never backfills mail. Unknown formats, malformed linkage and format rollback fail closed. Stop the writer before replacing a binary; never restore an older authority over later accepted commands or revocations.

UA1 source tests and local qualification are separate from the historical C2 all67, owner profile, F3/F4 and J1/E/J2 evidence. Run make check, make quality-test, go mod verify and a clean go mod tidy check on the final source.

The test-only fixture command `serve-ui-ua1` uses its validated test-owned public
origin for invitation links and enables loopback HTTP. It exposes the separate
`POST /ua1-fixtures/v1` discovery endpoint on the private fixture Unix socket.
Ordinary serve, profile selectors and production have no UA1 endpoint.

The unpublished supplement `umir-ua1-mail-fixtures/0.1.0-unpublished` is defined
by `tests/fixtures/protocol/ua1.schema.json` and `ua1.binding.json`. Its exact
binding SHA256 is `c468cb825a3b9bfe01577485f47267f4765c95286ac08de367002e3e25f3df45`.
Use the existing fixture-auth Bearer credential, a fresh request UUID and the
current fixture/instance/generation/binary/config identity. Link selectors use
orgID/invitationID and optional jobID; OTP selectors use challengeID and optional
jobID. Mixed kinds, foreign scope, unknown/duplicate fields and stale identities
fail before a qualified result is returned.

Discovery returns at most 64 complete selected rows with actual durable states,
attempts, deadlines, link command allocation and stable synthetic Message-ID.
It omits recipient and secret payloads. Request/response limits are 16384/262144
bytes; physical request lifetime is ten seconds; concurrency is eight; the
per-instance replay cache holds 256 identities without eviction. Identical
request replay retains the original observation. A fresh state observation
requires a fresh request ID and current owner identity.

This endpoint reads the live writer's immutable aggregate. It does not run mail
or mutate authority. A complete empty selection proves only that selected
population. It does not prove zero mutation, enqueue or delivery. The existing
operational RPC/schema and capabilities remain unchanged. Receiver integration
and the complete UA1 qualification remain pending.

The separate test library `umir-ua1-mail-controls/0.1.0-unpublished` supplies
typed one-shot storage controls for actual createInvitation/resendInvitationLink
commits, a gate before a routed ProcessMail invocation, and gates after durable
link claim and after actual sender return. Its binding is
`a89c877bc27aed78ac5c7ebee91a77c5a0680b8fbfb79fe7cc660e2f381d5738`.
Controls retain 64 records without eviction and use physical 100..30000 ms arm
lifetimes. The earlier control or invocation deadline cancels held work. The
routed invocation lasts at most ten seconds; actual sender IO lasts at most five.
Arm/hit/release/effect facts preserve their original identities and ordered
sequences. Command controls bind actual actor/org/idempotency identity and exact
request-body digest and the candidate's normalized fingerprint through the real
Auth ResultSecrets Digest port. They do not assign a business or delivery outcome.

The `serve-ui-ua1` wrapper routes its single mail worker through this library.
Bootstrap provides an additive MailProcessor port and ServeWithMailProcessor;
ordinary Serve keeps its original signature, processor, ticker and IO limits.
Do not start a competing ProcessMail caller beside that worker. A separately
qualified barrier inside SMTP IO and Factory runner integration remain required.
The owned-child process test stops real Auth after a stored sending claim and
checks ordinary bootstrap recovery and the retained retry deadline. These source
checks do not qualify a complete UA1 scenario, profile or final assembly.

The separate unpublished wire supplement is
`umir-ua1-mail-control-wire/0.1.0-unpublished`, binding
`5e546ae0c4db8d215d1f889bcdef413e50d4a5269351ceb49446a960f953eccd`.
It depends on the existing control-library and discovery bindings. The dedicated
schema and binding are `ua1-control-wire.schema.json` and
`ua1-control-wire.binding.json` under tests/fixtures/protocol. Production,
ordinary serve and owner-profile modes expose no control-wire endpoint.

POST /ua1-mail-controls/v1 on the private Unix socket accepts control.arm,
control.read, control.release and control.cancel. Use the existing fixture-auth
credential and current five-field identity. Reject extra/duplicate/null fields,
alternate methods/paths, foreign bindings and stale identities. Limits are
16384 request bytes, 262144 response bytes, eight calls and ten physical seconds.
The cache retains 256 request IDs, including errors, without eviction. A retry
of an identical request returns its original response; it is not a fresh read.
A retained NotReady error requires a new request UUID after recovery. Reads and
cancellation remain available after business/worker readiness loss.

The fixed CLI is `fixture-control ua1-control`, with JSON on stdin and the
existing private config/socket/credential checks. It returns redacted schema-
validated JSON. It has no arbitrary endpoint or credential argument. Store
controls observe the exact actual HTTP body/route and read-only Peek actor;
the real handler retains transport, CSRF, session and scope admission. The
client rejects wrong correlation, binding, identity, control ID, status and
causal sequence. A hit retains its exact arm generation. ControlConflict and
ObservationUnavailable errors have unknown control effect; a conflict can
observe an expiry before refusal. They cannot prove that no action occurred.
The four fixed ASCII schema patterns use strict Go regexp with the existing
500-ms validation and 4096-match work bounds. Other schema engines stay unchanged.
Factory consumers and runtime case
qualification remain separate handoffs.
