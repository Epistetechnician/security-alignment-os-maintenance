# Local end-to-end assurance V1

State slice: security-alignment-os-foundation-v1.

## Testable claim

The local Rust reference implementation binds a proposal to accepted local
evidence, admits it under the configured policy, issues and verifies a
single-use capability receipt, mutates only the declared local state, records
an auditable result, and rolls back and freezes when the supplied observation
is unhealthy. Invalid evidence or receipt bindings must not authorize a
mutation. Claim composition must meet guarantees and preserve exclusions. A
valid external-execution request remains blocked in this state slice.

This is a deterministic control-contract claim about the named local code and
fixtures. It is not a behavioral model evaluation or a scientific alignment
claim.

## Assay definition

- **Metric:** every required assertion in the local end-to-end tests passes;
  any failed, missing, or inconclusive assertion fails the gate.
- **Baseline and controls:** accepted synthetic evidence and signed test
  receipts are compared with replay, wrong-subject, unhealthy-observation,
  artifact-binding, and valid-but-blocked external-execution cases.
- **Repeat rule:** run the complete deterministic suite once for each candidate
  working tree. The fixtures do not introduce stochastic model behavior, so
  this assay makes no statistical effect-size or confidence claim.
- **Cost boundary:** local CPU, filesystem, and human review only. No model,
  provider, network service, paid execution, real-user data, credentials, or
  value movement is used. Local compute cost is not measured.
- **Fixtures and custody:** proposals, role labels, keys, attestation tokens,
  reports, and protocol responses used in these tests are synthetic test
  values, never production credentials. Temporary files are created under
  test-owned temporary directories.
- **Claim ceiling:** local Rust pure-data control and caller-owned persistence
  evidence only.
- **Nonclaims:** no host identity, Linux production hardening, TEE authenticity,
  independent replication, external reviewer acceptance, model behavior,
  held-out generalization, scientific alignment, production security, or
  deployment authorization is established.

## Coverage map

- tests/security_thesis_e2e.rs: accepted evidence through receipt verification,
  bounded write, independent local journal checks, audit persistence, replay
  rejection, missing-evidence quarantine, unhealthy rollback/freeze, subject and
  signature substitution quarantine, accepted and mismatched artifact binding,
  custody rejection for missing, deleted, expired, root-mismatched, and
  digest-mismatched records, a combined custody/evidence/receipt completion
  with retry after pre-admission custody rejection, local file custody success
  and rejection for content mismatch, path traversal, symlink, broad
  permissions, hard links, repository overlap, and byte-limit violations. It
  also covers meet-only claims and blocked external execution.
- `src/custody.rs` tests: synthetic owner/root/digest bindings, retention
  expiry, unsafe path and permission rejection, size limits, and a deterministic
  same-size artifact mutation during the bounded read rejected by the opened
  file metadata fingerprint check.
- tests/local_demo_e2e.rs: launches the public local_demo binary and checks its
  completed disposition, state digest, state slice, and claim ceiling.
- tests/maintenance_platform_runners_e2e.rs: execute both platform workload
  functions against the actual local replication runner, broker, and evaluator
  binaries. A local Unix socket returns a synthetic Confidential Space token;
  a synthetic Nitro callback supplies NSM bytes. Both flows validate the signed
  20-scenario report and check envelope audience, nonce, report digest, and the
  machine-attested claim ceiling.
- tests/nitro_enclave_image_policy.rs: checks clean Git source identity,
  rejects modified, untracked, ignored, and mismatched source inputs, and
  verifies Docker build-time digest checks, compile-time identity embedding,
  runtime override rejection, and binary/entrypoint wiring. It does not build
  the Docker image or EIF.
- src/bin/maintenance_confidential_space_runner.rs tests: exercise bounded HTTP
  parsing, response framing, token shape, chunk decoding, and the local socket
  request protocol.
- src/bin/maintenance_nitro_enclave_runner.rs tests: reject malformed report
  bytes and invalid host reports before envelope construction.
- tests/confidential_space_image_policy.rs: checks that the image forbids
  launcher stdout/stderr redirection while the hosted path remains closed.
- tests/routing_e2e.rs: checks routing against the registered tenant grant,
  retrieval, persisted revocation across restart, stale-handle and stale-save
  rejection, a separate-process revocation waiting for an in-flight gated
  effect, persistent-memory denial, fresh-grant re-consent, memory snapshot
  mode and symlink checks, pending-write recovery, and expiry.
- tests/market_e2e.rs: checks fixed-job offer selection, exact result and
  receipt validation, replay rejection, persisted settlement reservation, and
  fail-closed price, result, overflow, and expiry cases. Cross-job or malformed
  supplied offers reject the whole selection set. Offer-backed receipt
  completion must fall inside the offer window, while a valid completed receipt
  may be proposed before the live job deadline. Settlement remains
  authorization-required metadata only.
- tests/broker_e2e.rs, tests/maintenance_process_e2e.rs, and
  tests/maintenance_replication_runner.rs: exercise their respective real
  local subprocess boundaries. Their results do not merge into a production
  authorization or separate-host result.

## Run and report

Run pnpm run test:thesis for the focused public workflow, demo, market, routing,
and hermetic platform workload checks. Run pnpm run test:e2e for all
public integration tests, real local subprocess boundaries, release
reproducibility, and attestation envelope checks. Run pnpm run lint for format,
all-target tests, contract digest verification, and warnings-denied Clippy. Run
cargo run --quiet --bin local_demo to inspect the local demonstration output
directly.

Report a passing local run as INTERNAL_PASS for this state slice and exact
working tree. REPRODUCED_LOCAL requires a clean second environment with
recorded toolchain, dependency, fixture, and output digests. A local pass never
means INDEPENDENT_ACCEPT or PRODUCTION_AUTHORIZED.

The next external gates are independently administered Linux Host B
reproduction and authenticated custody for the maintenance packet, external
red-team and supply-chain review, platform-specific attestation validation,
operational incident/recovery exercises, and separate deployment authority.
The Confidential Space runner must not be launched while its token output lacks
protected custody. The scientific alignment claim remains closed and requires
a separately authorized, preregistered, held-out empirical protocol.

## Recorded local run

Run date: 2026-09-24. State slice: `security-alignment-os-foundation-v1`.

- Exact implementation and test identity: Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`, plus the 91-file working-tree
  manifest SHA-256
  `b109aac2047d910b76ec908e44cc7691f482db7325dc0a67dc0f58ee5ed117a2`.
  The manifest covers sorted paths from
  `git ls-files --cached --others --exclude-standard`, excluding this
  self-report document. For each regular file or symlink it hashes the
  big-endian path length, relative path, permission mode, file/link marker,
  payload length, and payload bytes. The clean sibling copy matched this source
  manifest before execution.
- Environment: clean sibling source copy with a fresh Cargo target directory;
  macOS 26.6.1, arm64; rustc 1.87.0
  (`17067e9ac6d7ecb70e50f92c1944e545188d2359`); Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Dependency and synthetic-fixture identity: `Cargo.lock` SHA-256
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`;
  48 Rust implementation/test files SHA-256
  `b8f769473fbadfc0a43ca040c9fe1ef75774cf6eec8835b54d471d9c852d7208`.
  Test fixtures are inline synthetic values; the latter digest covers all
  `src/**/*.rs` and `tests/**/*.rs` files, ordered by relative path. Its hash
  feeds each path length (unsigned 64-bit big-endian), path bytes, source byte
  length (unsigned 64-bit big-endian), and source bytes.
- Results: `pnpm run test:e2e` exited 0: 65 passed, 0 failed across all public
  integration tests, local subprocess boundaries, evaluator release
  reproducibility, and synthetic attestation checks. Its output SHA-256 is
  `1993fc5b7245559d6ad53b05d19bf23d61f2a1c5442aa69058c6fd0d6fb842e1`.
  `pnpm run lint` exited 0: 174 passed, 0 failed; Rust format, build-contract
  digest verification, and warnings-denied Clippy passed. Its full output
  SHA-256 is
  `d17fb86c50332c93d206e31a1c7bbf6a55f1d8e7453393387fc4a88f4b62e733`.
  Two direct `local_demo` runs were byte-identical (520 bytes each), SHA-256
  `d07e410511f54be8a63b3a1b96ac21ae2203ececf316df5fcbc5ec21498151e5`; both
  reported `Completed`, this state slice, and the documented claim ceiling.
- Supplemental Linux container probe: `INCONCLUSIVE`, using local image
  `rust:1.87.0-bookworm` (`linux/arm64`, image ID
  `sha256:cb3e55f4870f58146e1cb339a53262422b55578619f9b6f3b7fe8c0d40165036`),
  with network disabled and source mounted read-only. The all-target run reached
  `broker_e2e`, where two namespace-dependent success-path tests failed. The
  Linux backend launches through `unshare --user --map-root-user --net --pid
  --fork --mount-proc`; direct probes confirmed this Docker environment rejects
  even the initial user namespace with `Operation not permitted`. Temporary-file
  execution worked, and `docs/broker-v1.md` specifies fail-closed behavior when
  `unshare` is unavailable. The image lacks `rustfmt`; the complete format and
  Clippy gates therefore come from the host run above. A retry with only those
  two broker tests excluded could not complete because Docker failed during
  overlay cleanup and then stopped responding; no Linux pass is claimed. This
  same-host container probe is not Host B reproduction.
- Assurance: `INTERNAL_PASS` and `REPRODUCED_LOCAL`. This was a same-owner,
  same-host clean-copy reproduction, not independent review. No independent
  reviewer was asked to decide this local result, and no signed reviewer
  decision was returned. No separate-host replication was performed here.
- Custody and ceiling: only local source, synthetic fixtures, and local output
  were used. No provider, model, external network service, credential,
  real-user data, paid execution, TEE platform, or production workload was
  used. The claim ceiling remains local Rust pure-data control and caller-owned
  persistence evidence only. `INDEPENDENT_ACCEPT` and `PRODUCTION_AUTHORIZED`
  were not established.
- Next blocked gates: independently operated Linux Host B reproduction with
  authenticated custody; external red-team and supply-chain review; actual
  platform attestation validation through a protected output path; and separate
  deployment authority. The scientific alignment claim remains closed.

## Follow-up market offer hardening

Run date: 2026-09-24. State slice: `security-alignment-os-foundation-v1`.

- Change: `market::select_offer` validates every supplied offer against the
  exact job before selection. A malformed or cross-job offer rejects the whole
  supplied set; structurally valid expired offers remain ineligible. Settlement
  proposals also bind receipt completion to the selected offer's
  submitted/expires interval, while allowing later authorization proposals for
  completed work before the job deadline.
- Exact implementation and test identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; Git tree object for all current
  implementation, test, and documentation files excluding this self-report:
  `1dcea07112e1460f20804190f36347285e576435`. The 48 Rust implementation and
  test files have SHA-256
  `33342b2d2a065aea1403746096ff9010e4abc14af2bc8b963802b7fed2a23a9c`;
  `Cargo.lock` SHA-256 remains
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS 26.6.1, arm64; rustc and Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Results: the cross-job and offer-window regression tests failed before their
  respective implementation changes. After both changes,
  `cargo test --test market_e2e` passed all 5 tests; output SHA-256 is
  `c1f516a89efdf62bed224c783b030a60b93e81faeda4e1e33a47c8e93b853570`.
  `pnpm run lint` exited 0: format, contract digest verification,
  warnings-denied Clippy, and all 176 unit/integration tests passed. Its output
  SHA-256 is
  `b095c205349edd89b58df2bf95779ea6c8ca62f4742e107452f018d2f83ba1a1`.
- Assurance: `INTERNAL_PASS` for this exact local source tree. No second
  environment reproduced this follow-up change; it does not receive
  `REPRODUCED_LOCAL`. No reviewer decision was requested or returned.
- Data and custody: only deterministic synthetic jobs and offers were used.
  No provider, network service, credential, payment, or external execution was
  involved. Test output remained local.
- Claim ceiling: deterministic local offer validation and selection for the
  fixed integer-sum job. This establishes no provider identity, remote result
  correctness, payment authorization, scientific alignment, or production
  security. Provider execution and settlement remain closed.
- Next authority gate: none for continuing local implementation. Any claim or
  operation above local synthetic control evidence requires its separately
  governed review and authorization.

## Follow-up Confidential Space response parser hardening

Run date: 2026-09-24. State slice: `security-alignment-os-foundation-v1`.

- Change: the local OIDC response parser now checks exact `Content-Length`,
  rejects repeated or conflicting framing headers and unsupported transfer
  encodings, and requires a string token when the body is JSON. This prevents
  malformed local HTTP responses from being wrapped as machine-attested
  reports. The wrapper still does not validate the token signature or platform
  claims, and the hosted runner remains disabled.
- Regression evidence: the new malformed-length case failed before the parser
  change because a truncated body was accepted; the runner's 7 unit tests pass
  after the change. The same test group covers malformed token shapes, chunked
  decoding, bounded reads, the local socket request, and report binding.
- Exact revision: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; current 91-file working-tree
  manifest SHA-256 is
  `15ba1e6e6ad6960fb6f1d919c05c45fe95211edfed4eebb89f247524419b84af`.
- Assurance: `INTERNAL_PASS` for the recorded complete local gates. This is
  synthetic protocol parsing evidence, not hosted Confidential Space
  validation, attestation verification, independent review, or production
  authorization.
- Data and custody: local synthetic HTTP responses and report fixtures only;
  no token, credential, platform call, external network, or hosted execution.
- Claim ceiling: bounded local HTTP/token-response parsing and canonical report
  binding in the wrapper. Platform signature/claims verification and protected
  output custody remain open.
- Next blocked authority gate: none for further local implementation; hosted
  runner execution remains closed pending a protected output and custody path
  in a separately authorized state slice.

## Follow-up consent revocation lifecycle hardening

Run date: 2026-09-24. State slice: `security-alignment-os-foundation-v1`.

- Change: the shared `ConsentRegistry` keeps a revocation tombstone for a
  registered grant ID and rejects re-registering that same grant. An
  intentionally new issuance receives a different digest-bound grant ID and
  can be registered. Routing, `TenantRetrieval`, and `PersistentMemory` now
  consult this same registry.
- Regression evidence: the old-grant re-registration assertion failed before
  the in-store implementation change. The updated end-to-end routing suite
  checks persistence recovery with and without a primary file, rejects
  noncanonical snapshots, verifies owner-only snapshot mode, and demonstrates
  that revocation blocks routing plus persistent-memory reads, writes, and
  deletes after reload.
- Persistence boundary: callers can save and recover the consent snapshot, so
  a saved revocation remains effective after restart. Snapshots are plaintext,
  unauthenticated caller-owned state; restoring older valid bytes can roll back
  a revocation. Callers must save and recover the current snapshot before
  reopening access.
- Exact revision: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; current 91-file working-tree
  manifest SHA-256 is
  `15ba1e6e6ad6960fb6f1d919c05c45fe95211edfed4eebb89f247524419b84af`.
- Assurance: `INTERNAL_PASS` for the recorded complete local gates; no
  separate environment or reviewer decision was used.
- Data and custody: synthetic local tenant, grant, request, and resource
  fixtures only. No user data or external service was involved.
- Claim ceiling: caller-owned local consent snapshot persistence, in-process
  revocation, restart recovery, and fresh-issuance behavior. Snapshot
  authenticity and anti-rollback, hosted enforcement, independent review, and
  production authorization remain unestablished.
- Next blocked authority gate: none for local implementation. Cryptographic
  consent authority and anti-rollback remain outside this foundation slice.

## Combined follow-up verification

Run date: 2026-09-24. State slice: `security-alignment-os-foundation-v1`.

- Exact working-tree identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; 91 files, excluding this
  self-report document, manifest SHA-256
  `15ba1e6e6ad6960fb6f1d919c05c45fe95211edfed4eebb89f247524419b84af`.
  The manifest sorts repository-relative paths and hashes each big-endian
  64-bit path length, path bytes, big-endian 32-bit permission mode, file or
  symlink marker, big-endian 64-bit payload length, and file bytes or symlink
  target bytes. Rust implementation and test sources have SHA-256
  `4682689127ce1929f109b55fb8199c481f9bc05d4be6ee5e845d26cd3bddd047` using
  sorted `src/**/*.rs` and `tests/**/*.rs` paths, path length/path bytes,
  content length, and content bytes. `Cargo.lock` SHA-256 is
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS 26.6.1, arm64; rustc and Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Results: `pnpm run test:e2e` exited 0 with 69 passed and 0 failed across 13
  test suites; output SHA-256 is
  `551117c1838b8395d027a7bd835c70e39bf6b028fb62a4c3b2a9e8dcbf83d937`.
  `pnpm run lint` exited 0 with 178 passed and 0 failed across 22 test groups;
  format, contract digest verification, and warnings-denied Clippy passed. Its
  output SHA-256 is
  `368b011faf25ec4b20b017f64c35c1817b40901cc0dd3aa814dec8ace890a46e`.
- Assurance: `INTERNAL_PASS` for this exact local tree. These follow-ups were
  not reproduced in another environment and received no independent reviewer
  decision.
- Custody and ceiling: only local source and synthetic fixtures were used.
  The claim ceiling remains local Rust control and protocol parsing evidence;
  consent snapshot authenticity and anti-rollback, platform attestation
  authenticity, protected output custody, independent review, and production
  authorization remain unestablished.

## Follow-up consent and persistent memory storage

Run date: 2026-09-24. State slice: `security-alignment-os-foundation-v1`.

- Change: path-backed consent registries reload and update canonical state
  under a local owner-only single-writer lock. `TenantRetrieval` and
  `PersistentMemory` hold that lock from grant validation through their
  consent-gated effect. A stale opened handle cannot overwrite a persisted
  revocation. Initial snapshot export cannot replace an existing snapshot.
  Persistent memory takes a per-file lock for each read, write, delete, and
  `save`, then reloads the current snapshot before applying an operation.
  `save` persists and refreshes the latest snapshot. Memory snapshots
  are owner-only on Unix, use synced temporary replacement, recover a valid
  pending snapshot when a primary exists, and reject symlink, broad-mode, and
  noncanonical files.
- Recovery: opening or recovering a registry promotes a validated pending
  atomic-replace snapshot while holding the lock. An abandoned lock fails
  closed; manual removal requires checking that no writer remains live.
- Regression coverage: stale-handle regrant after revocation is rejected, and
  a revocation waits until a consent-gated effect releases the lock; subsequent
  access is rejected. Memory tests run overlapping parent and child-process
  writers, then prove stale-handle `save` refreshes without losing any record;
  parallel writer handles also retain every record. Restart recovery validates
  snapshots. Temporary-snapshot,
  malformed-snapshot, owner-only mode, and memory read/write/delete coverage
  remains in the local E2E suite.
- Limits: lock coordination assumes cooperating local processes and does not
  defend against a hostile same-UID process. An abandoned lock fails closed
  and requires an operator to establish no writer is live before removal.
  `len` and `is_empty` report a handle's last loaded view. Snapshot authorship
  and anti-rollback remain unprotected. Memory remains plaintext and logical
  deletion is not secure erasure.
- Exact tested identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; 92-file working-tree manifest
  SHA-256 `327e4bc778c3eaa7b641498b277141b9fc42355e36da66a5b2a5d94c5b971e4f`,
  excluding this self-report document. The manifest sorts repository-relative
  paths and hashes each big-endian 64-bit path length, path bytes, big-endian
  32-bit permission mode, `F` or `L` file/link marker, big-endian 64-bit
  payload length, and file bytes or symlink target bytes. The 49 Rust
  implementation and test files have SHA-256
  `2485f0652f75dc96af70ca5093948d28253136cb91e57132e4ad3a9f798b267e` using
  sorted `src/**/*.rs` and `tests/**/*.rs` paths and length-prefixed path and
  source bytes. `Cargo.lock` SHA-256 is
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS 26.6.1 arm64; rustc and Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Results: `pnpm run test:e2e` exited 0 with 76 distinct tests passed and 0
  failed across 13 targets; output SHA-256 is
  `dd09bcd851ef3b2ba0a2fdc862936173a65e91d3da83b25c4dbe2aa52d4d47af`.
  `pnpm run lint` exited 0 with 185 distinct tests passed and 0 failed across
  22 targets; format, contract digest verification, and warnings-denied Clippy
  passed. Its output SHA-256 is
  `2b546d76951fa00e9ceaaa26c7928c2a6196a515ef8b9b49f630c832904f50ec`.
- Assurance: `INTERNAL_PASS` for this exact local tree. Reviewer status: no
  independent signed decision was requested or used for this slice.
  Reproducibility status: no second-environment reproduction; this run is
  local to one Mac environment.
- Data and custody: local source and synthetic fixtures only; no external
  services or user data.
- Known limitations: cooperative local lock users only; hostile same-UID
  interference, authenticated consent authority, snapshot anti-rollback,
  abandoned-lock automatic recovery, and secure erasure are not established.
  `len` and `is_empty` report the last loaded handle view. Platform attestation
  authenticity, protected output custody, independent review, and production
  authorization also remain open.
- Claim ceiling: local cooperative-process consent and persistent-memory
  serialization, lock-held access effects, and owner-only Unix memory snapshot
  handling with validated crash recovery. This does not establish external
  authorization, anti-rollback, scientific validity, hosted enforcement, or
  production readiness.
- Next blocked authority gate: independently administered Linux reproduction,
  authenticated reviewer decision, platform attestation/custody validation,
  and separate deployment authorization remain external to this local
  implementation slice.

## Follow-up shared snapshot persistence

Run date: 2026-09-24. State slice: `security-alignment-os-foundation-v1`.

- Change: the shared local per-path writer lock, synced exclusive temporary
  replacement, and validated recovery now cover `ReplayJournal`,
  `KernelSnapshot`, `RuntimeSnapshot`, `AuditJournal`, `EvidenceRegistry`,
  `PredictionLock`, `ArtifactRegistry`, `BrokerJournal`, `FailureBudgetTracker`,
  `CustodyRegistry`, `ReleaseRegistry`, both receipt verifiers, `SchemaRegistry`,
  `SpecialistRegistry`, and `ToolRegistry`. New snapshot and lock files are
  mode 0600 on Unix. `ConsentRegistry` and `PersistentMemory` retain their
  purpose-specific lock-held update paths. Snapshot loaders reject primary
  symlinks and non-regular files.
- Semantics: These APIs replace complete snapshots. Concurrent calls serialize
  file replacement, but stale in-memory snapshots do not merge and the last
  completed save selects the contents. Audit appends remain caller-managed.
- Recovery validates and promotes a pending regular snapshot even when a
  primary exists, rejects symlink and non-regular primary paths, rejects
  pending symlinks, and makes new saves fail closed while pending data remains
  unresolved.
- Regression coverage: concurrent replay-journal snapshot replacement retains
  one complete validated state and leaves no lock/temp file; saved files are
  owner-only on Unix. Recovery promotes a valid pending snapshot over an
  existing primary. Kernel and runtime recovery also promote validated pending
  data over a malformed primary. Symlink regressions prove neither primary nor
  pending links are accepted. The full thesis E2E exercises the integration
  path and audit saving.
- Limits: local cooperating processes only; hostile same-UID interference,
  snapshot authorship, anti-rollback, and stale-state merging are not
  established. These APIs save complete replacements, so a caller saving stale
  in-memory state can replace newer state. A pending file must be resolved by
  `recover` before another save; abandoned locks require operator inspection.
- Exact tested identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; 92-file working-tree manifest
  SHA-256 `17cd3dce2f9645e0acd7cbc8992df92fea82903a6b50ed1b76e708e9758ffcb1`,
  excluding this self-report document. The manifest encoding is recorded in
  the preceding section. The 49 Rust implementation and test files have
  SHA-256 `c1dc7b59ed003cceff8f57ea16aef2c684e56e81a787d48b5ea5b2762f5238c2`.
  `Cargo.lock` SHA-256 is
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS 26.6.1 arm64; rustc and Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Results: `pnpm run test:e2e` exited 0 with 76 distinct tests passed and 0
  failed across 13 targets; output SHA-256 is
  `1fc41e7c70bd24d968436f2882c9fb18d5e972c40daf2ee3008af1119fe11151`.
  `pnpm run lint` exited 0 with 189 distinct tests passed and 0 failed across
  22 targets; format, contract digest verification, and warnings-denied Clippy
  passed. Its output SHA-256 is
  `d1e6641eff44b538befe9d32a01e37161a29e8101bfbc25b0153a2bb9f146b67`.
- Assurance: `INTERNAL_PASS` for this exact local tree. Reviewer status: no
  independent signed decision was requested or used. Reproducibility status:
  no second-environment reproduction; this run is local to one Mac environment.
- Data and custody: local source and synthetic snapshots only; no external
  services or user data.
- Claim ceiling: local serialized atomic replacement and validated crash
  recovery for the listed caller-owned snapshots, with symlink and non-regular
  path rejection. This does not establish authenticated storage, rollback
  protection, semantic validity, independent review, or production readiness.
- Next blocked authority gate: independently administered Linux reproduction,
  authenticated reviewer decision, platform attestation/custody validation,
  and separate deployment authorization remain external to this local slice.

## Follow-up replication runner identity V3

Run date: 2026-09-24. State slices: `security-alignment-os-foundation-v1`
and `maintenance-replication-runner-identity-v3`.

- Change: V3 host reports include a SHA-256 digest of the running replication
  executable. The runner records it before the 20-scenario matrix and rechecks
  it after the matrix. The report identity and both report signatures bind the
  digest; packet identity binds each report ID. Per-host runner digests may
  differ. V1 and V2 serialized signature inputs remain unchanged and
  verifiable. Baseline-manifest digest validation uses the report-version byte
  to preserve V1 and V2 values.
- Regression coverage: V1, V2, and V3 packet round trips; missing or changed
  V3 digest rejection; distinct runner digests across hosts; and the actual
  `maintenance_replication_runner report` process producing all 20 scenarios
  with its executable digest bound into the signed report.
- Known limits: the digest is a signed local observation, not build
  provenance. The path-based check does not close hostile same-UID races, and
  local signing keys and host/operator labels do not authenticate custody or
  independent operation. The report does not establish that the digest came
  from the declared source revision.
- Exact tested identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; 94-file working-tree manifest
  SHA-256
  `a7143028c5e2a01cd82631720643d8b13412cd8dd99419c1c813876295d20727`,
  excluding this self-report document. Manifest encoding is specified in the
  first recorded run above. The 49 Rust implementation and test files have
  SHA-256
  `d00471e04723bda484deab167d7ab34034f95dfde70d4e4565dfa6829fece754`.
  `Cargo.lock` SHA-256 is
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS 26.6.1 arm64; rustc and Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Results: `CARGO_NET_OFFLINE=true pnpm run test:e2e` exited 0 with 83 tests
  passed and 0 failed across 13 targets. Output SHA-256:
  `48dad6434a0767c75026d234d4005fe9bdf132087de172cafa03d0bcaabf6675`.
  `CARGO_NET_OFFLINE=true pnpm run lint` exited 0 with 197 tests passed and 0
  failed across all targets; Rust format, build-contract digest verification,
  and warnings-denied Clippy passed. Output SHA-256:
  `9ea72b63001b68b744a3478a63c9573d8c9ee01da4b7544a2c44c1082d8fe563`.
- Assurance: `INTERNAL_PASS` for this exact local tree. Reviewer status: no
  independent signed decision was requested or used. Reproducibility status:
  no second-environment reproduction; this run is local to one Mac.
- Data and custody: local source and synthetic scenarios only; no provider,
  external service, user data, or production workload was used.
- Claim ceiling: local signed wire-consistency evidence with V3 binding of the
  reported replication executable digest. This does not establish build
  provenance, independent replication, platform attestation, scientific
  validity, or production readiness. Consent snapshots also remain
  unauthenticated and rollbackable.
- Next blocked authority gate: independently administered Linux reproduction
  with authenticated custody, an authorized independent reviewer decision,
  platform attestation and protected-output validation, and separate
  deployment authorization remain open.

## Follow-up evaluator launch identity

Run date: 2026-09-24. State slice: `security-alignment-os-foundation-v1`.

- Change: the fixed maintenance broker revalidates the evaluator path as a
  private regular file after writing the request job and immediately before
  process creation. Its digest must match both the frozen configuration and
  the digest captured for the request. A detected replacement is quarantined
  before launch.
- Regression coverage: a real broker subprocess pauses before evaluator
  launch, the test replaces the evaluator after broker startup, and the request
  is quarantined with the checkout and neighboring file unchanged.
- Known limit: evaluator launch remains path-based. A hostile same-UID actor
  could race replacement between the final digest read and OS process
  creation; same-UID isolation is outside this local boundary.
- Exact tested identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; 92-file working-tree manifest
  SHA-256 `23993744335793f43ec05677106c69582311efb595ae63338cd3d9625be7374c`,
  excluding this self-report document. The manifest encoding is recorded in
  the earlier run record. The 49 Rust implementation and test files have
  SHA-256 `bcc43a35287f69db6c0a2988ad28aa76855cefa48c9c42d801b6ca29d1c9c114`.
  `Cargo.lock` SHA-256 is
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS 26.6.1 arm64; rustc and Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Results: the focused evaluator-replacement test passed. `pnpm run test:e2e`
  exited 0 with 78 tests passed and 0 failed across 13 targets; output SHA-256
  `de1dfc937195455800984603d92c54d5f457027e6a4c9b3df7e9fa3b171b234c`.
  `pnpm run lint` exited 0 with 191 tests passed and 0 failed across 22
  targets; formatting, build-contract digest verification, and warnings-denied
  Clippy passed. Its output SHA-256 is
  `6557b6ca890213f11ab0c121686329a98a7f35ec2ecfa3a99d374d08e441ddb3`.
- Assurance: `INTERNAL_PASS` for this exact local tree. Reviewer status: no
  independent signed decision was requested or used. Reproducibility status:
  no second-environment reproduction; this run is local to one Mac environment.
- Data and custody: local source and synthetic test inputs only; no external
  services or user data.
- Claim ceiling: local detection and quarantine of evaluator replacement
  before process launch, preserving the tested checkout bytes. This does not
  establish race-free executable identity, same-UID isolation, independent
  review, platform attestation, scientific validity, or production readiness.
- Next blocked authority gate: independently administered Linux reproduction,
  authenticated reviewer decision, platform attestation/custody validation,
  and separate deployment authorization remain external to this local slice.

## Follow-up supervisor launch identity

Run date: 2026-09-24. State slice: `security-alignment-os-foundation-v1`.

- Change: the broker now requires the configured supervisor to be a regular,
  non-symlink file and rechecks its digest immediately before each launch. A
  digest mismatch or unreadable/non-regular path rolls the authorized
  transaction back and freezes the broker before creating a child process.
- Regression coverage: an end-to-end broker test replaces the supervisor after
  broker startup and confirms the request is quarantined as
  `supervisor_identity_changed`, the source remains unchanged, and no output is
  created. The test also confirms a symlink supervisor path is rejected.
- Known limit: this is a path-based digest recheck, not an atomic executable
  handle. A same-UID actor may still race path resolution between recheck and
  OS process creation. Host identity, hostile same-UID resistance, and
  platform enforcement remain unestablished.
- Exact tested identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; 92-file working-tree manifest
  SHA-256 `134fd21dd02ce36fc339fc7ebd8708ec5fb6a999e8e03ce3edadf4483aec2ecb`,
  excluding this self-report document. The manifest encoding is recorded in
  the preceding section. The 49 Rust implementation and test files have
  SHA-256 `adb9856446d89139e8724aee38ae0567141b34b719dcb271e5c244bb45b682f2`.
  `Cargo.lock` SHA-256 is
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS 26.6.1 arm64; rustc and Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Results: the focused supervisor-replacement test passed. `pnpm run test:e2e`
  exited 0 with 77 tests passed and 0 failed across 13 targets; output SHA-256
  `f9f754b18f480ddb2fee9039c55a38d2dbb5e0c1027241775da3ee7adc475dec`.
  `pnpm run lint` exited 0 with 190 tests passed and 0 failed across 22
  targets; formatting, build-contract digest verification, and warnings-denied
  Clippy passed. Its output SHA-256 is
  `028e6fb46b07c4f6b7148ec15efaf86de4ecf36f0e455f0a722e33bc0f358ef7`.
- Assurance: `INTERNAL_PASS` for this exact local tree. Reviewer status: no
  independent signed decision was requested or used. Reproducibility status:
  no second-environment reproduction; this run is local to one Mac environment.
- Data and custody: local source and synthetic test inputs only; no external
  services or user data.
- Claim ceiling: local broker detection of supervisor path changes before
  process launch, with rollback and freeze on detected mismatch. This does not
  establish race-free executable identity, independent review, platform
  attestation, scientific validity, or production readiness.
- Next blocked authority gate: independently administered Linux reproduction,
  authenticated reviewer decision, platform attestation/custody validation,
  and separate deployment authorization remain external to this local slice.

## Follow-up replication executable identity V2

Run date: 2026-09-24. State slices: `security-alignment-os-foundation-v1`
and `maintenance-replication-executable-identity-v2`.

- Change: new V2 host reports and packets carry the maintenance broker
  executable SHA-256. The local runner rejects a non-regular, non-executable,
  symlinked, or changed broker path before every scenario launch. Packet
  validation requires both reports to bind the same broker digest. Signed V1
  reports and packets remain verifiable as legacy records without broker
  identity binding.
- Regression coverage: executable replacement and symlink paths fail the
  runner guard; broker digest tampering invalidates a signed report; reports
  with different broker digests cannot form a packet; the live 20-scenario
  runner records the launched broker digest; a V1 packet round-trips without
  the V2 field.
- Known limits: path-based checks retain a same-UID race between digest read
  and process creation. The report digest does not prove that executable bytes
  were built from the source revision label. Local signatures and caller
  labels do not authenticate separate operators, hosts, or evidence custody.
- Exact tested identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; 93-file working-tree manifest
  SHA-256 `20edb1998a12ff8d4f849dbf926743ea1097a2d71d93373656ad8cedad421449`,
  excluding this self-report document. The manifest encoding is recorded in
  the earlier run record. The 49 Rust implementation and test files have
  SHA-256 `02afc77c3e1707c9b8404c522859e916bbfadf610c3159b45f6ef36b8cc8c1a7`.
  `Cargo.lock` SHA-256 is
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS 26.6.1 arm64; rustc and Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Results: `pnpm run test:e2e` exited 0 with 81 tests passed and 0 failed
  across 13 targets; output SHA-256
  `c4fabfa07ad35e6c45ef8c1921420ad7f750eb53aad1cd49266c5a9b8ee5c59d`.
  `pnpm run lint` exited 0 with 195 tests passed and 0 failed across 22
  targets; formatting, build-contract digest verification, and warnings-denied
  Clippy passed. Its output SHA-256 is
  `23f6ab6d2b792f46fc6141f2d929ebc0e27d94973adda2ebe92c5151553cd1af`.
- Assurance: `INTERNAL_PASS` for this exact local tree. Reviewer status: no
  independent signed decision was requested or used. Reproducibility status:
  no second-environment reproduction; this run is local to one Mac environment.
- Data and custody: local source and synthetic scenario inputs only; no
  external services or user data.
- Claim ceiling: local signed wire-consistency evidence with V2 binding of the
  maintenance broker executable bytes across reports. This does not establish
  independent replication, build provenance, race-free executable identity,
  platform attestation, scientific validity, or production readiness.
- Next blocked authority gate: independently administered Linux reproduction,
  authenticated reviewer decision, platform attestation/custody validation,
  and separate deployment authorization remain external to this local slice.

## Follow-up hermetic platform runner integration

Run date: 2026-09-24. State slices: `security-alignment-os-foundation-v1`
and `maintenance-platform-runner-hermetic-e2e-v1`.

- Change: both platform runner entry points now call a workload function that
  the local E2E harness can invoke with isolated temporary paths and a synthetic
  attestation adapter. Each workload runs the actual local replication runner,
  broker, and evaluator, validates the signed canonical `HostReport`, then
  builds the corresponding envelope. The Confidential Space test exchanges an
  audience and report-bound nonce over a local Unix socket; the Nitro test
  checks report digest and nonce supplied to the synthetic NSM adapter. Both
  execute all 20 maintenance scenarios. While wiring this path, the test found
  that generic JSON decoding reordered report fields and rejected a valid
  canonical typed report. Both wrappers now parse, reserialize, and validate
  the `HostReport` type before building an envelope.
- Exact tested identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; 96-file working-tree manifest
  SHA-256
  `6deaefe607ea208ad31d4fa7e8eb49dfcddcbd417d2ea01831693b2523f9fb5e`,
  excluding this self-report document. The manifest includes sorted tracked
  and untracked nonignored files and, per path, its path length, relative path,
  permission mode, regular-file or symlink marker, payload length, and bytes.
  The 50 Rust implementation and test files have SHA-256
  `65604cb8535410b2d24c9f85d7d245d85a0b088d5f50f4acb772dc17007ee390`.
  `Cargo.lock` SHA-256 is
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS 26.6.1 arm64; rustc and Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Results: `pnpm run test:thesis` passed 41 tests; output SHA-256
  `72884e15e5867d7012e8c5f929be3087d53bf23d90ac0e22ec03636d5ee2c690`.
  `pnpm run test:e2e` passed 90 tests across its selected targets; output
  SHA-256
  `6837b9f5d5ef8c795cb060e9dd27cdbd914e3408d7a9a207d40778d3a78567f5`.
  `pnpm run lint` passed formatting, 204 all-target tests, contract-digest
  verification, and warnings-denied Clippy; output SHA-256
  `b26e40da177f87816d55a0379010852c6d487b5a294438d4f552bb2a338b2ffa`.
  `git diff --check` passed.
- Assurance: `INTERNAL_PASS` for this exact local tree. Reviewer status: no
  repository-specific independent reviewer or signed decision was used.
  Reproducibility status: no second-environment reproduction; the tests ran on
  this Mac only.
- Data and custody: locally built runner, broker, and evaluator binaries were
  copied into owner-only temporary test directories; report keys and reports
  remained in test-owned temporary directories. Attestation responses and NSM
  documents were synthetic. No cloud, enclave, provider, network, or production
  output service was invoked.
- Claim ceiling: local process wiring, signed-report validation, digest/nonce
  binding, and envelope construction for the two platform workload functions.
  The test does not authenticate GCP or Nitro, validate a protected output
  sink, establish independent operator or evidence custody, reproduce Linux,
  prove the scientific claim, or authorize production.
- Next blocked authority gate: independently operated Linux reproduction and
  authenticated evidence custody; repository-specific independent review;
  actual platform attestation with protected output; and separate deployment
  authorization. The scientific alignment claim remains closed.

## Follow-up Nitro image contract hardening

Run date: 2026-09-25. State slices: `security-alignment-os-foundation-v1`
and `maintenance-platform-runner-hermetic-e2e-v1`.

- Change: the Nitro Dockerfile now rejects a missing, malformed, uppercase, or
  non-hex `IMPLEMENTATION_REVISION` build value and retains the runner's
  expected binaries, unprivileged account, and entrypoint. A local policy test
  executes the exact Dockerfile revision-guard command with valid and invalid
  synthetic values. README and integration documentation now describe the
  workload-level tests accurately: they run local binaries with synthetic
  adapters, while not invoking platform attestation or building an image.
- Exact tested identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; 97-file working-tree manifest
  SHA-256
  `f8fa7f4f8e5aaf52c1cdd76de91f1a1ba552daf1454e63c90a2398367d991ab9`,
  excluding this self-report document. The manifest includes sorted tracked
  and untracked nonignored files and, per path, its path length, relative
  path, permission mode, regular-file or symlink marker, payload length, and
  bytes. The 51 Rust implementation and test files have SHA-256
  `72f650ac3aa4bd8b773927955794c258d3ecb6f880ad62afebe9a465b1e86aca`;
  `Cargo.lock` SHA-256 remains
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS 26.6.1 arm64; rustc and Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Results: the focused Nitro image-policy test passed 2 tests. `pnpm run
  test:thesis` passed 43 tests; output SHA-256
  `52bfbe516d031cc17e5df492f475b8496e8c90a82fa252e7b086b700e379cf59`.
  `pnpm run test:e2e` passed 92 tests, including local platform workload,
  fixed-scenario runner, packet, and release-reproducibility checks; output
  SHA-256 `273bba0012c904117058d7ab513563e3f9897a574baaaeeb15a998f1ccd8a6c9`.
  `pnpm run lint` passed formatting, all 206 direct all-target tests,
  build-contract digest verification, and warnings-denied Clippy; output
  SHA-256 `c3218fa8748b492e60398b7abd3d123e13451ac7b754a0e4fd3f70595c0ae64f`.
  `git diff --check` passed; no changes were staged or committed.
- Assurance: `INTERNAL_PASS` for this exact local working tree. Reviewer
  status: no independent reviewer or signed decision was used. Reproducibility
  status: this follow-up was not reproduced in a second environment.
- Data and custody: local source, synthetic test values, and local output only.
  No Docker image or EIF build, cloud service, Nitro NSM, Confidential Space,
  protected output sink, credential, or production workload was used.
- Claim ceiling: local process wiring with synthetic adapters and static plus
  shell-level Nitro Dockerfile revision and launch-contract evidence. The
  revision guard validates format, not provenance: it does not prove that a
  supplied revision names the bytes copied into an image. No platform
  attestation, host identity, independent custody, Linux production
  hardening, scientific alignment, or production authorization is established.
- Next blocked authority gate: independently operated Linux reproduction and
  authenticated evidence custody; validated platform attestation through a
  protected output path; repository-specific independent review; and separate
  deployment authority. These do not block further hermetic local work.

## Follow-up Nitro source identity and attestation binding

Run date: 2026-09-25. State slices: `security-alignment-os-foundation-v1`
and `maintenance-platform-runner-hermetic-e2e-v1`.

- Change: Nitro image builds now require a 40-character lowercase Git revision
  and a SHA-256 digest over the exact source inputs copied into the Docker
  build. The build script recomputes that digest before compilation and embeds
  both identity values at compile time. The runner rejects runtime identity
  overrides, requires the maintenance report revision to equal the embedded
  image revision, and binds the revision, report digest, and image source
  digest together in Nitro `user_data` and the returned envelope. The local
  workload test checks that changing the revision changes the attestation
  binding; unit coverage rejects a report/image revision mismatch. The identity
  command refuses this dirty checkout, as intended. No Docker image or EIF was
  built.
- Image source digest inputs: sorted regular files under `src`,
  `build_support`, and `infra/nitro-enclave`, plus `Cargo.toml`, `Cargo.lock`,
  and `build.rs`. The digest uses each path's big-endian 64-bit length and
  bytes, Unix permission mode (or fixed 0644 mode off Unix), `F` file marker,
  big-endian 64-bit content length, and file bytes. Symlinks and unsupported
  source inputs are rejected.
- Exact tested identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; 100 tracked and untracked
  nonignored files, excluding this self-report document, manifest SHA-256
  `1190b38adc3d6b6dc52fdb2a10eda358f3c2b380fd49e0ab27ac939818ab7c02`.
  The manifest uses the path, permission-mode, file/link-marker, and payload
  encoding recorded in the first run above. The 52 Rust implementation and
  test files have SHA-256
  `74c5ed87ff762ff405119e5e8c37d578810ecbd7221f4d6010e939d531733bb3`.
  `Cargo.lock` SHA-256 remains
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS 26.6.1 arm64; rustc and Cargo 1.87.0; pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`.
- Results: `pnpm run test:thesis` exited 0 with 50 direct tests passed across
  8 targets; output SHA-256
  `546e5bde789ed95af3cdfc1ecdcf4312f7ed688948167639d7af8bab92429554`.
  `pnpm run test:e2e` exited 0 with 99 direct tests passed across 15 targets;
  output SHA-256
  `dbe3b752fa6b32cd82686d86176ca5cc2ddf07d80eead90b090874695b8f22dc`.
  `pnpm run lint` exited 0 with 213 all-target tests passed; formatting,
  build-contract digest verification, and warnings-denied Clippy passed.
  Output SHA-256:
  `efc73bdab8d002568251ed26d8203fa67d5924449ab0593124daae22275b493e`.
  `git diff --check` passed. No changes were staged or committed.
- Assurance: `INTERNAL_PASS` for this exact local working tree. Reviewer status:
  no independent signed decision was requested or used. Reproducibility status:
  no second-environment reproduction; validation ran on this Mac only. An
  earlier E2E attempt during this work failed at broker IPC startup; targeted
  broker validation and the final full E2E run passed, but the first failure's
  cause was not established.
- Data and custody: only local source, synthetic fixtures, and local test
  output were used. No cloud service, Docker image build, EIF build, Nitro
  Secure Module, Confidential Space, external reviewer, protected output sink,
  credential, production workload, or real user data was used.
- Known limitations and claim ceiling: local build-script digest checking,
  compile-time identity embedding, report/envelope binding, and synthetic
  workload wiring only. A Git revision string paired with a source digest is
  not a signed build-provenance statement; no external quote verifier or
  platform attestation was exercised. Independent Linux reproduction,
  authenticated custody, repository-specific review, scientific alignment,
  and production authorization remain unestablished.
- Next blocked authority gate: independently operated Linux reproduction with
  authenticated custody, validated Nitro attestation through a protected
  output path, repository-specific independent review, and separate deployment
  authority. These do not block further hermetic local work.

## Follow-up canonical supervisor path and clean-copy reproduction

Run date: 2026-09-25. State slice: `security-alignment-os-foundation-v1`.

- Change: a fresh source copy with Cargo output under macOS `/var/folders`
  exposed that Seatbelt allowed the lexical supervisor path while `execvp`
  resolved it through `/private/var`, causing `Operation not permitted`. The
  broker now resolves the supervisor path at initialization, verifies the
  executable digest stayed the same across resolution, and stores the
  canonical path used by the Seatbelt rule and launch. A macOS E2E regression
  launches a supervisor through a symlinked parent while still rejecting a
  final executable symlink.
- Exact tested identity: base Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`; 100 tracked and untracked
  nonignored files, excluding this self-report document, manifest SHA-256
  `3aa0fc9ae69142f9c81568b354ae77264dd60d9635a4d5d937ada1a23a921bce`.
  The 52 Rust implementation and test files have SHA-256
  `2c41dd647e7a20f5cc10e442c22b1de983afce6f0e7bf0652b70e19d1e236bf8`.
  `Cargo.lock` SHA-256 remains
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: primary workspace and a clean local source snapshot, each on
  macOS 26.6.1 arm64 with rustc/Cargo 1.87.0 and pnpm 9.15.5;
  `CARGO_NET_OFFLINE=true`. The reproduction used a fresh Cargo target under
  `/var/folders`, matching the path class that exposed the failure. Synthetic
  test fixtures are inline. No dependency downloads occurred.
- Results in the primary workspace: `pnpm run test:thesis` passed 50 direct
  tests across 8 targets, output SHA-256
  `4a22bfede80e12a5ffb431846ef16ab611c43abaeb224a96cf09c5bf7786d440`.
  `pnpm run test:e2e` passed 100 direct tests across 15 targets, output
  SHA-256 `6feb4eeca96fadbd742dbd9ee0ed38c63f7f4bc67afed686927f0369ed27dced`.
  `pnpm run lint` passed 214 all-target tests, formatting, build-contract
  digest verification, and warnings-denied Clippy; output SHA-256
  `c1a3c4320a40a76699365024b109cbae8dd703762ce929c9547c5f5ee27b17eb`.
- Reproduced results from the clean sibling snapshot with a fresh target:
  thesis passed 50 tests, output SHA-256
  `c75b3dcd9a8b0d3bd71d08986fa0b70f4db8fbda0b4b74ca76c05471646bbd7c`;
  E2E passed 100 tests, output SHA-256
  `919a846eea1b0633903c5be286d6fc3590ee61e54aa23fae5aaee343032d9dcd`;
  lint passed 214 tests plus formatting, contract-digest verification, and
  Clippy, output SHA-256
  `57ec2a047ed2ccb94cb220fe3dc096501ab68b8aab2117ca1b330019eb3061f8`.
  Both E2E runs passed all 5 broker tests, including the symlinked-parent
  regression. `git diff --check` passed; no changes were staged or committed.
- Assurance: `INTERNAL_PASS` and `REPRODUCED_LOCAL` for this exact source
  manifest. The second run was same-owner and same-Mac; it is not independent
  review. No signed reviewer decision or separate-host reproduction was used.
- Data and custody: only local source, inline synthetic fixtures, and local
  logs were used. No provider, model, network service, TEE, cloud, real-user
  data, or production workload was involved. The clean-copy logs were retained
  under `/tmp/security-alignment-seatbelt-*-reproduced.log`.
- Claim ceiling and limitations: this establishes that the stated local
  integration and all-target checks reproduce from an exact source snapshot
  on one Mac, including macOS Seatbelt launch through a symlinked parent. It
  does not establish Linux sandbox behavior, independent host/operator
  custody, Nitro/GCP attestation, scientific alignment, or production
  authorization.
- Next blocked authority gate: none for continued hermetic local development.
  Linux Host B reproduction, protected platform attestation output,
  repository-specific independent review, and separate deployment authority
  remain open for the claims and operations that require them.

## Follow-up artifact-to-custody gate

Run date: 2026-09-25. State slice: `security-alignment-os-foundation-v1`.

- Exact implementation identity: Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`, plus the 100-file working-tree
  manifest SHA-256
  `8aac2dca9764d8892bf92c263ab4f20997368daae1248998d4f1e2469fae2ebe`.
  The manifest covers sorted tracked and unignored untracked paths, excluding
  this self-report. It hashes each 8-byte big-endian path length, relative path,
  4-byte mode, file/link marker, 8-byte payload length, and payload bytes. The
  52 Rust source/test files have SHA-256
  `c391bf38d4cedb2c555735e001812d9bc1f9fd6ce7bfcf51ae27c58d540230ba`;
  `Cargo.lock` SHA-256 is
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS arm64; rustc and Cargo 1.87.0; pnpm 9.15.5; Cargo ran
  offline with the already resolved lockfile dependencies.
- Results: `cargo test --test security_thesis_e2e` passed 9 tests.
  `pnpm run test:thesis` passed 51 direct tests across 8 targets, output
  SHA-256 `6f051f7ee98596432eef4516507373326e15a509ca50aae54bff6419824e9992`.
  `pnpm run test:e2e` passed 101 direct tests across 15 targets.
  Its output SHA-256 is
  `a68ab14d8730f936a4599b154855fa017d483c47c37f659e1802b7c05e6f5ef6`.
  `pnpm run lint` passed 217 all-target tests, Rust formatting, contract digest
  verification, and warnings-denied Clippy. The final `git diff --check` passed.
  Test logs are under `/tmp/security-alignment-custody-wiring-{thesis,e2e}.log`.
- Implemented behavior: `integration::run_with_artifact` requires an accepted
  artifact, then checks custody record ID, manifest root ID, exact subject
  digest, root validity, and the exclusive raw-retention deadline before
  evidence admission. Missing, deleted, expired, root-mismatched, or
  digest-mismatched custody returns quarantine with no admission or runtime
  mutation. The direct evidence-only `run` and receipt path do not require an
  artifact binding; this check applies when callers choose the artifact-bound
  workflow.
- Assurance: `INTERNAL_PASS` for this exact manifest. No clean second-environment
  reproduction was performed for this changed tree. The earlier same-Mac
  reproduction applies to a different manifest. Reviewer status: no independent
  review was performed and no signed decision was received.
- Data and custody: only local source, synthetic in-test custody records, and
  local filesystem test fixtures were used. No external artifact, real-user
  payload, provider, model, cloud, or production workload was involved.
- Known limitations and claim ceiling: custody identity, `0700` mode, and
  deletion remain caller assertions. The local check does not authenticate an
  owner, inspect or erase a filesystem, enforce physical retention, or prove
  external custody. The ceiling remains local Rust control behavior and
  caller-owned persistence evidence; this is not scientific alignment,
  production security, or deployment authorization evidence.
- Next blocked authority gate: none for continued hermetic local development.
  External custody verification, independent Linux reproduction, a signed
  repository-specific review, platform attestation validation, and separate
  deployment authorization remain open for higher-risk claims and actions.

## Follow-up composed artifact, custody, and receipt workflow

Run date: 2026-09-25. State slice: `security-alignment-os-foundation-v1`.

- Exact implementation identity: Git `HEAD`
  `72282b3d8ba6691b558b9090107c4eb2bce36e66`, plus the 100-file working-tree
  manifest SHA-256
  `34707ea8ecc05f7bf763d87a549b10dea251344185dd3f5888fe87dc3d513d7d`.
  The manifest covers sorted tracked and unignored untracked paths, excluding
  this self-report. It hashes each 8-byte big-endian path length, relative path,
  4-byte mode, file/link marker, 8-byte payload length, and payload bytes. The
  52 Rust source/test files have SHA-256
  `deac4f12e360f37285279c2848421e10a9ea97075ea064b0abcc9380aa6e100a`;
  `Cargo.lock` SHA-256 is
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
- Environment: macOS arm64; rustc and Cargo 1.87.0; pnpm 9.15.5; Cargo ran
  offline with the already resolved lockfile dependencies.
- Results: the focused `security_thesis_e2e` target passed 10 tests.
  `pnpm run test:thesis` passed 52 direct tests across 8 targets, output
  SHA-256 `710a5dd04475c86695641a9f9f275fa8bb92e54f5cdd59edd120146d284fdc49`.
  `pnpm run test:e2e` passed 102 direct tests across 15 targets, output
  SHA-256 `453bf51728825b2b1fe55e5a1f7a8d8004ae93d64e9aadec0a996b9a7dbe0e69`.
  `pnpm run lint` passed 218 all-target tests, formatting, contract digest
  verification, and warnings-denied Clippy; output SHA-256
  `82005c47b3abc55be77220fb484dda6697b17f7e6d9f0ce4c4dfad8d822d2b09`.
  `git diff --check` and `cargo fmt --all -- --check` passed. Logs are retained
  under `/tmp/security-alignment-combined-gates-{thesis,e2e,lint}.log`.
- Post-run tree note: after those suites completed, only
  `docs/architecture.md` and this self-report changed. The Rust source/test
  digest above remained unchanged; formatting and diff checks were rerun on the
  final working tree.
- Implemented behavior: `run_with_artifact_and_receipt` composes artifact and
  custody validation before admission, evidence and policy checks at admission,
  signed receipt verification before capability consumption, then the existing
  execution, rollback, and audit path. Its E2E test first supplies a mismatched
  root and verifies quarantine without admission, verifier consumption, or
  runtime mutation, then retries the same proposal and receipt with the correct
  custody binding and completes successfully.
- Assurance: `INTERNAL_PASS` for the recorded source/test digest and final
  working-tree manifest. No clean second-environment reproduction was performed
  for this tree. Reviewer status: no independent
  review was performed and no signed decision was received.
- Data and custody: local source, synthetic evidence, receipts and custody
  records, temporary test files, and local command logs only. No external
  artifact, real-user payload, provider, model, cloud, or production workload
  was involved.
- Known limitations and claim ceiling: identity, root mode, custody location,
  retention, and deletion remain caller-owned assertions. No owner is
  authenticated, no filesystem is inspected or erased, and no external custody
  is proved. The local assurance ceiling remains Rust control behavior and
  caller-owned persistence; it does not establish scientific alignment,
  production security, or deployment authorization. The artifact and custody
  checks are applied when this composed workflow is selected; the evidence-only
  and receipt-only workflow entry points remain available for workflows without
  an artifact binding.
- Next blocked authority gate: none for continued hermetic local development.
  Independent Linux reproduction, authenticated custody, a signed
  repository-specific review, platform attestation validation, and separate
  deployment authorization remain open for higher-risk claims and actions.

## Local artifact custody verification follow-up

Run date: 2026-09-25. State slice: `security-alignment-os-foundation-v1`.

- Exact target: Git `HEAD` `72282b3d8ba6691b558b9090107c4eb2bce36e66` on
  `codex/exploratory-adaptation-market-v1`, plus the 100-file working-tree
  manifest SHA-256
  `6f350e59cb080b8865d72c8778ac0d88665a625e168f380f89a419da94e8a435`.
  The manifest uses sorted paths from
  `git ls-files --cached --others --exclude-standard`, excluding this
  self-report document. Each record hashes an unsigned 64-bit big-endian path
  length, UTF-8 path bytes, four-byte big-endian permission mode, `F` for a
  regular file or `L` for a symlink, unsigned 64-bit big-endian payload length,
  and file bytes or symlink target bytes. No changes were staged or committed;
  the existing dirty tree was preserved.
- Rust source and test identity: 52 `src/**/*.rs` and `tests/**/*.rs` files,
  SHA-256
  `a301354f8d57ea037be71112eb0726594e553480b94bb8c05b6041e28c482134`;
  `Cargo.lock` SHA-256
  `81adebcf72d1354f881bc24993e12fe2586eb2453badf0cd2318ab6db10666dc`.
  Environment: macOS 26.6.1, arm64; rustc and Cargo 1.87.0; pnpm 9.15.5.
- Results on this tree: custody unit tests passed (8), the public security
  thesis E2E target passed (11), `pnpm run test:thesis` passed (53 tests),
  `pnpm run test:e2e` passed (103 tests), and `pnpm run lint` passed (222
  all-target tests, format, build-contract digest verification, and
  warnings-denied Clippy). Final command output SHA-256 values are `test:thesis`
  `953a77159f5b65774121a8b7a75fd651246909893854e53167f30de3763bab45`,
  `test:e2e`
  `f63aa45419ad38b1e581fdda7ef862aca9808a7655135ca537b5e26b2d817968`, and
  `lint` `cd7653872bb7c88f57da2b21a861c74db3693eb81b0153a56ef03255d00f06a5`.
  The logs are retained under `/tmp/security-alignment-local-custody-*-recorded.log`.
- Implemented path: `CustodyRegistry::verify_local_artifact` binds the
  manifest root ID and digest to the exact local file. It requires a real
  `0700` custody directory outside the caller-supplied repository anchor,
  checks a normalized relative path with no symlink components, requires a
  regular owner-readable file without group/other access or multiple hard
  links, enforces the caller's byte limit, and hashes the bounded file read.
  `integration::run_with_local_artifact_and_receipt` runs this check before
  admission and receipt verification. The E2E test rejects wrong bytes without
  admission, capability consumption, or runtime mutation, corrects the file,
  then completes using the same receipt. Adversarial cases cover traversal,
  root and artifact symlinks, root/repository overlap, hard links, broad modes,
  oversize files, and digest mismatch.
- Assurance: `INTERNAL_PASS` for the target and source/test digest above.
  Reviewer status: no independent reviewer was engaged and no signed decision
  was received; a repository-specific reviewer authority is not established.
  Reproducibility status: no second-environment reproduction was performed
  for this target. The same-host Linux container probe remains
  `INCONCLUSIVE`; the release byte-reproducibility test passing on this Mac is
  not a second-environment reproduction or independent review.
- Data and artifact custody: inline synthetic proposals, evidence, receipts,
  and registry records; temporary local files; and local `/tmp` test logs only.
  No real-user data, provider, model, external service, credential, hosted TEE,
  external transfer, or production workload was used.
- Known limitations and claim ceiling: the OS user, declared owner and
  validator are not authenticated; path anchor and byte limit are
  caller-supplied; retention metadata is not physically enforced and deletion
  is not performed. Path checks cannot prevent a same-user process from racing
  parent-directory or file changes. Existing artifact-and-receipt entry points
  retain logical custody checks; callers must select the new local-artifact
  entry point for this filesystem gate. The claim ceiling remains local Rust
  control behavior and caller-owned persistence evidence. No scientific
  alignment, production security, or deployment authorization is established.
- Next blocked authority gate: independent Linux reproduction with separate
  operator and evidence custody, a signed review for this repository, protected
  platform-attestation output validation, and separate deployment authority
  remain open for higher-risk claims and production actions. No external
  custody handoff was initiated by this local implementation run.

## Descriptor-relative local custody follow-up

Run date: 2026-09-27. State slice: `security-alignment-os-foundation-v1`.

- Exact target: Git `HEAD` `72282b3d8ba6691b558b9090107c4eb2bce36e66` on
  `codex/exploratory-adaptation-market-v1`, plus the 100-file working-tree
  manifest SHA-256
  `034a6240b15b50951b71e584ea7cca3f433dfab25baa697470f05113fd3b5422`.
  The sorted manifest covers tracked and non-ignored untracked paths, excluding
  this self-report document, and uses the record encoding described above. No
  changes were staged or committed; the existing dirty tree was preserved.
- Rust source and test identity: 52 `src/**/*.rs` and `tests/**/*.rs` files,
  SHA-256
  `965e63c197ffc38694afbf84c71d75895f1dd898f211621a9b6a623c1d36ab89`;
  `Cargo.lock` SHA-256
  `14f922d6a0ee38d5f7cf027642c309264686360369aff0de5fc408be17533a27`.
  Environment: macOS 26.6.1, arm64; rustc and Cargo 1.87.0; pnpm 9.15.5.
- Implemented path: under the same local-artifact integration gate, Unix path
  components are opened relative to already-open directory handles with
  symlink following disabled. The check validates the caller-supplied UID and
  private modes for the root, nested directories, and file; bounds the read;
  rejects hard links; hashes the opened file; and compares file identity and
  metadata before and after the read. Tests reject an incorrect UID and a
  symlinked intermediate directory. The exact-byte integration test still
  proves rejection occurs before admission or runtime mutation and that the
  same receipt completes after the file is corrected. Rustix 1.1.4 is pinned
  for Unix `openat`; its registry checksum and license are recorded in
  `docs/source-intake-v1.json`.
- Results: the focused custody filter passed 4 tests, and the focused public
  security-thesis E2E passed. `pnpm run test:thesis` passed 53 tests with log
  SHA-256 `65432d448219eb82b4ed5398eddbb5f21b73c31dbcb89988edb474290508115f`;
  `pnpm run test:e2e` passed 103 tests with log SHA-256
  `de6a6cf184a5e2753303a4dfc1a52e7a607eecc40a83ad12472b407b0c401be6`; and
  `pnpm run lint` passed 223 all-target tests, format, contract-digest
  verification, and warnings-denied Clippy with log SHA-256
  `8e26f0cfb388e4cee1f02a465be1ec20292aa600d993f68398149c17b4832dcc`.
  Logs are retained under `/tmp/security-alignment-custody-descriptor-*.log`.
- Assurance: `INTERNAL_PASS` for this exact local Mac tree and the stated
  checks. Reviewer status: no independent reviewer was engaged and no signed
  decision was received. Reproducibility status: no second-environment run was
  performed; the same-host Linux container remains `INCONCLUSIVE` for
  reproduction requiring a Linux host environment.
- Data and artifact custody: synthetic test bytes, temporary local custody
  roots, and local `/tmp` command logs. No production traffic, external
  transfer, provider, model, credential, hosted TEE, real-user payload, or
  deployment action was used.
- Known limitations and claim ceiling: expected UID, repository anchor, and
  byte budget are supplied by the caller; the check does not authenticate the
  declared owner-to-UID mapping. Descriptor-relative opens protect the walk
  from symlink redirection and pin the opened inode, but a same-UID process can
  alter or replace its own filesystem state before the check. The metadata
  comparison detects ordinary changes observed during the bounded read; it is
  not a proof against a hostile same-UID process or every filesystem's
  timestamp semantics. Non-Unix builds return an unsupported result. No
  independent Linux reproduction, scientific alignment claim, hosted
  enforcement, or production readiness is established.
- Next blocked authority gate: independent Linux reproduction with separate
  operator and evidence custody, a repository-specific signed review, protected
  platform-attestation output validation, and separate deployment
  authorization remain open for higher-risk claims and actions. No external
  custody handoff was initiated.

## Process effective-UID custody follow-up

Run date: 2026-09-27. State slice: `security-alignment-os-foundation-v1`.

- Exact target: Git `HEAD` `72282b3d8ba6691b558b9090107c4eb2bce36e66` on
  `codex/exploratory-adaptation-market-v1`, plus the 100-file working-tree
  manifest SHA-256
  `837187edd7bd4acd898a94206bc5f3980d582611f41883074bb54538bf308b28`.
  It covers sorted tracked and non-ignored untracked paths, excluding this
  self-report document, using the manifest encoding described earlier. No
  changes were staged or committed; the existing dirty tree was preserved.
- Rust source and test identity: 52 `src/**/*.rs` and `tests/**/*.rs` files,
  SHA-256
  `95ecafa7266e49a4ef9f7f7c066ab6a76aba9d928010f77752fc40cc5d78c5da`;
  `Cargo.lock` SHA-256
  `14f922d6a0ee38d5f7cf027642c309264686360369aff0de5fc408be17533a27`.
  Environment: macOS 26.6.1, arm64; rustc and Cargo 1.87.0; pnpm 9.15.5.
- Implemented path: the local custody API no longer accepts a caller-selected
  expected UID. On Unix it gets the process effective UID through pinned Rustix
  1.1.4 `process::geteuid`, then requires the custody root, nested directories,
  and artifact to have that UID. `LocalCustodyPaths` now contains only transient
  path anchors and the byte limit. The direct dependency's version, checksum,
  license, and lockfile digest are recorded in `docs/source-intake-v1.json`.
- Results: all 9 custody unit tests passed; the focused public security-thesis
  E2E passed. `pnpm run test:thesis` passed 53 tests with log SHA-256
  `78c0df734968ab76c99b62c90116a8dadd369b1d214d4e21c9ec36d5ea7e5304`;
  `pnpm run test:e2e` passed 103 tests with log SHA-256
  `b008caf6f2aaf10a3350d7b6e5217099c5a881b918042b78043c37714492da9e`; and
  `pnpm run lint` passed 223 all-target tests, format, contract-digest
  verification, and warnings-denied Clippy with log SHA-256
  `422b9bef12c7b39c99c0300298b54a7307767e686ee6aefe3e6912196de3f4b2`.
  `cargo check --all-targets --target x86_64-unknown-linux-gnu --locked
  --offline` also passed as a compile-only check using rustc/Cargo 1.93.1 and
  the installed Rustup Linux standard library; its log SHA-256 is
  `41ab6f4ca2c533a124e9f25a1f5803cc8e0252d62356882aeb079235d6ea4ea2`.
  The first cross-check attempts selected Homebrew rustc 1.87.0 from `PATH`,
  which lacks Linux `core`/`std`; setting `RUSTC` to the Rustup compiler fixed
  the invocation. No Linux binary was executed. Logs are retained under
  `/tmp/security-alignment-effective-uid-*.log`.
- Assurance: `INTERNAL_PASS` for this exact local Mac tree and listed checks.
  Reviewer status: no independent reviewer was engaged and no signed decision
  was received. Reproducibility status: no second-environment run was
  performed; the same-host Linux container remains `INCONCLUSIVE` for Host B
  reproduction.
- Data and artifact custody: synthetic test bytes, temporary local custody
  roots, and local `/tmp` logs. No production traffic, external transfer,
  provider, model, credential, hosted TEE, real-user payload, or deployment
  action was used.
- Known limitations and claim ceiling: filesystem ownership is checked against
  the process effective UID, but that UID is not mapped to the repository's
  declared owner identity. A same-UID process can change filesystem state
  before the check; metadata comparison only detects ordinary changes observed
  during the read. Path anchor and byte limit remain caller-supplied. Non-Unix
  builds return unsupported. No independent Linux reproduction, scientific
  alignment claim, hosted enforcement, or production readiness is established.
- Next blocked authority gate: independent Linux reproduction with separate
  operator and evidence custody, a repository-specific signed review, protected
  platform-attestation output validation, and separate deployment
  authorization remain open for higher-risk claims and actions. No external
  custody handoff was initiated.

## Same-UID mutation-during-read regression follow-up

Run date: 2026-09-28. State slice: `security-alignment-os-foundation-v1`.

- Exact target: Git `HEAD` `72282b3d8ba6691b558b9090107c4eb2bce36e66` on
  `codex/exploratory-adaptation-market-v1`, plus a 100-file working-tree
  manifest SHA-256
  `734c9e3e0f87a0b0e6437cf4aecbe89baf4eeb7376989a4f41edd109e1546718`.
  The manifest covers sorted tracked and non-ignored untracked files,
  excluding this self-report; each record hashes 8-byte big-endian path length,
  path bytes, 4-byte mode, file/link marker, 8-byte payload length, and payload.
  Rust source/test identity: 52 files, SHA-256
  `9db3a0d0889a3716aee3fdcac878bfcfffbd33c3f8a8d306b64686c8239da062`;
  `Cargo.lock` SHA-256 `14f922d6a0ee38d5f7cf027642c309264686360369aff0de5fc408be17533a27`.
  Environment: macOS 26.6.1 arm64, rustc/Cargo 1.87.0, pnpm 9.15.5. This
  follow-up preserves the pre-existing dirty and untracked files; no changes
  were staged or committed.
- Implemented path: extracted the opened-file verification into a generic
  private reader helper so the test can deterministically change bytes on the
  opened inode after its initial metadata snapshot and before reading. The
  regression replaces a synthetic artifact's bytes in place during the first
  read, checks that verification rejects specifically with `artifact changed
  while it was read`, then restores and checks the original fixture bytes.
  This exercises the metadata-fingerprint branch before digest comparison; it
  does not model every filesystem or a hostile same-UID process.
- Results: all 10 custody unit tests passed. `pnpm run test:thesis` passed 55
  tests across its selected targets with output SHA-256
  `4b5d3ff828f506109a7af98b04a9ac59673c9e9bd0f92bdad4426e46a030b1c4`;
  `pnpm run test:e2e` passed 105 tests across its selected targets with output
  SHA-256
  `bf6f803463d2b54f6fbfe74030c471d66204e6b1eb9c667e5d56b8ff0e766754`; and
  `pnpm run lint` passed 226 all-target tests, formatting, contract-digest
  verification, and warnings-denied Clippy with output SHA-256
  `316e28d0c4682bbc8d8ff0014b4cbbcbdee56596225d7b2e85bc2d1ce19e756f`.
  The Linux `x86_64-unknown-linux-gnu` all-target compile check also passed
  offline with Rustup rustc/Cargo 1.93.1; its output SHA-256 is
  `339648c4d273409eafdc14801fd4deea674e037dd584eb826700b7ce2688d01a`.
  This compiled the target only; no Linux binary was executed. Logs are
  retained under `/tmp/security-alignment-midread-*.log`.
- Assurance: `INTERNAL_PASS` for the current local Mac tree and listed checks.
  Reviewer status: no independent reviewer was engaged and no signed decision
  was received. Reproducibility status: no second-environment run was
  performed; the Linux target check is compile-only and does not establish
  Linux execution or Host B reproduction.
- Data and artifact custody: synthetic test bytes and a temporary local
  artifact restored by the test; test output logs are in local `/tmp`. No
  external transfer, production traffic, provider, model, credential, hosted
  TEE, real-user payload, or deployment action was used.
- Known limitations and claim ceiling: ownership is checked against the
  process effective UID, but that UID is not mapped to the repository's
  declared owner identity. The repository anchor and byte limit remain
  caller-supplied. Descriptor-relative opens and the metadata comparison reject
  the tested path and ordinary in-read mutation, but do not prove resistance to
  hostile same-UID changes or timestamp behavior on all filesystems. Non-Unix
  builds return unsupported. This supersedes the earlier recorded limitation
  that expected UID was caller-supplied. No independent Linux reproduction,
  scientific alignment claim, hosted enforcement, or production readiness is
  established.
- Next blocked authority gate: independent Linux reproduction with separate
  operator and evidence custody, a repository-specific signed review, protected
  platform-attestation output validation, and separate deployment
  authorization remain open for higher-risk claims and actions. No external
  custody handoff was initiated.
