---
title: Upstream patch register
description: Fork patches, their acceptance contracts, and the workflow for replaying or retiring them after Lore upstream changes.
---

# Upstream patch register

This register tracks the patches maintained on `aidonia/main` relative to local `main`. Use it when updating the fork from Lore upstream, rebuilding the patch series, or deciding whether an upstream implementation replaces a local change.

## Recorded comparison

| Item | Recorded value |
| --- | --- |
| Review date | 2026-10-16 |
| Upstream project | [EpicGames/lore](https://github.com/EpicGames/lore) |
| Fork | [Laurelianae/lore](https://github.com/Laurelianae/lore), branch `aidonia/main` |
| Baseline | Upstream `5c88e6e7528a12b74ab3e1621b5d7c540a5d1606` (merged head; contains the previously verified `c094c64ebf9560f62065b988bd3227d6c846912b`) |
| Fork revision | `48d9aed45c6bef2de30b3096fe1e2f346f64a32f` plus the tests commit `e5da4fa` and this register update |
| Comparison | Thirty-three series commits plus the merge; 129 changed files; 8,886 insertions and 1,097 deletions versus `5c88e6e` |
| Upstream freshness | Verified via `ls-remote`: `EpicGames/lore@main` = `5c88e6e` on 2026-10-16. The revision had been pulled into the fork's local `main` and `origin/main` before the review; the check confirmed it was still upstream's head, so the merge landed the exact revision pulled. |

The 2026-10-08 review recorded `491a7ed75c9b0dac7de50ada6d2a9c38f3cbc046` as baseline with fork revision `4bfa0ec058d08ba9c2aa7abb783d7299c9829820` (nine commits; 86 files; 5,306 insertions and 513 deletions) and could not reach the network. Its values are superseded by the table above; the narrative below is retained as provenance.

The configured remote is the fork, `origin`; there is no configured `upstream` remote. Local `main` and `origin/main` pointed to the same baseline during that review. This establishes the local comparison, not whether upstream has since incorporated any of these patches. The working tree was clean before that documentation change.

[Upstream PR #49](https://github.com/EpicGames/lore/pull/49) is a comparison lead already recorded in the [server authorization configuration](../reference/lore-server-config.md). Its current status, merge commit, and behavioral equivalence are unverified. Do not mark a patch retired merely because that PR exists or touches similar code.

## Reconciliation 2026-10-16

**Landing strategy.** Upstream was landed as a merge, not a replay: `git merge 5c88e6e` on review branch `codex/upstream-patch-review-20261016`, producing merge commit `7f44d24`, with five follow-up commits (two re-lands, the access-token credential rule, and two test adaptations) completing the gate. The merge keeps `origin/aidonia/main` an ancestor of the new tip, so the push is an ordinary fast-forward and the retained patches' original SHAs stay valid.

**Retirement review.** All thirteen patches were screened against `5c88e6e` with the register's marker checks and per-patch contracts. Upstream's four OIDC client commits — `33b1f62` (auth-path selection), `21c2bd1` (device grant), `228762f` (D5 derivation), `8b73077` (RFC 8693 partition exchange) — replace LP-011 and LP-012, and upstream's resolved-auth rework replaces LP-008. Ten patches remain Active; three retire, two of them with a residual re-landed on upstream's backend.

**Conflict resolution.** Git auto-merged most files. The OIDC client area (`connection.rs`, `auth/mod.rs`, `oidc/*`, `login.rs`, `jwt.rs`, `Cargo.toml`) was resolved wholesale in favor of upstream's implementation, dropping `1526c6c`'s content and its `oidc/backend.rs` structure; LP-013's revocation was re-landed onto the new layout as `a8d07fa`, and the refresh grant plus the api-key mapping as `482c038`. Verified against the acceptance contracts in the auto-merged zones: LP-009's `SessionAuthorization` expiry/replay lifecycle kept through upstream's stale-session rebind (`bind_session`/`StaleSession`), with `AuthorizationExpired` kept non-recoverable in `send_with_reconnect` and mapped to `NotAuthenticated` in the storage client's `map_send_error` (the auto-merge had dropped the latter arm); LP-007's supplied-access-token precedence kept in the storage client's `issue()` for servers that advertise no auth endpoint, where upstream sends an empty token; LP-006's read/write gates and LP-002/LP-004's authorizer consultations intact. `GRPCAuth::new`'s refresher and `for_partition` replaced LP-008's per-request interceptor; the fork's wire-level `repository_client.rs` test file, which tested the retired interceptor, was dropped in favor of upstream's exchange, select, and connection-rotation coverage. The duplicate `oidc_provider` test module the merge produced was collapsed (`d737698`).

**Adopted upstream behavior changes.**

- `8b73077` makes a repository lookup (`RepositoryGet`) reachable for any verified token on resource-grant servers (`check_repository_lookup`): the client must name a repository before it can exchange for a token granting it, and the record discloses only the id, name, and metadata hash. `test_read_write_matrix` now asserts lookup per tier, keeping the HTTP content probes as the read/write gates. The claims and legacy tiers still gate the lookup on read. **Fork delta:** the resource-grant tier deliberately diverges — a follow-up patch re-gated the lookup on a read-like grant, restoring the pre-merge Tier 2 behavior (LP-014 below).
- A supplied access token is now the authentication credential itself on claim-based endpoints (no advertised auth server, or the OIDC path), per LP-008's precedence; on a legacy auth-service endpoint the identity token remains the RPC credential, with a scoped access token serving the uploads (`d42b015`). `auth_exchange` and `auth_exchange_custom_resource` short-circuit on it, so repository creation and the repository RPCs authorize from a token the caller supplied even without a stored login. The token-store `load_user_token` contract is unchanged.
- The refresh wiring and the logout revocation now take the endpoint's carried implementation instead of `authentication::find`, which can never resolve an OIDC backend (it is bound per selection, not registered under a scheme).
- An explicit `--auth-url` naming an `oidc+` issuer resolves through the registry and fails there, instead of the fork's refusal message; upstream's error shape stands.

**Validation (executed 2026-10-16, on the review branch).**

- `cargo build --release`, `cargo +nightly fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings --no-deps`: all clean.
- `cargo test --workspace`: 4,758 passed, 0 failed (after the re-lands; re-verified below).
- `cargo build -p lore-capi`: clean; `cargo test --locked -p lore-integration-tests --features integration_tests --no-run`: passed. The Compose services were not run (no AWS environment in this sandbox), recorded as a limitation per §Reconcile step 7.
- Focused regressions: `cargo test -p lore-server --test unit quic::` 77 passed, `authnz::` 68 passed, `grpc::` 450 passed; `cargo test -p lore-transport` 240 passed; `cargo test -p lore-credential` 36 passed.
- Smoke (release binaries): `uv run pytest scripts/test/test_repository_permissions.py` — 96 passed, 45 skipped (matches the LP-008 recorded counts); `uv run pytest scripts/test/test_auth_oidc.py` — 14 passed (upstream's nine plus the fork's device-grant, Tier 1, refresh-renewal, logout-revocation, and Tier 2 exchange suites); `uv run pytest scripts/test/ -m smoke` — 1,349 passed, 0 failed, 83 skipped, 24 deselected. The seven smoke failures recorded in 2026-10-13 no longer reproduce: upstream fixed them between `c094c64` and `5c88e6e`.
- `pre-commit run --all-files`: all hooks passed, including the GitHub Actions workflow lint that could not run in 2026-10-13's sandbox.

**Future comparisons** should use `git diff 5c88e6e <fork-tip>` — or the then-current merge-base — rather than the retired `c094c64` baseline, and keep this section's marker checks (§ above) as the retirement screen.

## Reconciliation 2026-10-13

**Landing strategy.** Upstream was landed as a merge, not a replay: `git merge c094c64` on review branch `codex/upstream-patch-review-20261013`, producing merge commit `9e7966fd6a6fdc4e77629ba6a26bdb6aea7e1510` (“Merge upstream main c094c64 into aidonia patch series”), then fast-forwarded onto `aidonia/main` and pushed as an ordinary push. A merge was chosen over cherry-pick/replay because this fork syncs repeatedly: merges keep `origin/aidonia/main` an ancestor of every future tip, preserve the original patch commit SHAs below (provenance stays valid), and accumulate conflict resolutions. `db1b7c3` had been fast-forwarded into `origin/main` on 2026-10-13; the live `ls-remote` then showed upstream at `c094c64` (two commits ahead: `0595e60` docs, `c094c64` lore-revision progress counting), and the newer head was merged instead. The two extra commits touch `lore-revision/src/commit.rs`, its unit tests, and docs, none of which the series modifies.

**Retirement review.** All ten patches remain **Active** with their original commit SHAs; no replayed-SHA mapping is needed. Marker checks against `c094c64` found no fork behavior upstream: no `push-protected` in `lore-server/src`, no `AuthorizationExpired` in `lore-transport`, no access-token selection in `lore-transport/src/grpc/repository_client.rs`, while the pre-fork behavior is intact (`is_service_account` bypass in both push/delete handlers, `can_obliterate` in `lore-server/src/grpc/mod.rs` and `handlers/obliterate.rs`, “Only service accounts may vend presigned URLs” in the presign handler). [PR #49](https://github.com/EpicGames/lore/pull/49) remains open with the maintainer’s 2026-07-07 comment deferring granular permissions to a future authn/authz overhaul. Upstream added `auth_mode` (commit `7c04530`) — an orthogonal gRPC-vs-OIDC auth *path* selector (`lore-revision/src/auth/mode.rs`, resolved in `lore-client/src/cli/cli.rs`); it introduces no credential source, so LP-008’s precedence (supplied access token → supplied identity token → stored auth token) was left untouched.

**Conflict resolution.** Git auto-merged all but four files; each auto-merge was verified against the acceptance contracts (store-request metrics from `0f99022` coexist with the LP-001 gate in `branch_push.rs`; `[profile.release-lto]` kept beside upstream’s `[workspace.lints]`; `pub(super)` authorization clocks in both QUIC storage services; `ParallelChunking` wired around the expiry admission checks; token precedence kept in `lore-transport/src/grpc/mod.rs`). Resolved conflicts: `lore-transport/src/session.rs` — upstream’s pooled-session turn plumbing (`with_resolved(turn, …)`, `project_current`, `resolve_pending`, `AtomicBool` pool staleness) adapted around the fork’s `SessionAuthorization` replay lifecycle, whose `Drop` remains the sole `session_stop` owner; `lore-revision/src/immutable.rs` — fork’s authorization-error forwarding kept against upstream’s internal-error wrapping; `lore-transport/tests/unit/session.rs` — fork’s `expiry_recovery` tests unioned with upstream’s `pooled` tests; `docs/reference/lore-cli-commands.md` — regenerated to match the merged `lore-client/src/cli/cli.rs` and `commands/repository.rs` help text. Two mechanical lint fixes completed the gate: collapsed identical match arms in the merged `Drop` and `Box::pin` for a `large_futures` warning in upstream’s new `cache_tests.rs` under upstream’s own `[workspace.lints]`.

**Validation (executed 2026-10-13, on the review branch).**

- `cargo build --release`, `cargo +nightly fmt --all --check`, `cargo clippy --all-targets -- -D warnings --no-deps`: all clean (after the two lint fixes above).
- `cargo test --workspace`: green; three `lore --test unit remote::network` tests fail only in this sandbox (`/run/user/1000` is a read-only filesystem) and pass with `XDG_RUNTIME_DIR` pointed at a writable directory.
- LP-009 build compatibility: `cargo test --locked -p lore-integration-tests --features integration_tests --no-run` passed standalone. The Compose services were not run (no AWS environment available in this sandbox), so the full integration suite was not executed — recorded as a limitation per §Reconcile step 7.
- Focused regressions: `cargo test -p lore-server --test unit quic::` 77 passed, `authnz::` 67 passed, `grpc::` 450 passed, `cargo test -p lore-transport` 173 passed.
- Smoke (release binaries): `uv run pytest scripts/test/test_repository_permissions.py` — 96 passed, 45 skipped (matches the LP-008 recorded counts); `uv run pytest scripts/test/ -m smoke` — 1,282 passed, 7 failed, 83 skipped, 22 deselected. The 7 failures (`test_merge_restart`, `test_lock_query` owner-name resolution, `test_search_nearest_layer_metadata`, and four `scripts/test/link/` tests) were reproduced on **both** the pure fork `e0eb83a` and pure upstream `c094c64` in isolated worktrees — they pre-date this reconciliation on both sides and are not merge regressions. The four link tests are upstream-new and fail on upstream itself.
- `pre-commit run --all-files`: 17 hooks passed. `actionlint` could not run: its golang hook environment cannot fetch modules because the sandbox proxy forbids `proxy.golang.org`, `golang.org`, `gopkg.in`, and mirrors.

**Future comparisons** should use `git diff c094c64 <fork-tip>` — or the then-current merge-base — rather than the retired `491a7ed` baseline, and keep this section’s marker checks (§ above) as the retirement screen.

## Patch inventory

IDs remain stable through rebases, splits, and retirement. The table is in replay order. “Active” means present beyond the recorded local baseline; it does not assert absence from live upstream. Dependencies describe supporting behavior and overlapping edits, not a guarantee that an isolated cherry-pick will apply.

| ID | Commit | Purpose | Dependencies and overlaps | Status |
| --- | --- | --- | --- | --- |
| LP-001 | [c982cdf](https://github.com/Laurelianae/lore/commit/c982cdf18724d876115f70b1331bbca3f0282083) | Explicit protected-push permission | LP-005 adjusts tests; LP-006 adds baseline read/write enforcement | Active |
| LP-002 | [e3fe945](https://github.com/Laurelianae/lore/commit/e3fe945b231ef56c8f37a3707aa99bfc911fab64) | Owner/admin deletion bypass | LP-005 adjusts tests; LP-006 adds ordinary write requirement | Active |
| LP-003 | [7cac15f](https://github.com/Laurelianae/lore/commit/7cac15fc71a746c6bc9e6444bb3de7a0f061cbdb) | Explicit presign permission | LP-005 adjusts tests; LP-006 changes baseline reachability | Active |
| LP-004 | [4298dcc](https://github.com/Laurelianae/lore/commit/4298dcc6910ce6d5e1e0269efbcd0b1d6daf1e06) | Configured-authorizer obliteration | LP-005 adjusts tests; LP-006 changes baseline reachability | Active |
| LP-005 | [b25e641](https://github.com/Laurelianae/lore/commit/b25e6410fb0fcb8fa6c5b96ea16c58e2ade7e071) | Permission-matrix test cleanup | Supporting work for LP-001 through LP-004 | Supporting |
| LP-006 | [74f99b9](https://github.com/Laurelianae/lore/commit/74f99b9dde16fee134884a781df7cdc348bd1e5c) | Read/write enforcement across transports | Layers onto LP-001 through LP-005; adds smoke infrastructure used by LP-007 and LP-008 | Active |
| LP-007 | [ca0b042](https://github.com/Laurelianae/lore/commit/ca0b04201cd9350b419ecb5120e9d7ac00595012) | Supplied access tokens in QUIC sessions | Extends LP-006 smoke coverage; same storage client later changed by LP-009 | Active |
| LP-008 | [e799c84](https://github.com/Laurelianae/lore/commit/e799c84368a25a43f98d8ccad0c0e95f5f9a5700) | Scoped tokens for repository RPCs | Extends LP-006 smoke coverage; complements LP-007 | Retired 2026-10-16 |
| LP-009 | [4bfa0ec](https://github.com/Laurelianae/lore/commit/4bfa0ec058d08ba9c2aa7abb783d7299c9829820) | Cached QUIC authorization expiry and recovery | Uses LP-006 cached grants and LP-007 current-token selection | Active |
| LP-010 | [eabb070](https://github.com/Laurelianae/lore/commit/eabb0702aa04b08861e60008b4cd8dc1921df1cc) | Portable Docker builds and fork release delivery | Reuses the portable ARM baseline, version stamping, and notices generation | Active |
| LP-011 | [1526c6c](https://github.com/Laurelianae/lore/commit/1526c6c24f63e0d3081578626dfe2f777e041f07) | Client OIDC device grant, refresh, and auth-path dispatch | Builds on the D5 claim reading also recorded by LP-012; adds the `AuthMode` plumbing the connect bridge forwards | Retired 2026-10-16, refresh re-landed |
| LP-012 | [1526c6c](https://github.com/Laurelianae/lore/commit/1526c6c24f63e0d3081578626dfe2f777e041f07) | RFC 8693 token exchange and external-token login | Layers onto LP-011's backend and D5 derivation | Retired 2026-10-16, api-key login re-landed |
| LP-013 | [5534934](https://github.com/Laurelianae/lore/commit/5534934c564d37341ff8e244a31ce6293937517e) | RFC 7009 token revocation on `lore auth logout` | Extends LP-011's backend and per-URL registry | Active, re-landed 2026-10-16 |
| LP-014 | This commit (the follow-up to the 2026-10-16 merge) | Read-gated repository lookup on resource-grant servers | Restores LP-006's read gate for `RepositoryGet`/`RepositoryQuery` after `8b73077` opened it | Active |

## Patch details and acceptance contracts

Paths below are relative to the repository root through links from this page. The final behavior includes later patches in the inventory. Keep the current regression assertions when replacing an earlier commit.

### LP-001: Protected pushes

**Before:** Both legacy and v1 branch-push handlers used `is_service_account` to bypass branch protection.

**Current:** Bypass requires the configured authorizer's explicit `push-protected` action. With LP-006, ordinary write access is also required. Neither service-account identity nor `admin`/`owner` alone grants the bypass. Unauthenticated servers still deny protected pushes.

**Code and regressions:** [Legacy handler](../../lore-server/src/grpc/handlers/branch_push.rs), [v1 handler](../../lore-server/src/grpc/revision/v1/branch_push.rs), and [push tests](../../lore-server/tests/unit/grpc/revision/v1/branch_push.rs), particularly `explicit_permission_bypasses_protection` and `protected_push_permission_matrix`. The commit also wires the authorizer through both revision services and server construction.

**Compatibility:** Grant `push-protected` explicitly to mirroring accounts before deployment, together with a write-like grant.

**Retire when:** Upstream enforces the same configured-authorizer decision on both handler paths and passes allowed/denied permission cases, including service-account-only denial and unauthenticated denial. Preserve LP-006's write gate if upstream replaces only the bypass check.

### LP-002: Repository deletion bypass

**Before:** Service accounts could bypass the creator check when deleting a repository without a legacy auth endpoint.

**Current:** Without `auth_url`, bypass requires `owner` or `admin`; other callers must satisfy the creator check. LP-006 additionally requires ordinary write permission. With `auth_url`, the external `DeleteResource` authorization remains authoritative. Unauthenticated deletion retains the creator check.

**Code and regressions:** [Legacy deletion handler](../../lore-server/src/grpc/handlers/repository_delete.rs), [v1 deletion handler](../../lore-server/src/grpc/repository/v1/repository_delete.rs), and [deletion tests](../../lore-server/tests/unit/grpc/repository/v1/repository_delete.rs). Acceptance includes `repository_delete_permission_matrix`, `the_creator_check_compares_the_identity_claim`, and `legacy_repository_delete_denial_preserves_repository`. Both services receive the authorizer; handlers obtain repository-scoped grants before deciding on bypass.

**Compatibility:** Service accounts need an explicit elevated grant to bypass ownership. A creator with only `read` cannot delete. Do not replace external deletion authorization with a local elevated-role shortcut.

**Retire when:** Both upstream deletion paths meet the creator, owner/admin, ordinary-write, and external-denial contracts, including preservation of repository state on denial.

### LP-003: Presigned content URLs

**Before:** Authenticated URL vending required service-account identity.

**Current:** The HTTP handler requires explicit `presign` permission through matching cached grants or the configured authorizer. LP-006 also requires baseline repository read access. Missing permission returns HTTP 403. Existing unauthenticated presign behavior remains available when configured.

**Code and regressions:** [Presign handler](../../lore-server/src/http/repositories/repository/contents/content/presign_repository_content.rs) and [presign tests](../../lore-server/tests/unit/http/repositories/repository/contents/content/presign_repository_content.rs), including `presign_permission_matrix`. The handler's error and response text now describe permission denial rather than service-account status.

**Compatibility:** URL-vending accounts need `presign` plus a read-like grant. Service-account status and elevated ordinary roles do not imply this action.

**Retire when:** Upstream supports the configured authorization tiers and cached-grant path, denies service-account-only and wrong-resource requests, and preserves configured unauthenticated behavior.

### LP-004: Obliteration

**Before:** A dedicated `can_obliterate` helper inspected token resource claims rather than consulting the configured repository authorizer.

**Current:** The admin service supplies the authorizer. The handler verifies the bearer token, preserves its raw token and claims, obtains repository grants, and requires explicit `obliterate` permission before hooks or deletion. LP-006 makes baseline read access necessary. The existing no-authentication path remains unchanged.

**Code and regressions:** [Obliteration handler](../../lore-server/src/grpc/handlers/obliterate.rs), [admin service](../../lore-server/src/grpc/admin_service.rs), and [obliteration tests](../../lore-server/tests/unit/grpc/handlers/obliterate.rs), especially `obliterate_permission_matrix` and `expired_token_cannot_obliterate`. The old helper is removed from the gRPC module.

**Compatibility:** Issuers must supply `obliterate` and a read-like grant through the deployment's configured authorization model. An `admin` or `owner` grant alone is insufficient.

**Retire when:** Upstream verifies fresh credentials and consults the configured authorizer across supported tiers, with denied/expired requests leaving hooks and storage untouched.

### LP-005: Permission-test cleanup

**Before:** The four new permission matrices contained statement/style issues and the legacy deletion test used a direct Tokio spawn.

**Current:** Missing semicolons are added, contiguous match alternatives use ranges, and the test server uses `lore_spawn!`. No application behavior changes.

**Code and regressions:** This commit changes only the push, deletion, presign, and obliteration test files linked under LP-001 through LP-004.

**Compatibility:** This is supporting test work. When porting or splitting those patches, retain the corrected test setup with its parent tests rather than treating cleanup as a separate product requirement.

**Retire when:** Equivalent tests are retained and compile under upstream's test conventions, or their corrected forms have been incorporated into the replayed parent patches. Removing a parent patch does not justify discarding acceptance coverage still needed by another patch.

### LP-006: Repository read/write enforcement

**Before:** Global authorization permitted repository reachability for any verified token. Matching resource entries could grant reachability with empty permission lists. Ordinary mutations lacked consistent write checks across transports; remote upload errors could hide permission failures as internal errors.

**Current:** `read`, `write`, `admin`, or `owner` grants baseline read access; `write`, `admin`, or `owner` grants ordinary writes. Missing, empty, or unknown-only permissions deny access. Privileged actions remain explicit. Enforcement covers legacy/v1 gRPC, HTTP uploads, forwarded calls, and both QUIC storage protocols, including metadata, branches, locks, mutable pointers, resolved uploads, and copies. Copies need source read and destination write access.

Creation validates and authorizes before mutation hooks or writes, including retries and name-mapping repairs. Claim-based creation needs a grant for the proposed repository ID. Legacy new creation still uses `CreateResource`; existing repositories/auth resources need write access. A newly created external auth resource can remain after hook rejection for a subsequent retry. Forwarded calls verify the caller's token at the destination; forwarded branch-list authorization is bounded by the RPC timeout. Remote upload/push paths preserve authorization errors. Verification healing remains read-authorized. A stream can retain earlier authorized mutations if a later item is denied; it is not a batch rollback.

**Code and regressions:** Start with [repository authorizer](../../lore-server/src/authnz/repository_authorizer.rs), [creation authorization](../../lore-server/src/grpc/handlers/repository_create.rs), and [forwarded token verification](../../lore-server/src/grpc/forwarded_requests.rs). The commit link inventories all transport gates and error-propagation edits. Acceptance coverage includes:

- [Authorizer tests](../../lore-server/tests/unit/authnz/repository_authorizer.rs): `ordinary_permission_matrix_agrees_across_authorizers_and_cached_grants`.
- [Creation tests](../../lore-server/tests/unit/grpc/repository/v1/repository_create.rs): `claim_creation_and_retries_require_write_before_hooks`.
- [Forwarded list tests](../../lore-server/tests/unit/grpc/forwarded_revision/v1/branch_list.rs): `service_bounds_stalled_authorization`.
- [Real QUIC tests](../../lore-server/tests/unit/quic/stream_handler.rs): `authenticated_storage_permission_matrix_on_both_protocols`.
- [Remote storage tests](../../lore-revision/tests/unit/immutable/session_tests.rs): `denied_remote_upload_preserves_authorization_error_without_retrying`.
- [Authenticated smoke suite](../../scripts/test/test_repository_permissions.py): read/write matrices, creation/retries, cross-repository copy, branches/metadata/locks, and forwarded mutations across global, resource, and legacy grants.

**Compatibility:** Configure the global permission claim where applicable. Replace empty resource grants with explicit permissions; the server configuration specifically calls for Aidonia's broker to emit `permission: ["read"]`. There is no empty-grant compatibility switch. Unauthenticated ordinary operations retain their previous behavior. Automatic OAuth issuance/exchange for claim-based creation remains separate work; provide a token already granting the proposed ID.

**Retire when:** Upstream passes the complete transport and authorization-tier contract, including denial before mutation hooks/writes, creation retry authorization, source/destination copy isolation, and permission-error propagation. PR #49 is only a lead. If it covers a subset, retain the remaining transport gates and tests. Reconcile LP-001 through LP-004's fixtures and LP-007/LP-008's smoke additions rather than dropping them with this commit.

### LP-007: QUIC access-token selection

**Before:** A storage session used token exchange when `auth_url` was configured; without it, a supplied access token was not sent. Claim-only writer pushes could fail despite the correct supplied grant.

**Current:** Each session start reads current credentials, prefers a supplied access token even without `auth_url`, and uses legacy exchange as fallback when no access token is supplied.

**Code and regressions:** [QUIC storage client](../../lore-transport/src/quic/storage_service/client.rs) and the smoke suite's `test_reader_cannot_push_and_writer_can`. Coverage includes QUIC/gRPC, global/resource/legacy grants, and access-token-only pushes.

**Compatibility:** Access-token precedence also applies when a legacy endpoint exists. This patch does not provide automatic OAuth token issuance. Its token-selection behavior must survive LP-009's session refreshes.

**Retire when:** Upstream sends the latest supplied token at every QUIC session start and refresh, while preserving exchange fallback. Confirm writer success and reader denial with access-token-only credentials across the smoke matrix.

### LP-008: Repository RPC token selection

**Before:** Repository RPCs used the authentication/login-token interceptor even when a separate scoped access token had been supplied for claim-based authorization.

**Current:** Create, delete, query/get, list, and metadata get/set RPCs choose the supplied access token, then supplied identity token, then the stored authentication token. Selection occurs per request, including retries and reconnects. Legacy deployments retain authentication-token selection. CLI help and the generated command reference explain credential selection.

**Code and regressions:** [Repository interceptor/client](../../lore-transport/src/grpc/repository_client.rs), [client construction and reconnect](../../lore-transport/src/grpc/mod.rs), and [wire-level tests](../../lore-transport/tests/unit/grpc/repository_client.rs). Acceptance includes `all_repository_rpcs_send_access_tokens_in_claim_mode`, `all_repository_rpcs_preserve_legacy_login_selection`, and credential rotation/retry/reconnect tests. The smoke suite covers claim creation and repository management using distinct credentials, reader denials, cross-repository isolation, and legacy behavior.

**Compatibility:** Claim-only stored-login resolution still needs an auth endpoint; automatic token exchange is separate work. Preserve legacy catalog/deletion credential semantics and update [CLI help source](../../lore-client/src/cli/cli.rs) and [CLI reference](../reference/lore-cli-commands.md) together when replacement changes user-visible guidance.

**Retire when:** All upstream repository RPCs implement the same current-credential precedence and pass wire-level plus CLI coverage, including access-token-only creation and legacy selection after reconnect.

**Disposition (2026-10-16): Retired.** Upstream's resolved-auth rework replaces the per-request interceptor: `GRPCAuth::new` resolves the authentication and authorization tokens once per endpoint (commits `33b1f62`, `8b73077`), `grpc_auth_refresher` re-resolves on credential rotation, reconnects re-run `repository_authz`, and the `AuthnInterceptor`/`AuthzInterceptor` pair injects the resolved tokens. A supplied access token is the authentication credential on claim-based endpoints and a legacy auth-service deployment retains login-token selection (`d42b015`). Verified with upstream's `auth/exchange.rs` selection tests (`supplied_access_token_replaces_the_repository_exchange`, `access_token_alone_authorizes_without_an_authentication_token`, `one_supplied_credential_is_never_served_anothers_authorization`), the `oidc/exchange.rs` wire tests, `connection.rs`'s rotation tests, and the permission smoke suite's 96 passing tests including the legacy distinct-credential matrices. The fork's wire-level `repository_client.rs` tests tested the retired interceptor and were dropped; the per-request-versus-per-connection selection difference is an implementation detail the rotation watcher absorbs.

### LP-009: Cached QUIC authorization expiry

**Before:** JWT verification checked expiry when authorization was established, but open legacy connections and v4 sessions could keep using cached grants after expiry. Client sessions lacked the new expiry-specific recovery path.

**Current:** Both QUIC protocols check effective expiry before admitting storage commands, with the existing 60-second skew allowance. Equality at the end of that allowance remains valid. Expired authorization is permanently retired even if the clock moves backward. Legacy connections reject reauthorization after retirement and require a fresh connection. V4 sessions can authorize a replacement without disturbing unrelated sessions; cleanup remains possible.

The transport maps wire status `AuthorizationExpired = 6` to `NotAuthenticated`. Storage sessions reauthorize and replay once on a pre-dispatch authentication rejection, using current credentials. Concurrent refreshes share a replacement; failed credentials are terminal until their generation changes. Permission denials never trigger refresh. The replacement session is stopped when its final authorization-state owner drops, including during active refresh/cleanup races.

**Code and regressions:** [JWT expiry boundary](../../lore-server/src/auth/jwt.rs), [server session map](../../lore-server/src/protocol/storage/session.rs), [legacy storage service](../../lore-server/src/quic/storage_service.rs), [v4 storage service](../../lore-server/src/quic/storage_service_v4.rs), [wire error status](../../lore-transport/src/quic/mod.rs), and [client session lifecycle](../../lore-transport/src/session.rs). Acceptance includes:

- [V4 service tests](../../lore-server/tests/unit/quic/storage_service_v4.rs): expiry after opening, near-expiry start, and malformed/missing/expired credentials.
- [Real QUIC tests](../../lore-server/tests/unit/quic/stream_handler.rs): `open_connections_reject_expired_reads_writes_and_cached_copies` and `actual_client_recovers_once_with_latest_token_and_enforces_new_grants`.
- [Client session tests](../../lore-transport/tests/unit/session.rs): concurrent refresh, changed credential generations, reader replacement denying writes, replay expiry, retryable backpressure, and final-owner cleanup.
- [JWT tests](../../lore-server/tests/unit/auth/jwt.rs), [server session tests](../../lore-server/tests/unit/protocol/storage/session.rs), and [response-reader tests](../../lore-transport/tests/unit/quic/response_reader.rs) for expiry boundaries, sticky retirement, and status classification.

**Compatibility:** Status 6 is emitted without ALPN negotiation. Older clients fail closed through unknown-status handling and may report a generic/internal error. Upgraded clients cannot impose server-side expiry when connected to an older server that still accepts expired grants. Preserve both server enforcement and client recovery when splitting this patch.

**Build compatibility (2026-10-09):** Both QUIC storage services expose only their authorization clock fields to the parent module with `pub(super)`. The shared test handler factory can therefore inject clocks when built with `integration_tests` alone; previously this failed with E0616 unless `test-util` also widened the fields. Preserve the existing test annotations and expiry behavior. Acceptance requires the standalone integration build and suite to pass without relying on workspace feature unification, together with the QUIC unit regressions.

**Validation (2026-10-09):** `cargo test --locked -p lore-integration-tests --features integration_tests --no-run` passed independently of workspace tests. With the Compose services running and CI AWS environment settings, the same command without `--no-run` passed 363 integration tests (4 ignored) and the separate GC trigger test. `cargo test --locked -p lore-server --test unit quic::` passed all 76 selected tests. `cargo +nightly fmt --all --check`, `cargo clippy --locked -p lore-server --all-targets --features integration_tests -- -D warnings --no-deps`, and `git diff --check` passed. `bash scripts/docs-lint.sh` could not validate documentation because Vale, markdownlint-cli2, and lychee were unavailable.

**Retire when:** Upstream passes expiry admission and sticky-retirement checks on both protocols, plus bounded v4 recovery, concurrent credential rotation, new-grant enforcement, and cleanup regressions. A server-only expiry fix replaces only part of this patch.

### LP-010: Portable Docker builds and fork release delivery

**Purpose:** Distribute this fork's tested binaries and server images under an independent Aidonia release identity. The recorded nine-commit comparison above remains historical; this entry tracks the subsequent release implementation.

**Before:** Source Docker builds tuned every ARM64 binary for Graviton3+, and the image publisher expected upstream release assets and published to EpicGames' namespace. Installer defaults selected upstream releases.

**Current:** Source Docker builds use portable AMD64/ARM64 code and the production `release-lto` profile. The server CLI reports the stamped library version, matching startup logs and the client. Fork tags prepare tested client archives for four targets and Linux server archives in a draft. Published releases produce one signed multi-platform image in the fork's GHCR namespace, using checksum-verified released server binaries and configuration from the same source commit. Both installers default to this fork while retaining repository overrides.

**Acceptance:** No default ARM64 build selects Neoverse tuning. Both container transports are exposed and tested; pushed data survives container recreation with the same volume. Every download identifies the fork version and source commit and includes license notices. Failed validation creates no draft. Exact published versions are preserved on retries, and prereleases and older backfills do not take newer moving tags.

**Code and regressions:** `lore-server/tests/unit/server.rs::cli_version::version_reports_the_stamped_library_version`, [release contracts](../../scripts/release/tests/test_release.py), [native container smoke flow](../../scripts/release/smoke-image.py), [release preparation](../../.github/workflows/prepare-release.yml), [image publication](../../.github/workflows/publish-loreserver-image.yml), and [release guide](releases.md).

**Replay:** Keep fork registry and installer destinations, tag namespace, ancestry checks, and source-stamp checks when updating upstream packaging. The core portable ARM build configuration is reused without modification.

**Compatibility:** Default ARM64 images now run on general ARM64 Linux hosts. Graviton-specific images are not part of this fork's release stream. Linux downloads initially require glibc 2.39 or newer; macOS and Windows clients are distributed without certificate signing or notarization.

**Build compatibility (2026-10-12):** The first hosted multi-OS release build exhausted every runner: both Linux legs were killed with exit 143 eleven minutes in, Windows failed with `rustc-LLVM ERROR: out of memory` (exit 101), and macOS was canceled at the 180-minute ceiling. `release-lto` now builds with `debug = "line-tables-only"` and `lto = "thin"` so peak rustc and linker memory fit the 7 GB macOS and 16 GB Linux/Windows runner budgets. Crash backtraces keep file-and-line information, matching the dev profile tradeoff. Packaging expectations are unchanged (executables plus notices; no `.pdb`/`.dSYM` is consumed).

**Validation (2026-10-09):** All 1,386 server unit tests passed outside the filesystem/network sandbox, including the CLI version regression. All 19 release contract tests passed. Local Linux release binaries were rebuilt, stamped, and packaged with generated notices; notices generation passed for all six planned archives. The AMD64 packaging image passed startup, health, push/clone on both transports, and persistence after container recreation with the same volume. Focused server Clippy, nightly formatting, Actionlint, ShellCheck, Ruff, Pyright, changed-document Markdownlint, and whitespace checks passed. ARM64/macOS/Windows native builds and hosted signing/publication remain to be verified by GitHub Actions. Vale and lychee were unavailable, and a broader Markdownlint scan reported existing findings in unrelated documentation. The hosted release build for `aidonia-v0.1.2` completed green on 2026-10-12 (run [38272694802](https://github.com/Laurelianae/lore/actions/runs/38272694802)): all four build matrix jobs — including the previously OOM-killed Windows and macOS legs — passed the production build, smoke, and packaging stages, and the draft was created.

**Retire when:** Replacement release tooling satisfies these acceptance contracts and preserves fork identity, downloads, signatures, and immutable exact versions. Upstream publishing to its own namespace does not replace fork delivery.

### LP-011: Client OIDC device grant, refresh, and auth-path dispatch

**Purpose:** Let `lore login` run the RFC 8628 device grant against the server-advertised issuer, keep tokens fresh through the `refresh_token` grant, and let the caller choose the authentication path (`--auth-mode` / `LORE_AUTH_MODE` / default-Auto), so the Aidonia broker can serve the OIDC contract. This is the client half of the approved LEP; the server side shipped upstream. The provider-facing half of the contract is written down in the [OIDC broker contract](oidc-broker-contract.md).

**Before:** `register_builtin()` registered only `UcsAuthentication`, so there was no backend to run a device grant or a refresh against. The plumbed-but-unconsumed `AuthMode` (auto/grpc/oidc) never reached `connect()` or the login flows. A server configured with `[server.auth]` + `[server.auth.oidc]` and no `auth_url` could not be logged into except by hand-supplied tokens. Root-domain derivation concatenated `iss` and `aud`, so tokens from a standard provider failed the remote check.

**Current:** `AuthMode`/`AuthPath`/`UnknownAuthMode` live in `lore-transport` and `lore-revision` re-exports them; `connect()` takes the mode, resolves it against the advertisement (D2: an explicitly requested path the server does not advertise is an error, Auto never errors), and registers an `OidcAuthentication` instance for the issuer in a new per-URL registry checked before the scheme registry. A caller that supplies credentials consults no auth path: resolution is skipped, so an OIDC-advertising server leaves `auth_url` empty exactly as before the dispatch and the auth block is skipped, while a gRPC server's non-empty `auth_url` still drives identity resolution as it always did. `interactive()` and `with_token()` resolve the same way; an explicit `--auth-url` with the `oidc` scheme is refused (the OIDC path resolves from the advertisement). `OidcAuthentication` implements the device grant (`verification_uri_complete`, `user_code`, `interval`, required `expires_in`), maps `authorization_pending`/`slow_down`/`expired_token`/`access_denied`, requests `offline_access` alongside the advertised scopes, and refreshes with one-time rotation. Refresh is wired into the exchange identity paths: an expired stored token is renewed in place (store writes persist the rotation) before the identity is skipped; supplied credentials are handed over untouched. Root domains are derived per D5 (`root_domains`, its `https://lore.org/claims/root_domains` alias, then shaped `aud` entries); the issuer itself is no longer part of the list, and the empty case stays fail-closed via the auth-endpoint domain `store_user_token` appends. Identity persistence and `lore auth info` / `auth list` resolve the effective URL (the issuer) through `Connection::auth_url`, so OIDC-only deployments work without repo-config auth URLs.

**Code and regressions:** [AuthMode](../../lore-transport/src/auth/mode.rs), [backend](../../lore-transport/src/auth/oidc/backend.rs), [registry](../../lore-transport/src/auth/mod.rs), [connect](../../lore-transport/src/connection.rs), [login dispatch](../../lore-revision/src/auth/login.rs), [refresh wiring](../../lore-transport/src/auth/exchange.rs), and [D5 derivation](../../lore-credential/src/jwt.rs). Acceptance includes the backend suite (`lore-transport/tests/unit/auth/oidc/backend.rs`: device happy path, `slow_down` consumption, `expired_token`/`access_denied` naming, missing-endpoint issuer naming, refresh rotation including spent-token refusal, identity-claim selection, opaque-token and missing-claim fail-closed, Tier 1 passthrough, root-domain claim precedence, `exp` fallback), the registry precedence test (`lore-transport/tests/unit/auth.rs::an_instance_registered_for_a_url_wins_over_the_scheme_registry`), the resolve matrix (`lore-transport/tests/unit/auth/mode.rs`), the D5 derivation tests (`lore-revision/tests/auth.rs`), and the refresh-wiring tests (`lore-transport/tests/unit/auth/exchange.rs::an_expired_stored_token_is_renewed_through_its_refresh_token` and `::an_expired_stored_identity_without_a_refresh_token_is_skipped`). The supplied-credential bypass is regression-covered by `scripts/test/test_repository_permissions.py`, whose servers advertise `[server.auth.oidc]` while the tests create repositories with supplied `--identity-token`/`--access-token` — the dispatch must leave those creations untouched. End to end: `scripts/test/test_auth_oidc.py` (device login against an OIDC-only server, `auth info`/`auth list` identity persistence, Tier 1 operation, automatic renewal through the refresh grant).

**Compatibility:** `lore.h` is unchanged: cbindgen resolves `AuthMode` through `lore-transport` under the same rename, and the `lore_global_args_t` layout is unaffected. A same-version client/service is assumed — an older service process that receives a shorter `LoreGlobalArgs` bitcode resolves `Auto`. Tokens minted by the legacy auth service keep working: shaped `aud` entries (`["URC", ".epicgames.net"]`) yield exactly the suffix they did before.

**Retire when:** Upstream lands an equivalent client OIDC login (the LEP is upstream-approved, so this is expected). Verify against the same contract — device grant against the advertised issuer, refresh with rotation persisted through the exchange identity path, D5 derivation, and `AuthMode` dispatch with the explicit-not-advertised error — then retire per the register's reconciliation procedure.

**Disposition (2026-10-16): Retired, refresh grant re-landed.** Upstream's `33b1f62` (auth-path selection, registry, supplied-credential bypass, connection dispatch), `21c2bd1` (device grant against the advertised issuer, `offline_access`, poll-state mapping), and `228762f` (D5 derivation) satisfy the dispatch, grant, and derivation contracts; `select.rs` and the `oidc/device.rs` tests are the regression surface. Upstream stores the refresh token but never uses it (`refresh_authentication` answered `NotSupported`), so the refresh grant was re-landed as `482c038` on the restructured backend, keeping the merge-surviving `refresh_if_expired` wiring and the rotation persistence contract; `oidc/refresh.rs` is its regression surface, and the exchange-wiring tests in `auth/exchange.rs` remain. The fork's per-URL registry is replaced structurally: the implementation is bound into the selected `AuthEndpoint`, and the refresh and logout paths now take it from there instead of re-resolving. Upstream allows an explicit `--auth-url` naming an `oidc+` issuer to fail at registry resolution where the fork refused it with a dedicated message — the upstream shape stands.

### LP-012: RFC 8693 token exchange and external-token login

**Purpose:** Mint partition-scoped tokens so the Aidonia broker can express the GitHub-style permission model, and make `lore login --token-type api-key` work on the OIDC path. The provider-facing contract is the [OIDC broker contract](oidc-broker-contract.md); the Tier 2 configuration rule (issuer plus exactly one template) mirrors the server's startup validation.

**Before:** The OIDC backend's exchanges were Tier 1 passthroughs (the authentication token itself, grants read server-side by the `GlobalGrantsAuthorizer`), and `exchange_external_token` answered `NotSupported`.

**Current:** With `token_exchange_issuer` plus exactly one of `resource_template`/`scope_template` advertised, `exchange_for_repository` runs the RFC 8693 grant at the exchange issuer — `subject_token`/`subject_token_type=urn:ietf:params:oauth:token-type:access_token`, `requested_token_type=access_token`, and one `resource` (RFC 8707, template with `{id}` substituted) or `scope` per request (D3). `exchange_for_custom_resource` names the resource verbatim in either mode. Any other template/issuer combination errors naming the misconfiguration instead of silently degrading to Tier 1. The minted token is mapped from its claims (`exp`, D5 domains); `exchange()` already runs `verify_jwt_usage_for_remote` against it before caching or storing. `exchange_external_token` maps `api-key` to `urn:lore:params:oauth:token-type:api-key`, passes any `urn:...` value through verbatim, and refuses other short names naming the supported set; the existing `with_token` → `exchange_token` flow stores the result and its refresh token.

**Code and regressions:** [exchange grant](../../lore-transport/src/auth/oidc/backend.rs) (`ExchangeMode`, `token_exchange`, `exchange_token`, `subject_token_type`). Acceptance includes `the_tier_2_exchange_mints_a_resource_scoped_token` (asserting every grant parameter on the wire, including the substituted `resource` and the absence of `scope`), `the_scope_template_names_the_partition_as_a_scope`, `the_custom_resource_exchange_names_the_resource_verbatim`, `an_exchange_configuration_that_names_no_carrier_is_refused` (all invalid combinations), and `the_external_token_exchange_maps_the_token_type` (api-key mapping, `urn:` passthrough, unknown short name refused). End to end: `scripts/test/test_auth_oidc.py::test_tier2_exchange_mints_a_resource_scoped_token` against a server with `resource_template` + `resource_claim` configured, asserting the exchange request's `resource` parameter and that the operation succeeds under the resource-grants authorizer.

**Compatibility:** A deployment that sets no exchange configuration stays on Tier 1 indefinitely (D2). The exchange grant goes to `token_exchange_issuer` when configured, else to the advertised issuer's token endpoint, so an external-token login works on Tier 1 issuers that implement RFC 8693 at their token endpoint. `exchange()` classifies backend errors through the existing `NotAuthorized`/internal mapping, so permission denials are still not retried.

**Retire when:** Upstream implements the RFC 8693 client exchange with the same template rule (exactly one carrier, verbatim custom resources, one resource per request) and the API-key `subject_token_type` mapping, verified against the broker contract's checklist; retire per the register's reconciliation procedure.

**Disposition (2026-10-16): Retired, api-key login re-landed.** Upstream's `8b73077` implements the exchange (`oidc/exchange.rs`): the exactly-one-carrier rule refused before any request, one `resource`/`scope` per request with the substituted partition, verbatim custom resources, the separate-issuer root-domain check, Tier 1 passthrough, and refusal classification — `oidc/exchange.rs`'s tests are the regression surface. The api-key external-token mapping (`--token-type api-key` to `urn:lore:params:oauth:token-type:api-key`, `urn:` passthrough, unknown short names refused before any request) was absent upstream and was re-landed as `482c038` (`exchange_external` plus `subject_token_type`), with the wire test in `oidc/exchange.rs`. The subject is the caller's own credential, so like the fork it is checked against no root-domain list. Should the api-key flow prove unused, dropping it retires the residual entirely.

### LP-013: RFC 7009 token revocation on `lore auth logout`

**Purpose:** Complete the proposal's phase-3 client list: `lore auth logout` revokes the removed identities' refresh token and authentication token at the provider's advertised `revocation_endpoint` (RFC 7009), so credentials die at the issuer instead of only disappearing locally. The provider-facing contract is the [OIDC broker contract](oidc-broker-contract.md).

**Before:** Logout was local-only: it deleted entries from the token store and never contacted the provider. Discovery already parsed and https-validated `revocation_endpoint`, but nothing consumed it.

**Current:** The `Authentication` trait gains `revoke_token(auth_url, token, token_type_hint, correlation_id)`. The OIDC backend implements it by discovering the issuer, answering a no-op when discovery advertises no `revocation_endpoint` (RFC 7009 is optional), and otherwise posting `token`/`token_type_hint`/`client_id` form-encoded to the advertised endpoint — any 2xx is success per RFC 7009 §2.2 (the body is ignored), anything else is a reportable failure. The gRPC path answers `NotSupported`. `logout_local` looks the backend up by the resolved auth URL, revokes the refresh token (hint `refresh_token`) and then the stored authentication token (hint `access_token`) per removed identity, and treats every failure — including a missing backend — as a non-fatal `LoreEvent::Error` while local state is always cleared; exit code and "Logged out" output are unchanged. Resource-scoped tokens (`--resource`) are not revoked: they are minted at the exchange issuer and bounded by their own expiry, and RFC 7009 §2.1 has conforming providers invalidate the grant's access tokens when the refresh token is revoked. Logout with an explicit `--auth-url` but no connection stays local-only (no registered backend means no discovery endpoints), preserving the offline use case.

**Code and regressions:** [trait](../../lore-transport/src/traits.rs), [backend](../../lore-transport/src/auth/oidc/backend.rs), [gRPC stub](../../lore-transport/src/auth/ucs_auth.rs), [logout wiring](../../lore/src/auth.rs). Acceptance includes `the_revocation_endpoint_receives_the_token_and_hint`, `a_provider_without_a_revocation_endpoint_makes_revocation_a_no_op`, and `a_failing_revocation_answer_is_an_error` in `lore-transport/tests/unit/auth/oidc/backend.rs`, backed by the fake provider's `/revoke` route (`lore-transport/tests/support/oidc_provider.rs`), and end to end `scripts/test/test_auth_oidc.py::test_logout_revokes_tokens_at_the_provider`.

**Retire when:** Upstream lands equivalent client-side revocation on logout; verify the failure contract (reported, non-fatal, local state always cleared) and the no-endpoint no-op against the same test surface, then retire per the register's reconciliation procedure.

**Status (2026-10-16): Active, re-landed.** No upstream commit implements revocation. The merge dropped the fork's `backend.rs` with the rest of `1526c6c`; `a8d07fa` ported `revoke_token` onto the restructured `oidc` module (discovery, no-endpoint no-op, form POST, 2xx-is-success) and moved the regression tests to `oidc/revoke.rs` against the `RecordingProvider`. The trait method, the gRPC `NotSupported` stub, and the logout wiring (non-fatal error, local state always cleared) survived the merge; the logout lookup now takes the endpoint's carried implementation, since a per-selection OIDC backend is unreachable through `authentication::find`.

### LP-014: Read-gated repository lookup on resource-grant servers

**Purpose:** Keep the fork's LEP D4 model — the broker mints login tokens already carrying the user's partition grants — by restoring LP-006's baseline read gate on repository lookups after upstream's `8b73077` opened them on the resource-grant tier.

**Before:** `ResourceGrantsAuthorizer` overrode `check_repository_lookup` (adopted with `8b73077` in the 2026-10-16 merge) to answer `Ok` for any verified token, so a Tier 2 login token carrying no grant on a repository could resolve its name to an id and read its record.

**Current:** The override is deleted and the trait default applies: a lookup requires `check_repository_access(token, repository_id, None)`, i.e. a read-like grant (`read`/`write`/`admin`/`owner`) on the named repository, directly or through the `urc-*` wildcard. All lookup call sites (legacy `RepositoryQuery`, v1 `RepositoryGet` by id and by name, and forwarded `RepositoryGet`) go through `check_repository_query_authorization`, so a denial surfaces as `NOT_FOUND`, hiding the repository. The claims and legacy tiers and AllowAll servers are unchanged — the trait default already governed them.

**Code and regressions:** The override's deletion in [resource_grants_authorizer.rs](../../lore-server/src/authnz/resource_grants_authorizer.rs). Upstream's trait method and the `check_repository_query_authorization` indirection ([repository_query.rs](../../lore-server/src/grpc/handlers/repository_query.rs)) are structure, not behavior, and are kept. Regression: `a_lookup_requires_a_read_like_grant` in [resource_grants_authorizer.rs](../../lore-server/tests/unit/authnz/resource_grants_authorizer.rs) (Ok for read-like entries, `PermissionDenied` for empty, unknown-only, and non-matching partitions, `Unauthenticated` without a token) and `test_read_write_matrix` in [test_repository_permissions.py](../../scripts/test/test_repository_permissions.py), which asserts the lookup against the read matrix on every tier again.

**Compatibility:** A Tier 2 login token naming no partition can no longer bootstrap the partition exchange by resolving a name: the broker must keep including the user's partition grants (per-partition or wildcard) in the login token itself, as LEP D4 and the Tier 2 suites already assume. Users the broker has provisioned see no change; users without a grant on a repository get `NOT_FOUND` again. Upstream's motivating case — a grantless login token bootstrapping an exchange — is deliberately not supported.

**Retire when:** Upstream re-gates the resource-grant lookup on read, or the fork deliberately adopts the open lookup with the compatibility consequences written down. PR #49 is not evidence.

## Inspect and export the recorded series

Run these commands from the repository root. Immutable revisions keep the original comparison reproducible even after branch names move.

```bash
baseline=5c88e6e7528a12b74ab3e1621b5d7c540a5d1606
fork_revision=e5da4fa
git merge-base --is-ancestor "$baseline" "$fork_revision"
git log --reverse --format='%H %s' "$baseline..$fork_revision"
git diff --stat "$baseline" "$fork_revision"
git diff "$baseline" "$fork_revision"
git show c982cdf18724d876115f70b1331bbca3f0282083
patch_dir=$(mktemp -d "${TMPDIR:-/tmp}/lore-patches.XXXXXX")
git format-patch --output-directory "$patch_dir" "$baseline..$fork_revision"
```

The export covers the Active patches and their supporting commits; the retired LP-008, LP-011, and LP-012 content rides in history but is absent from the tree. Keep the original commit links as provenance if a later replay changes commit hashes.

## Reconcile after upstream changes

1. Obtain a fresh upstream revision when network access is available. With the currently recorded remotes, `git fetch https://github.com/EpicGames/lore.git main` fetches it without changing remote configuration. Record the immutable revision with `git rev-parse FETCH_HEAD` before another fetch replaces that reference.
2. Review upstream's behavior against each acceptance contract. Use `git log` and diffs for context and `git cherry <new-upstream-sha> <recorded-fork-sha>` for patch-equivalence hints. An equivalent patch ID is useful evidence; a non-equivalent ID does not establish that upstream lacks the behavior.
3. Create an isolated review branch/worktree based on the new upstream revision, using a fresh branch name such as `codex/upstream-patch-review-YYYYMMDD`. Preserve the original fork branch during review.
4. Replay retained commits in table order, using `git cherry-pick <commit>` individually. If every patch is retained, the exported series can instead be applied in filename order with `git am`. When omitting or splitting a patch, resolve dependent edits against the acceptance contracts. Do not blindly revert an early commit on the existing fork: later patches modify the same handlers, tests, configuration prose, and storage client.
5. Keep equivalent regression coverage even when its implementation commit is omitted. Run affected server, transport, and revision tests and the authenticated smoke scenarios described above. Use the existing [contribution testing instructions](../../CONTRIBUTING.md) for setup. After building the required binaries, run `uv run pytest scripts/test/test_repository_permissions.py` for the focused smoke suite. Confirm privileged actions and ordinary writes separately, and cover both QUIC protocols plus legacy authorization compatibility.
6. Mark a patch **Retired** only when upstream supplies its complete behavior and the relevant regressions pass. Mark it **Partially replaced** when residual behavior remains; record retained hunks/replacement commits and dependencies. Keep retired rows and detail sections as historical records.
7. For every reconciliation, record the new upstream baseline, reviewed fork revision, review date, upstream replacement commit/PR, replayed commit hashes, and actual test commands/results. If validation is blocked, record that limitation and keep the retirement decision pending. Update comparison counts and this register alongside the reviewed fork changes.

For each retired or partially replaced entry, append a disposition record containing: status, review date, upstream replacement SHA/link, remaining behavior (if any), replayed SHA(s), and verification evidence. The stable LP ID and original provenance remain unchanged.

## Validation evidence

This documentation review checks the nine-commit inventory, code/test references, the final comparison, and documentation structure. It does not rerun application tests or verify live upstream equivalence. Future reconciliation must record its own executed checks.

Historical results below come from commit messages, not from this documentation review:

| Commit | Reported validation |
| --- | --- |
| LP-007 | Claim-only QUIC writer failure reproduced before the fix; 118 transport tests passed; 56 permission smoke tests passed with 19 tier-specific skips |
| LP-008 | 126 transport tests passed; 96 permission smoke tests passed with 45 tier-specific skips; Clippy, nightly formatting, and Ruff passed |
| LP-009 | 1,385 server tests and 136 transport tests passed; Clippy and nightly formatting passed |

During this review, `bash scripts/docs-lint.sh` exited with code 2 because Vale, markdownlint-cli2, and lychee were all unavailable. Local reference, commit-inventory, test-symbol, shell-syntax, and whitespace checks passed; external URLs were not validated. Application tests were not rerun.

For documentation changes, run `bash scripts/docs-lint.sh`. Report missing tools, existing unrelated findings, and unavailable external-link checks separately from checks that actually passed.
