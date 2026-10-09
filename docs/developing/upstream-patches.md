---
title: Upstream patch register
description: Fork patches, their acceptance contracts, and the workflow for replaying or retiring them after Lore upstream changes.
---

# Upstream patch register

This register tracks the patches maintained on `aidonia/main` relative to local `main`. Use it when updating the fork from Lore upstream, rebuilding the patch series, or deciding whether an upstream implementation replaces a local change.

## Recorded comparison

| Item | Recorded value |
| --- | --- |
| Review date | 2026-10-08 |
| Upstream project | [EpicGames/lore](https://github.com/EpicGames/lore) |
| Fork | [Laurelianae/lore](https://github.com/Laurelianae/lore), branch `aidonia/main` |
| Baseline | Local `main`: `491a7ed75c9b0dac7de50ada6d2a9c38f3cbc046` |
| Fork revision | `4bfa0ec058d08ba9c2aa7abb783d7299c9829820` |
| Comparison | Nine commits; 86 changed files; 5,306 insertions and 513 deletions |
| Upstream freshness | Unverified. The upstream network check failed because `github.com` could not be resolved. |

The configured remote is the fork, `origin`; there is no configured `upstream` remote. Local `main` and `origin/main` pointed to the same baseline during this review. This establishes the local comparison, not whether upstream has since incorporated any of these patches. The working tree was clean before this documentation change.

[Upstream PR #49](https://github.com/EpicGames/lore/pull/49) is a comparison lead already recorded in the [server authorization configuration](../reference/lore-server-config.md). Its current status, merge commit, and behavioral equivalence are unverified. Do not mark a patch retired merely because that PR exists or touches similar code.

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
| LP-008 | [e799c84](https://github.com/Laurelianae/lore/commit/e799c84368a25a43f98d8ccad0c0e95f5f9a5700) | Scoped tokens for repository RPCs | Extends LP-006 smoke coverage; complements LP-007 | Active |
| LP-009 | [4bfa0ec](https://github.com/Laurelianae/lore/commit/4bfa0ec058d08ba9c2aa7abb783d7299c9829820) | Cached QUIC authorization expiry and recovery | Uses LP-006 cached grants and LP-007 current-token selection | Active |
| LP-010 | [eabb070](https://github.com/Laurelianae/lore/commit/eabb0702aa04b08861e60008b4cd8dc1921df1cc) | Portable Docker builds and fork release delivery | Reuses the portable ARM baseline, version stamping, and notices generation | Active |

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

**Retire when:** Upstream passes expiry admission and sticky-retirement checks on both protocols, plus bounded v4 recovery, concurrent credential rotation, new-grant enforcement, and cleanup regressions. A server-only expiry fix replaces only part of this patch.

### LP-010: Portable Docker builds and fork release delivery

**Purpose:** Distribute this fork's tested binaries and server images under an independent Aidonia release identity. The recorded nine-commit comparison above remains historical; this entry tracks the subsequent release implementation.

**Before:** Source Docker builds tuned every ARM64 binary for Graviton3+, and the image publisher expected upstream release assets and published to EpicGames' namespace. Installer defaults selected upstream releases.

**Current:** Source Docker builds use portable AMD64/ARM64 code and the production `release-lto` profile. The server CLI reports the stamped library version, matching startup logs and the client. Fork tags prepare tested client archives for four targets and Linux server archives in a draft. Published releases produce one signed multi-platform image in the fork's GHCR namespace, using checksum-verified released server binaries and configuration from the same source commit. Both installers default to this fork while retaining repository overrides.

**Acceptance:** No default ARM64 build selects Neoverse tuning. Both container transports are exposed and tested; pushed data survives container recreation with the same volume. Every download identifies the fork version and source commit and includes license notices. Failed validation creates no draft. Exact published versions are preserved on retries, and prereleases and older backfills do not take newer moving tags.

**Code and regressions:** `lore-server/tests/unit/server.rs::cli_version::version_reports_the_stamped_library_version`, [release contracts](../../scripts/release/tests/test_release.py), [native container smoke flow](../../scripts/release/smoke-image.py), [release preparation](../../.github/workflows/prepare-release.yml), [image publication](../../.github/workflows/publish-loreserver-image.yml), and [release guide](releases.md).

**Replay:** Keep fork registry and installer destinations, tag namespace, ancestry checks, and source-stamp checks when updating upstream packaging. The core portable ARM build configuration is reused without modification.

**Compatibility:** Default ARM64 images now run on general ARM64 Linux hosts. Graviton-specific images are not part of this fork's release stream. Linux downloads initially require glibc 2.39 or newer; macOS and Windows clients are distributed without certificate signing or notarization.

**Validation (2026-10-09):** All 1,386 server unit tests passed outside the filesystem/network sandbox, including the CLI version regression. All 19 release contract tests passed. Local Linux release binaries were rebuilt, stamped, and packaged with generated notices; notices generation passed for all six planned archives. The AMD64 packaging image passed startup, health, push/clone on both transports, and persistence after container recreation with the same volume. Focused server Clippy, nightly formatting, Actionlint, ShellCheck, Ruff, Pyright, changed-document Markdownlint, and whitespace checks passed. ARM64/macOS/Windows native builds and hosted signing/publication remain to be verified by GitHub Actions. Vale and lychee were unavailable, and a broader Markdownlint scan reported existing findings in unrelated documentation.

**Retire when:** Replacement release tooling satisfies these acceptance contracts and preserves fork identity, downloads, signatures, and immutable exact versions. Upstream publishing to its own namespace does not replace fork delivery.

## Inspect and export the recorded series

Run these commands from the repository root. Immutable revisions keep the original comparison reproducible even after branch names move.

```bash
baseline=491a7ed75c9b0dac7de50ada6d2a9c38f3cbc046
fork_revision=4bfa0ec058d08ba9c2aa7abb783d7299c9829820
git merge-base --is-ancestor "$baseline" "$fork_revision"
git log --reverse --format='%H %s' "$baseline..$fork_revision"
git diff --stat "$baseline" "$fork_revision"
git diff "$baseline" "$fork_revision"
git show c982cdf18724d876115f70b1331bbca3f0282083
patch_dir=$(mktemp -d "${TMPDIR:-/tmp}/lore-patches.XXXXXX")
git format-patch --output-directory "$patch_dir" "$baseline..$fork_revision"
```

`git format-patch` exports nine numbered patches in chronological order, including supporting tests. Keep the original commit links as provenance if a later replay changes commit hashes.

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
