# Serve a user directory for an OIDC deployment

With OIDC authentication, Lore tokens carry only user IDs (`sub`, or a provider-mapped
`identity` claim). The CLI shows *your own* name by decoding your cached token, but every
*other* user — revision authors, lock owners, branch creators — needs a **user directory**:
a service the server advertises as `user_url` that maps user IDs to display names. Without
one the CLI silently falls back to printing raw IDs.

This guide records how resolution works, what a minimal directory must implement today,
and the migration path to the planned native directory API.

## How name resolution works

- **Your own name** is decoded locally from the cached identity token:
  `preferred_username`, then `name`, then the raw ID (`display_name` in
  `lore-revision/src/auth/userinfo.rs`). Works only if the provider includes those claims
  in the access token.
- **Other users' names** are resolved remotely through a `UserService`. The server
  advertises the directory as `[environment.endpoint] user_url` (falling back to
  `auth_url`), and the client selects the implementation by URL scheme
  (`lore-transport/src/auth/mod.rs`):
  - `ucs-auth`, `https`, `http` → the UCS auth client (`UcsAuthentication`), which calls
    `epic_urc.UrcAuthApi/GetUserInfo` and `/GetUserId`.
  - anything else → `TokenOnlyUserService`, which answers only the bearer's own name and
    echoes every other ID as its own name.
- Every failure on this path degrades silently to raw IDs — nothing breaks, names simply
  do not resolve. Verify with a real directory, not by absence of errors.
- `lore auth info <ids>` resolves **locally only**; the directory is exercised by
  `lore lock list`, revision author fields, and branch views.
- What gets *recorded* as the user ID is a separate knob: the token's `identity` claim,
  else its namespaced alias `https://lore.org/claims/identity`, else `sub` (OIDC LEP,
  updated 2026-10-15). Mapping a readable claim into `identity` yields readable history
  without a directory, at the cost of renames forking identities.

## Prerequisites

- A Tier 1 or Tier 2 OIDC deployment (see the
  [OIDC LEP](../proposals/2026-08-20-oidc-oauth2-authentication.md), D5–D7).
- Repository access already works, i.e. the token exchange against your issuer succeeds.

## Steps

1. **Implement a minimal `epic_urc.UrcAuthApi` directory.**

   The client's directory path calls exactly two RPCs; copy the messages from
   [`lore-proto/proto/auth_api.proto`](../../lore-proto/proto/auth_api.proto):

   - `GetUserInfo(GetUserInfoRequest) → GetUserInfoResponse` — batch IDs → display names.
   - `GetUserId(GetUserIdRequest) → GetUserIdResponse` — display name → ID.

   Nothing else is called on this path: login and exchange RPCs go to the OIDC issuer,
   and `LookupUserPermissions` is a server-side concern (`RepositoryCatalog`). Notes:

   - TLS is required: the client upgrades any non-loopback URL to `https`
     (`grpc_endpoint` in `lore-transport/src/auth/ucs_auth.rs`); loopback `http` is
     allowed for testing.
   - Requests carry `authorization: Bearer <token>`; validate it against your issuer's
     JWKS and read the ID from the claims.
   - `resource_id` arrives as `urc-{partition-id}`; ignore it or scope by it.
   - Prefer a `ucs-auth://` URL for the directory: that scheme is registered for the user
     service outright, while `https://` is a transition fallback a future native
     directory will also want.

2. **Make the directory's domain acceptable to the token.**

   The directory credential is exchanged like any repository token and then checked
   against the directory's domain (`open_user_service` in
   `lore-revision/src/auth/userinfo.rs`, the D5 send-check). Under Tier 2 that token is
   your usual partition-scoped one, so it must cover the directory's domain:

   - host the directory under the resource-template host's domain — a `https` URI in
     `aud` contributes its host, and matching is a label-boundary suffix match, so
     `ucs.lore.example.com` passes a `https://lore.example.com/partitions/{id}`
     template — or
   - stamp a `root_domains` claim (or the namespaced alias
     `https://lore.org/claims/root_domains`) naming the directory's domain at the
     exchange issuer.

   If neither holds, the check fails and names degrade to raw IDs.

3. **Advertise the directory.**

   ```toml
   [environment.endpoint]
   user_url = "ucs-auth://directory.example.com"
   ```

4. **Verify through a display path.**

   `lore lock list`, or a revision log authored by another user. Bare IDs instead of
   names mean the domain check or an RPC failed — debug logging
   (`User info query …` in `lore-revision/src/auth/userinfo.rs`) tells which.

## Result

`lore lock list`, revision logs, and branch views resolve other users through the
directory and show display names instead of bare IDs.

## Migrating to the native directory later

`lore.user.v1.UserService` (`lore-proto/proto/lore/user/v1/user.proto`) is the planned
successor: `UserGet` maps to `GetUserInfo`, `UserFind` to `GetUserId`, with `username`
and `display_name` carried separately. As of now it exists only as a proto and generated
stubs — no server implements it and no client wiring selects it, so a `https://`
`user_url` still reaches the UCS client. When support lands, re-implement the two
lookups behind the new service and flip `user_url`; the client-side `UserService` trait
and your deployment knob stay unchanged.

## See also

- [OIDC/OAuth2 authentication LEP](../proposals/2026-08-20-oidc-oauth2-authentication.md) —
  D5 (token domains), D7 (the user directory and the `identity` claim).
- [`lore-transport/src/auth/ucs_auth.rs`](../../lore-transport/src/auth/ucs_auth.rs) — the
  client's directory protocol.
- [`lore-transport/src/auth/token_only.rs`](../../lore-transport/src/auth/token_only.rs) —
  the degraded default.
- [`lore-revision/src/auth/userinfo.rs`](../../lore-revision/src/auth/userinfo.rs) —
  resolution entry points and the token-domain check.
