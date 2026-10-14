---
title: OIDC broker contract
description: The exact HTTP behavior the Aidonia broker must serve so Lore clients can log in, refresh, and exchange against it.
---

# OIDC broker contract

This is the synchronization artifact for the Aidonia broker: the HTTP surface it must serve to act as the issuer a Lore server advertises under `[server.auth]` + `[server.auth.oidc]`. The client side of every requirement below is implemented in the fork ([`lore-transport/src/auth/oidc/backend.rs`](../../lore-transport/src/auth/oidc/backend.rs)) and exercised against a fake provider with the same contract in [`lore-transport/tests/support/oidc_provider.rs`](../../lore-transport/tests/support/oidc_provider.rs) and `scripts/test/test_auth_oidc.py`. The design is the approved LEP, [OIDC/OAuth2 authentication](../proposals/2026-08-20-oidc-oauth2-authentication.md); the fork patches are LP-011 (device grant, refresh, dispatch) and LP-012 (RFC 8693 exchange) in the [upstream patch register](upstream-patches.md).

Until the broker serves this contract, the fake provider is the reference behavior: `scripts/test/test_auth_oidc.py` is the executable form of everything below, and the manual broker checklist at the end replays the same scenarios against the real broker.

## 1. Discovery

Serving `GET <issuer>/.well-known/openid-configuration` with `Content-Type: application/json`:

```json
{
  "issuer": "<issuer>",
  "token_endpoint": "<issuer>/token",
  "jwks_uri": "<issuer>/jwks",
  "device_authorization_endpoint": "<issuer>/device"
}
```

- `issuer` MUST equal the URL the document was fetched from, exactly (scheme, host, port, path). A mismatch fails the login with an issuer-mismatch error.
- `token_endpoint` and `device_authorization_endpoint` MUST be present. `revocation_endpoint` and `end_session_endpoint` are optional (the client does not call them yet).
- Every URL in the document MUST be `https`, or plain `http` to a loopback host (this is what permits the local test broker).
- The client caches the document per issuer; the broker MAY serve it statically. Redirects are followed only within the issuer's origin.

## 2. Device grant (RFC 8628)

`POST <device_authorization_endpoint>`, form-encoded:

| Parameter | Value |
| --- | --- |
| `client_id` | The server-advertised client ID |
| `scope` | The advertised scopes plus `offline_access`, space-delimited |

Answer `200` with the RFC 8628 §3.2 response:

| Field | Requirement |
| --- | --- |
| `device_code` | MUST be present; opaque to the client, echoed on every poll |
| `verification_uri_complete` | SHOULD be present; opened in the user's browser or emitted as the `AuthUrl` event |
| `verification_uri` | Required if `verification_uri_complete` is absent |
| `user_code` | SHOULD be present; the code the user types from another machine |
| `expires_in` | MUST be present; seconds the session stays open for approval |
| `interval` | Optional; the client polls every 5 seconds when absent |

`verification_uri_complete` MUST be `https` (or loopback `http`) and MUST NOT carry a username or password — the client refuses such a URL before showing it to anyone.

`POST <token_endpoint>` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `device_code`, `client_id` answers per RFC 8628 §3.5:

| Situation | Response |
| --- | --- |
| Not yet approved | `400` `{"error": "authorization_pending"}` |
| Polling too fast | `400` `{"error": "slow_down"}` — the client widens its interval by 5 s per answer |
| Session lifetime elapsed | `400` `{"error": "expired_token"}` |
| User refused | `400` `{"error": "access_denied"}` |
| Approved | `200` token response (§4, §5) |

Any other `error` value reaches the user verbatim (with `error_description` when present), so error strings are user-visible.

## 3. Refresh grant, with one-time rotation

`POST <token_endpoint>` with `grant_type=refresh_token`, `refresh_token`, `client_id`, `scope` (the same set the login requested):

- A valid refresh token is answered with a token response carrying a NEW access token and a NEW refresh token (§4). The presented refresh token is burned: presenting it again MUST be answered `400` `{"error": "invalid_grant"}`. Rotation is one-time, no grace window — the client persists the rotation before using the new token.
- The `scope` parameter MAY be ignored, but the minted token's grants must not widen beyond what the login requested.
- A refresh token the broker does not recognize (expired SSO session, revoked) is `400` `{"error": "invalid_grant"}` with a `error_description` the user can act on.

The client refreshes lazily: an expired authentication token is renewed at the next operation that needs it, so the broker must not require refresh within any particular window.

## 4. Access-token format

The broker MUST emit JWT access tokens (the RFC 9068 profile; an opaque token fails login with a naming error — this is a broker requirement, not a client feature):

| Claim | Requirement |
| --- | --- |
| `iss` | The issuer URL, exactly as advertised |
| `sub` | The user's identity, unless the server advertises a different `identity_claim` to read instead |
| `exp` | Expiry, seconds since epoch. If absent, the client falls back to the token response's `expires_in` |
| `name` / `preferred_username` | At least one SHOULD be present; the display name comes from it |
| `aud` | See below |
| `root_domains` | See below |

The client sends tokens only to hosts under a root domain the token names (D5). The list comes from the token itself, in order:

1. the `root_domains` claim (list of domain suffixes/hosts) if present and non-empty;
2. the namespaced alias `https://lore.org/claims/root_domains`, same shape;
3. otherwise each `aud` entry that has a usable shape: an `https://` URI contributes its host, a domain-shaped entry contributes a suffix, anything else (opaque IDs such as `lore-api`) contributes nothing.

The broker MUST mint every access token with either a `root_domains` claim or an `aud` entry shaped as the deployment's domain, or the login fails closed. A token with no usable domain can only ever be sent back to the token endpoint.

## 5. RFC 8693 token exchange (Tier 2)

When the server advertises `token_exchange_issuer` plus exactly one of `resource_template` / `scope_template`, the client exchanges at `<token_exchange_issuer>/.well-known/openid-configuration` → its `token_endpoint`:

`POST <token_endpoint>` form-encoded:

| Parameter | Value |
| --- | --- |
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | The authentication token from login or refresh |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:access_token` |
| `requested_token_type` | `urn:ietf:params:oauth:token-type:access_token` |
| `resource` OR `scope` | Exactly one per request. Repository exchange: the template with `{id}` replaced by the partition ID. Custom-resource exchange: the resource ID verbatim, never template-substituted |

The broker MUST:

- validate `subject_token_type` — `urn:ietf:params:oauth:token-type:access_token` for the partition exchange; for an API-key login the subject token type is `urn:lore:params:oauth:token-type:api-key` and the subject token is the opaque API key, which the broker validates and binds to a user;
- mint the scoped token with `exp` shorter than the subject's, carrying `iss`, `sub` (the same identity), `aud`, and a `root_domains` claim — the client requires the minted token to name a domain before it will send it anywhere, so copying `root_domains` (narrowed to what the subject may reach for that partition) is mandatory;
- refuse an expired, spent, or unrecognized subject token with `400` `{"error": "invalid_grant", ...}`.

The client runs its own domain check on the minted token against the remote it is talking to, so a minted token that lacks the deployment domain is rejected client-side even if the broker accepted the exchange.

## 6. Checklist for the broker sync

Run once the broker is ready, with the broker advertised from a `[server.auth]`-configured lore-server and `LORE_AUTH_MODE=oidc` (or `--auth-mode oidc`):

1. `lore login --no-browser` completes against the broker's device grant; `lore auth info` shows the identity.
2. A repository operation succeeds with the login token (Tier 1 authorizer).
3. With a Tier 2 template configured, a repository operation mints a scoped token; the broker saw exactly one `resource` (or `scope`) parameter, substituted from the template.
4. A token minted with a short `exp` is renewed by the next operation; the broker saw the `refresh_token` grant, and the presented refresh token is not re-presentable.
5. `lore login --token-type api-key --no-browser` exchanges the API key for an authentication token.
6. A token minted without any root-domain source fails the login or the exchange (fail-closed check).

Scenarios 1–4 and 6 are automated against the fake provider in `scripts/test/test_auth_oidc.py`; run the same script with the broker's issuer to use it as the harness for the real sync.
