"""Smoke tests for the client OIDC path.

The device-grant tests come from upstream and run against
`mock_oidc_provider`. The refresh, revocation and Tier 2 exchange tests are the
fork's regression surface for the re-landed patches and run against the
`FakeOidcIdp` in this file.
"""

# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
"""Smoke tests for `lore auth login` over the OIDC path: the device
authorization grant (RFC 8628) against a stub provider.

The module launches one lore server that advertises an OIDC issuer and no
gRPC auth service, so every client takes the OIDC path. `[server.auth]` names
the stub as `jwt_issuer`, which the server resolves through the stub's
discovery document at startup, and `[server.auth.oidc]` names the public
client the CLI presents. The stub (see mock_oidc_provider.py) serves
discovery, the device authorization endpoint, the token endpoint and a JWKS,
and mints RS256 access tokens.

What this ticket can get wrong is the shape of the two requests and the
mapping of the token endpoint's answers, both asserted on the wire here. The
same login against a real provider is the fixture repository's job.
"""

import logging
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from error_types import LoreException, NotAuthenticatedError
from lore_server import (
    _kill_server_by_pid,
    allocate_free_port,
    generate_server_config,
    launch_lore_server,
)
from mock_oidc_provider import (
    DEVICE_CODE_GRANT,
    PAIRWISE_USER,
    MockOidcProvider,
    OidcUser,
)

from lore import Lore

logger = logging.getLogger(__name__)

pytestmark = pytest.mark.xdist_group("auth_oidc")


OIDC_CONFIG = """

# --- appended by test_auth_oidc.py: an OIDC issuer and no gRPC auth service ---
[server.auth]
jwt_issuer = "{issuer}"
jwt_audience = ["{audience}"]
permission_claim = "permissions"

[server.auth.oidc]
client_id = "{client_id}"
scopes = ["openid"]
"""


@pytest.fixture(scope="module")
def oidc_env(request, tmp_path_factory, lore_server_executable_path):
    """A lore server advertising the stub as its OIDC provider."""
    provider = MockOidcProvider().start()

    shared_port = allocate_free_port()
    ports = {
        "quic": shared_port,
        "grpc": shared_port,
        "http": allocate_free_port(),
        "internal": allocate_free_port(),
    }
    server_root, server_env = generate_server_config(request, tmp_path_factory, ports)
    config_path = server_root / "lore-server" / "config" / "gha.toml"
    config_path.write_text(
        config_path.read_text()
        + OIDC_CONFIG.format(
            issuer=provider.issuer,
            audience=provider.audience[0],
            client_id=provider.client_id,
        )
    )
    server_proc, server_log_path, server_log_fd = launch_lore_server(
        server_root, server_env, lore_server_executable_path
    )
    try:
        yield SimpleNamespace(
            provider=provider,
            remote_url=f"lore://127.0.0.1:{shared_port}/",
            server_log=server_log_path,
        )
    finally:
        _kill_server_by_pid(server_proc.pid, server_log_path, label="auth-oidc server")
        server_log_fd.close()
        provider.stop()


@pytest.fixture(autouse=True)
def _reset_provider(oidc_env):
    oidc_env.provider.reset()


@pytest.fixture
def make_repo(oidc_env, new_lore_repo, scratch_dir):
    """A repository against the OIDC server, with a token store of its own."""

    def _make_repo(**environment_vars: str) -> Lore:
        auth_store = scratch_dir("auth-store", create=True)
        environment_vars = {"LORE_AUTH_PATH": str(auth_store), **environment_vars}
        return new_lore_repo(
            remote_url=oidc_env.remote_url,
            create_repo=False,
            environment_vars=environment_vars,
        )

    return _make_repo


def assert_device_grant_on_the_wire(provider: MockOidcProvider, polls: int) -> None:
    """One device authorization request naming the client and the scopes,
    then `polls` token requests carrying the device code grant."""
    device = provider.requests_to("/device")
    assert len(device) == 1
    assert device[0].form == {
        "client_id": provider.client_id,
        "scope": "openid offline_access",
    }
    token = provider.requests_to("/token")
    assert len(token) == polls, [r.form.get("grant_type") for r in token]
    for request in token:
        assert request.form == {
            "grant_type": DEVICE_CODE_GRANT,
            "device_code": provider.device_code,
            "client_id": provider.client_id,
        }
        assert "authorization" not in request.headers


def assert_user_logged_in(repo: Lore, provider: MockOidcProvider) -> None:
    """The access token is stored under the user its `sub` names, at the
    endpoint the OIDC path is keyed by."""
    listing = repo.run(urc_args=["auth", "list"])
    assert f"oidc+{provider.issuer}" in listing
    assert provider.user.user_id in listing


@pytest.mark.smoke
def test_login_without_a_browser_completes_the_device_grant(oidc_env, make_repo):
    """`auth login --no-browser` prints the verification URL and the code,
    polls the token endpoint through `authorization_pending` and `slow_down`,
    and stores the access token under the user the token names."""
    provider = oidc_env.provider
    provider.script_polls(["authorization_pending", "slow_down"])
    repo = make_repo()

    output = repo.run(urc_args=["auth", "login", oidc_env.remote_url, "--no-browser"])

    assert "Login at:" in output
    assert provider.verification_uri_complete in output
    assert f"Code: {provider.user_code}" in output
    assert "Authentication successful" in output
    assert_device_grant_on_the_wire(provider, polls=3)
    assert_user_logged_in(repo, provider)


@pytest.mark.smoke
@pytest.mark.skipif(sys.platform != "linux", reason="Stubs the browser through xdg-open")
def test_login_with_a_browser_opens_the_verification_url(
    oidc_env, make_repo, scratch_dir
):
    """`auth login` hands `verification_uri_complete` to the browser, here an
    `xdg-open` on PATH that records what it was asked to open, and completes
    the same grant."""
    provider = oidc_env.provider
    browser_dir = scratch_dir("browser", create=True)
    opened = Path(browser_dir) / "opened-url"
    xdg_open = Path(browser_dir) / "xdg-open"
    xdg_open.write_text(f'#!/bin/sh\nprintf \'%s\' "$1" > "{opened}"\n')
    xdg_open.chmod(xdg_open.stat().st_mode | stat.S_IXUSR)
    repo = make_repo(PATH=f"{browser_dir}{os.pathsep}{os.environ['PATH']}")

    output = repo.run(urc_args=["auth", "login", oidc_env.remote_url])

    assert opened.read_text() == provider.verification_uri_complete
    # The code is shown so the user can confirm it on the page (RFC 8628
    # §3.3.1); the URL went to the browser rather than the terminal.
    assert f"Code: {provider.user_code}" in output
    assert "Authentication successful" in output
    assert_device_grant_on_the_wire(provider, polls=1)
    assert_user_logged_in(repo, provider)


@pytest.mark.smoke
def test_a_declined_login_stops_polling_at_once(oidc_env, make_repo):
    """`access_denied` ends the login as `NotAuthenticated` on the first poll
    that reports it, rather than polling on until the session expires."""
    provider = oidc_env.provider
    provider.script_polls(["access_denied"])
    repo = make_repo()

    with pytest.raises(NotAuthenticatedError):
        repo.run(urc_args=["auth", "login", oidc_env.remote_url, "--no-browser"])

    assert_device_grant_on_the_wire(provider, polls=1)
    assert provider.user.user_id not in repo.run(urc_args=["auth", "list"])


@pytest.mark.smoke
def test_an_expired_session_fails_the_login(oidc_env, make_repo):
    """`expired_token` ends the login on the poll that reports it, as a
    failure of its own rather than a denial."""
    provider = oidc_env.provider
    provider.script_polls(["expired_token"])
    repo = make_repo()

    with pytest.raises(LoreException) as failure:
        repo.run(urc_args=["auth", "login", oidc_env.remote_url, "--no-browser"])

    assert not isinstance(failure.value, NotAuthenticatedError)
    assert_device_grant_on_the_wire(provider, polls=1)


def seed_and_commit(repo: Lore, **kwargs) -> None:
    """One file staged and committed, under the global options `kwargs`."""
    with repo.open_file("seed.txt", "w+") as f:
        f.write("seed\n")
    repo.stage(scan=True, **kwargs)
    repo.commit("seed", **kwargs)


@pytest.mark.smoke
def test_login_records_the_tokens_identity_claim(oidc_env, make_repo):
    """The token carries `identity`, so it is stored under that value and
    not the pairwise `sub`, and `auth list` reports it."""
    provider = oidc_env.provider
    provider.user = PAIRWISE_USER
    repo = make_repo()

    output = repo.run(urc_args=["auth", "login", oidc_env.remote_url, "--no-browser"])

    assert "Authentication successful" in output
    listing = repo.run(urc_args=["auth", "list"])
    assert PAIRWISE_USER.identity in listing
    assert PAIRWISE_USER.user_id not in listing


@pytest.mark.smoke
def test_a_commit_after_login_records_the_tokens_identity(
    oidc_env, new_lore_repo, scratch_dir
):
    """A revision made after login names the `identity` value as its creator,
    and the server authorizes the creating request as the same identity."""
    oidc_env.provider.user = PAIRWISE_USER
    auth_store = scratch_dir("auth-store", create=True)
    repo = new_lore_repo(
        remote_url=oidc_env.remote_url,
        environment_vars={"LORE_AUTH_PATH": str(auth_store)},
        create_repo=False,
    )
    repo.run(urc_args=["auth", "login", oidc_env.remote_url, "--no-browser"])
    repo.repository_create()
    seed_and_commit(repo)

    rev = repo.revision_info(metadata=True)
    assert rev.creator == PAIRWISE_USER.identity, rev.creator
    server_log = Path(oidc_env.server_log).read_text(errors="replace")
    assert f'user_id="{PAIRWISE_USER.identity}"' in server_log
    assert f'user_id="{PAIRWISE_USER.user_id}"' not in server_log


@pytest.mark.smoke
def test_a_push_after_login_sends_the_login_token_unexchanged(oidc_env, make_repo):
    """The server advertises no partition template, so the deployment is on
    Tier 1: the login token authorizes the push itself, and the provider is
    asked for no exchange."""
    provider = oidc_env.provider
    repo = make_repo()
    repo.run(urc_args=["auth", "login", oidc_env.remote_url, "--no-browser"])
    repo.repository_create()
    seed_and_commit(repo)

    repo.push()

    grants = [r.form.get("grant_type") for r in provider.requests_to("/token")]
    assert grants == [DEVICE_CODE_GRANT], grants


@pytest.mark.smoke
def test_a_supplied_token_and_an_offline_commit_record_the_identity(
    oidc_env, new_lore_repo, scratch_dir
):
    """A token passed with `--identity-token`, and a commit made offline with
    it, record the token's `identity` value too: the identity is read from
    the token wherever the token is, with no environment response."""
    token = oidc_env.provider.mint_token(PAIRWISE_USER)
    auth_store = scratch_dir("auth-store", create=True)
    repo = new_lore_repo(
        remote_url=oidc_env.remote_url,
        environment_vars={"LORE_AUTH_PATH": str(auth_store)},
        create_repo=False,
    )
    repo.repository_create(identity_token=token)
    seed_and_commit(repo, identity_token=token, offline=True)

    rev = repo.revision_info(metadata=True, identity_token=token, offline=True)
    assert rev.creator == PAIRWISE_USER.identity, rev.creator


@pytest.mark.smoke
def test_login_with_an_empty_identity_claim_is_refused(oidc_env, make_repo):
    """An `identity` claim that is present but empty names no one: the login
    fails, naming the claim, and nothing is stored."""
    provider = oidc_env.provider
    provider.user = OidcUser("empty-identity-sub", "Empty", "empty", identity="")
    repo = make_repo()

    with pytest.raises(LoreException) as refused:
        repo.run(urc_args=["auth", "login", oidc_env.remote_url, "--no-browser"])

    assert "identity" in str(refused.value)
    assert "empty-identity-sub" not in repo.run(urc_args=["auth", "list"])


import base64
import collections
import json
import logging
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from lore_server import (
    ServerException,
    _kill_server_by_pid,
    allocate_free_port,
    generate_server_config,
    launch_lore_server,
)

from lore import Lore


CLIENT_ID = "lore-smoke-client"
AUDIENCE = "lore-smoke-audience"
USER_ID = "oidc-user"
USER_NAME = "Ada Lovelace"

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

# The device poll cadence the fake advertises: the client refuses anything
# below one second anyway.
DEVICE_INTERVAL_SECONDS = 1
DEVICE_LIFETIME_SECONDS = 1800
DEFAULT_TOKEN_LIFETIME_SECONDS = 3600

TIER1_CONFIG = """

# --- appended by test_auth_oidc.py: OIDC-only authentication, Tier 1 ---
[server.auth]
jwt_issuer = "{issuer}"
jwt_audience = ["{audience}"]
permission_claim = "groups"

[server.auth.jwk]
endpoint = "{jwks_url}"

[server.auth.oidc]
client_id = "{client_id}"
scopes = ["openid", "profile"]
"""

TIER2_CONFIG = """

# --- appended by test_auth_oidc.py: OIDC-only authentication, Tier 2 ---
[server.auth]
jwt_issuer = "{issuer}"
jwt_audience = ["{audience}"]
resource_claim = "resources"
resource_id_template = "https://lore.example.com/partitions/{{id}}"

[server.auth.jwk]
endpoint = "{jwks_url}"

[server.auth.oidc]
client_id = "{client_id}"
resource_template = "https://lore.example.com/partitions/{{id}}"
"""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _form_params(body: bytes) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(body.decode("utf-8")).items()}


class _IdpHTTPServer(ThreadingHTTPServer):
    """Carries the owning `FakeOidcIdp` for its request handler."""

    idp: "FakeOidcIdp"

    daemon_threads = True


class FakeOidcIdp:
    """A fake OpenID Connect provider on a loopback port.

    Serves discovery, a JWKS of one RS256 key, the RFC 8628 device grant,
    and the token endpoint with `device_code`, `refresh_token`, and RFC 8693
    token-exchange grants. One device session at a time, approved on
    creation. Minted claims are the defaults below merged with whatever
    `set_claims` last installed — an absolute `exp` in the override pins the
    lifetime, and `set_claims({})` returns to the defaults.
    """

    def __init__(self) -> None:
        self._private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.kid = "fake-oidc-kid-1"
        self._server: _IdpHTTPServer | None = None
        self._port = 0
        # Reentrant: the token handlers mint under the lock they already hold.
        self._lock = threading.RLock()
        self.auto_approve = True
        # The outstanding device session: its code, whether it is approved,
        # and the RFC 8628 §3.5 error the next polls answer with.
        self._device_code: str | None = None
        self._device_counter = 0
        self._approved = False
        self._device_error: str | None = None
        self._slow_downs = 0
        # Live refresh tokens, consumed on use.
        self._refresh_tokens: set[str] = set()
        self._refresh_counter = 0
        self.last_refresh_token: str | None = None
        # Claims merged over the defaults of every minted access token.
        self._claims_extra: dict = {}
        self.opaque_access_token = False
        # What the fake has seen, for assertions.
        self.path_hits: collections.Counter[str] = collections.Counter()
        self.grant_hits: collections.Counter[str] = collections.Counter()
        self.exchange_requests: list[dict[str, str]] = []
        self.device_requests: list[dict[str, str]] = []
        self.revocation_requests: list[dict[str, str]] = []

    # -- lifecycle -------------------------------------------------------

    def start(self) -> "FakeOidcIdp":
        import socket

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self._port = sock.getsockname()[1]
        sock.close()
        server = _IdpHTTPServer(("127.0.0.1", self._port), _IdpRequestHandler)
        server.idp = self
        self._server = server
        threading.Thread(
            target=server.serve_forever, daemon=True, name="fake-oidc-idp"
        ).start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    @property
    def issuer(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}/jwks"

    # -- test controls ---------------------------------------------------

    def reset(self) -> None:
        """Between tests: counters, session state, claim overrides."""
        with self._lock:
            self._device_code = None
            self._device_counter = 0
            self._approved = False
            self._device_error = None
            self._slow_downs = 0
            self._refresh_tokens.clear()
            self.last_refresh_token = None
            self._claims_extra = {}
            self.opaque_access_token = False
            self.path_hits.clear()
            self.grant_hits.clear()
            self.exchange_requests.clear()
            self.device_requests.clear()
            self.revocation_requests.clear()

    def set_claims(self, claims: dict) -> None:
        """Replaces the claims merged into every minted access token."""
        with self._lock:
            self._claims_extra = dict(claims)

    def expire_device(self) -> None:
        with self._lock:
            self._device_error = "expired_token"

    def deny_device(self) -> None:
        with self._lock:
            self._device_error = "access_denied"

    def slow_down_device(self, count: int) -> None:
        with self._lock:
            self._slow_downs = count

    def answer_opaque_tokens(self) -> None:
        with self._lock:
            self.opaque_access_token = True

    def hits(self, suffix: str) -> int:
        with self._lock:
            return sum(
                count for path, count in self.path_hits.items() if path.endswith(suffix)
            )

    # -- minting ---------------------------------------------------------

    def jwks(self) -> dict:
        numbers = self._private_key.public_key().public_numbers()

        def uint_b64(value: int) -> str:
            return _b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))

        return {
            "keys": [
                {
                    "kty": "RSA",
                    "n": uint_b64(numbers.n),
                    "e": uint_b64(numbers.e),
                    "kid": self.kid,
                    "alg": "RS256",
                    "use": "sig",
                }
            ]
        }

    def mint_token(self, extra: dict | None = None) -> str:
        """A signed JWT: the standard defaults with the `set_claims`
        override, plus this call's `extra` on top."""
        now = int(time.time())
        with self._lock:
            claims = {
                "iss": self.issuer,
                "sub": USER_ID,
                "aud": [AUDIENCE],
                "iat": now,
                "exp": now + DEFAULT_TOKEN_LIFETIME_SECONDS,
                "name": USER_NAME,
                "preferred_username": USER_NAME.lower().replace(" ", "-"),
                "root_domains": ["127.0.0.1"],
            }
            claims.update(self._claims_extra)
        if extra:
            claims.update(extra)
        if self.opaque_access_token:
            return "an-opaque-access-token"
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64url(json.dumps(claims, separators=(",", ":")).encode())
        ).encode("ascii")
        signature = self._private_key.sign(
            signing_input, padding.PKCS1v15(), hashes.SHA256()
        )
        return signing_input.decode("ascii") + "." + _b64url(signature)

    # -- request handling (called from the HTTP thread) ------------------

    def handle(self, path: str, params: dict[str, str]) -> tuple[int, dict | None]:
        with self._lock:
            self.path_hits[path] += 1
            if path == "/.well-known/openid-configuration":
                return 200, {
                    "issuer": self.issuer,
                    "token_endpoint": f"{self.issuer}/token",
                    "jwks_uri": self.jwks_url,
                    "device_authorization_endpoint": f"{self.issuer}/device",
                    "revocation_endpoint": f"{self.issuer}/revoke",
                }
            if path == "/jwks":
                return 200, self.jwks()
            if path == "/device":
                return self._handle_device(params)
            if path == "/revoke":
                # RFC 7009 §2.2: a bare 200 with an empty body, even for an
                # unknown token.
                self.revocation_requests.append(dict(params))
                return 200, None
            if path == "/token":
                return self._handle_token(params)
            return 404, {"error": "not_found"}

    def _handle_device(self, params: dict[str, str]) -> tuple[int, dict]:
        self._device_counter += 1
        self._device_code = f"dev-{self._device_counter}"
        self._approved = self.auto_approve
        self._device_error = None
        self.device_requests.append(dict(params))
        return 200, {
            "device_code": self._device_code,
            "user_code": "WDJB-MJHT",
            "verification_uri": f"{self.issuer}/activate",
            "verification_uri_complete": f"{self.issuer}/activate?user_code=WDJB-MJHT",
            "expires_in": DEVICE_LIFETIME_SECONDS,
            "interval": DEVICE_INTERVAL_SECONDS,
        }

    def _handle_token(self, params: dict[str, str]) -> tuple[int, dict]:
        grant = params.get("grant_type", "")
        self.grant_hits[grant] += 1
        if grant == DEVICE_GRANT:
            if params.get("device_code") != self._device_code:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "unknown device code",
                }
            if self._slow_downs > 0:
                self._slow_downs -= 1
                return 400, {"error": "slow_down"}
            if self._device_error is not None:
                return 400, {"error": self._device_error}
            if not self._approved:
                return 400, {"error": "authorization_pending"}
            return 200, self._token_response()
        if grant == "refresh_token":
            presented = params.get("refresh_token", "")
            if presented not in self._refresh_tokens:
                return 400, {
                    "error": "invalid_grant",
                    "error_description": "the refresh token is one-time and has been used or was never issued",
                }
            self._refresh_tokens.discard(presented)
            return 200, self._token_response()
        if grant == TOKEN_EXCHANGE_GRANT:
            self.exchange_requests.append(dict(params))
            # The broker mints a grant for the resource the exchange named:
            # the requested resource (or scope) is what the token may touch.
            extra: dict = {}
            named = params.get("resource") or params.get("scope")
            if named:
                extra["resources"] = [
                    {
                        "resource_id": named,
                        "permission": ["read", "write", "admin"],
                    }
                ]
            return 200, self._token_response(extra)
        return 400, {"error": "unsupported_grant_type"}

    def _token_response(self, extra: dict | None = None) -> dict:
        self._refresh_counter += 1
        refresh = f"refresh-{self._refresh_counter}"
        self._refresh_tokens.add(refresh)
        self.last_refresh_token = refresh
        return {
            "access_token": self.mint_token(extra),
            "refresh_token": refresh,
            "token_type": "Bearer",
            "expires_in": DEFAULT_TOKEN_LIFETIME_SECONDS,
            "scope": "openid profile offline_access",
        }


class _IdpRequestHandler(BaseHTTPRequestHandler):
    """Routes one request into the owning `FakeOidcIdp`."""

    @property
    def idp(self) -> "FakeOidcIdp":
        server = self.server
        assert isinstance(server, _IdpHTTPServer)
        return server.idp

    def _read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        return _form_params(body) if body else {}

    def _answer(self, status: int, payload: dict | None) -> None:
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        status, payload = self.idp.handle(path, {})
        self._answer(status, payload)

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        status, payload = self.idp.handle(path, self._read_form())
        self._answer(status, payload)

    def log_message(self, format: str, *args) -> None:
        logger.debug("fake-oidc-idp: %s", format % args)


def append_oidc_config(server_root: Path, config: str) -> None:
    config_path = server_root / "lore-server" / "config" / "gha.toml"
    config_path.write_text(config_path.read_text() + config)


def _wait_for_advertised_issuer(log_path, issuer: str, timeout: float = 60.0) -> bool:
    """Waits until the server log reports the OIDC advertisement naming
    `issuer`.

    The launch harness health-checks whatever answers the reserved port, so
    under a parallel run a different test's server can win the port race:
    that server's environment advertises no OIDC path, and every login
    against it fails with "No authentication configured on server". The
    server logs the advertisement (`Advertising the OIDC provider to
    clients issuer=...`) once its own discovery fetch succeeded, so the
    line is proof this log belongs to a server advertising this fake.
    """
    deadline = time.monotonic() + timeout
    needle = "Advertising the OIDC provider to clients"
    while time.monotonic() < deadline:
        try:
            text = Path(log_path).read_text(errors="replace")
        except OSError:
            text = ""
        if needle in text and issuer in text:
            return True
        time.sleep(0.2)
    return False


def launch_oidc_server(request, tmp_path_factory, executable_path, config: str):
    """A lore server authenticating against a fresh fake IdP, with no
    `auth_url`. The fake must be up before the server starts: the server
    reads the discovery document and the JWKS at startup.

    Retries with fresh ports when the launch lost the port race (see
    [`_wait_for_advertised_issuer`]); the caller owns teardown of the
    returned pair."""
    for attempt in range(3):
        idp = FakeOidcIdp().start()
        shared_port = allocate_free_port()
        ports = {
            "quic": shared_port,
            "grpc": shared_port,
            "http": allocate_free_port(),
            "internal": allocate_free_port(),
        }
        server_root, server_env = generate_server_config(
            request, tmp_path_factory, ports
        )
        append_oidc_config(
            server_root,
            config.format(
                issuer=idp.issuer,
                audience=AUDIENCE,
                jwks_url=idp.jwks_url,
                client_id=CLIENT_ID,
            ),
        )
        try:
            server_proc, server_log_path, server_log_fd = launch_lore_server(
                server_root, server_env, executable_path
            )
        except ServerException:
            # The port race can hand the reservation to another process
            # entirely; retry on fresh ports rather than fail the module.
            idp.stop()
            continue
        server = SimpleNamespace(
            proc=server_proc,
            log=server_log_path,
            log_fd=server_log_fd,
            remote_url=f"lore://127.0.0.1:{shared_port}/",
        )
        if _wait_for_advertised_issuer(server_log_path, idp.issuer):
            return idp, server
        # Not our server (or it failed to advertise): tear down and retry.
        stop_oidc_server(server, idp, label=f"oidc launch attempt {attempt}")
    raise RuntimeError(
        "the OIDC-only lore server never advertised the fake issuer; see the "
        "kept test data for its server log"
    )


def stop_oidc_server(server: SimpleNamespace, idp: FakeOidcIdp, label: str) -> None:
    _kill_server_by_pid(server.proc.pid, server.log, label=label)
    server.log_fd.close()
    idp.stop()


def make_actor_factory(new_lore_repo, scratch_dir, remote_url: str):
    """A per-test actor factory: isolated token store, OIDC mode requested."""

    def _make_actor(label: str):
        auth_store = scratch_dir(f"oidc-auth-store-{label}", create=True)
        environment_vars = {
            "LORE_AUTH_PATH": str(auth_store),
            "LORE_AUTH_MODE": "oidc",
        }

        def make_repo(**kwargs) -> Lore:
            kwargs.setdefault("remote_url", remote_url)
            kwargs.setdefault("create_repo", False)
            kwargs.setdefault("environment_vars", dict(environment_vars))
            return new_lore_repo(**kwargs)

        return SimpleNamespace(make_repo=make_repo)

    return _make_actor


@pytest.fixture(scope="module")
def fork_oidc_env(request, tmp_path_factory, lore_server_executable_path):
    """The Tier 1 server: OIDC-only, global-grants authorizer."""
    idp, server = launch_oidc_server(
        request, tmp_path_factory, lore_server_executable_path, TIER1_CONFIG
    )
    try:
        yield SimpleNamespace(idp=idp, remote_url=server.remote_url)
    finally:
        stop_oidc_server(server, idp, label="oidc tier1 server")


@pytest.fixture(scope="function")
def fork_oidc_actor(fork_oidc_env, new_lore_repo, scratch_dir):
    """An actor factory against the Tier 1 server."""
    return make_actor_factory(new_lore_repo, scratch_dir, fork_oidc_env.remote_url)


@pytest.fixture(autouse=True)
def _reset_idp(fork_oidc_env):
    """Every test starts from clean fake state and default claims."""
    fork_oidc_env.idp.reset()


def login_interactive(repo: Lore, remote_url: str) -> str:
    """`lore auth login --no-browser` under the actor's LORE_AUTH_MODE."""
    return repo.run(urc_args=["auth", "login", remote_url, "--no-browser"])


def commit_file(repo: Lore, name: str = "hello.txt", content: str = "hello") -> None:
    (Path(repo.path) / name).write_text(content)
    repo.file_stage(name)
    repo.revision_commit(f"add {name}")
    repo.push()


@pytest.mark.smoke
def test_oidc_device_grant_login_completes_and_identity_persists(fork_oidc_env, fork_oidc_actor):
    """`--auth-mode oidc` login runs the RFC 8628 device grant against the
    advertised issuer and stores the identity under it; `auth info` and
    `auth list` resolve it back."""
    idp = fork_oidc_env.idp
    actor = fork_oidc_actor("login")
    repo = actor.make_repo()

    output = login_interactive(repo, fork_oidc_env.remote_url)

    assert "Login at:" in output
    assert f"{idp.issuer}/activate?user_code=WDJB-MJHT" in output
    assert "Authentication successful" in output
    assert idp.hits("/device") == 1, "one device authorization per login"
    assert idp.grant_hits[DEVICE_GRANT] >= 1, (
        "the client polls the token endpoint with the device grant"
    )
    assert idp.device_requests, "the device endpoint saw the client_id and scope"
    assert "offline_access" in idp.device_requests[0]["scope"], (
        "the client requests offline_access so refresh tokens outlive the session"
    )

    # The identity persists under the issuer: `auth list` resolves the
    # store keyed by the issuer.
    listing = repo.run(urc_args=["auth", "list"])
    assert USER_ID in listing
    assert idp.issuer in listing


@pytest.mark.smoke
def test_authenticated_operation_succeeds_under_tier1_authorizer(fork_oidc_env, fork_oidc_actor):
    """After login, repository create and push run under the global-grants
    authorizer reading the presented token's `groups` claim."""
    idp = fork_oidc_env.idp
    idp.set_claims({"groups": ["admin"]})
    actor = fork_oidc_actor("tier1")
    login_interactive(actor.make_repo(), fork_oidc_env.remote_url)

    repo_id = f"oidc-tier1-{uuid.uuid4().hex[:8]}"
    repo = actor.make_repo(repo_id=repo_id)
    repo.repository_create(repo_id=repo_id, identity=USER_ID)

    # `auth info` resolves the effective auth endpoint (the issuer) from
    # the repository's remote environment and reads the identity from the
    # store keyed by it.
    info = repo.run(urc_args=["auth", "info"])
    assert USER_ID in info

    commit_file(repo)


@pytest.mark.smoke
def test_expired_token_is_renewed_by_the_refresh_grant(fork_oidc_env, fork_oidc_actor):
    """A token minted with a short `exp` is renewed on the next operation:
    the refresh grant is hit, the rotation is persisted, and the operation
    succeeds with the renewed token."""
    idp = fork_oidc_env.idp
    idp.set_claims({"groups": ["admin"], "exp": int(time.time()) + 2})
    actor = fork_oidc_actor("refresh")
    login_interactive(actor.make_repo(), fork_oidc_env.remote_url)

    # The login token dies within seconds; the renewal must hand out the
    # default lifetime, so clear the override before the refresh answers.
    idp.set_claims({"groups": ["admin"]})
    time.sleep(3)

    refreshes_before = idp.grant_hits["refresh_token"]
    repo_id = f"oidc-refresh-{uuid.uuid4().hex[:8]}"
    repo = actor.make_repo(repo_id=repo_id)
    repo.repository_create(repo_id=repo_id, identity=USER_ID)
    commit_file(repo)

    assert idp.grant_hits["refresh_token"] > refreshes_before, (
        "an expired token must be renewed through the refresh grant"
    )
    assert idp.last_refresh_token is not None


@pytest.mark.smoke
def test_logout_revokes_tokens_at_the_provider(fork_oidc_env, fork_oidc_actor):
    """`auth logout` posts the stored access and refresh tokens to the
    advertised revocation endpoint and still clears the local store."""
    idp = fork_oidc_env.idp
    actor = fork_oidc_actor("logout")
    # The Tier 1 global-grants authorizer reads `groups` from the token;
    # repository creation below needs the grant.
    idp.set_claims({"groups": ["admin"]})
    scratch = actor.make_repo()
    login_interactive(scratch, fork_oidc_env.remote_url)
    refresh = idp.last_refresh_token

    # `auth logout` resolves the endpoint from the repository's remote
    # environment, so the repository is created here — after the login
    # that authenticates its creation — against the same actor's token
    # store.
    repo = actor.make_repo(
        repo_id=f"oidc-logout-{uuid.uuid4().hex[:8]}", create_repo=True
    )

    output = repo.run(urc_args=["auth", "logout"])
    assert "Logged out" in output
    assert idp.hits("/revoke") == 2, "both the access and the refresh token are revoked"
    revoked = {r["token_type_hint"]: r["token"] for r in idp.revocation_requests}
    assert revoked["refresh_token"] == refresh
    assert revoked["access_token"], "the authentication token is revoked too"

    listing = repo.run(urc_args=["auth", "list"])
    assert USER_ID not in listing, "logout clears the local store"


@pytest.fixture(scope="function")
def tier2_env(request, tmp_path_factory, lore_server_executable_path):
    """The Tier 2 server: resource template configured, resource-grants
    authorizer reading the minted tokens' `resources` claim."""
    idp, server = launch_oidc_server(
        request, tmp_path_factory, lore_server_executable_path, TIER2_CONFIG
    )
    try:
        yield SimpleNamespace(idp=idp, remote_url=server.remote_url)
    finally:
        stop_oidc_server(server, idp, label="oidc tier2 server")


@pytest.fixture(scope="function")
def tier2_actor(tier2_env, new_lore_repo, scratch_dir):
    """An actor factory against the Tier 2 server."""
    return make_actor_factory(new_lore_repo, scratch_dir, tier2_env.remote_url)


@pytest.mark.smoke
def test_tier2_exchange_mints_a_resource_scoped_token(tier2_env, tier2_actor):
    """With a Tier 2 template configured, a repository operation mints a
    partition-scoped token: the exchange grant carries the template with
    `{id}` replaced by the repository ID, and the server accepts the
    operation under the resource-grants claim."""
    idp = tier2_env.idp
    repo_id = f"oidc-tier2-{uuid.uuid4().hex[:8]}"
    actor = tier2_actor("tier2")
    # The login token authorizes the create itself: a token minted with the
    # configured wildcard grant is admitted for any partition, the new one
    # included. The exchange then scopes every later operation.
    idp.set_claims({"resources": [{"resource_id": "urc-*", "permission": ["admin"]}]})
    login_interactive(actor.make_repo(), tier2_env.remote_url)

    # What the minted (exchanged) token must carry for the server's
    # resource-grants authorizer to admit the partition.
    idp.set_claims(
        {
            "resources": [
                {
                    "resource_id": f"urc-{repo_id}",
                    "permission": ["read", "write"],
                }
            ],
        }
    )

    repo = actor.make_repo(repo_id=repo_id)
    repo.repository_create(repo_id=repo_id, identity=USER_ID)
    commit_file(repo)

    exchanges = idp.exchange_requests
    assert exchanges, "the repository operations must go through the exchange"
    assert all(e["grant_type"] == TOKEN_EXCHANGE_GRANT for e in exchanges)
    assert all(e["subject_token_type"] == ACCESS_TOKEN_TYPE for e in exchanges)
    for exchange in exchanges:
        resource = exchange["resource"]
        assert resource.startswith("https://lore.example.com/partitions/"), (
            f"the template is substituted, not sent verbatim: {resource}"
        )
        # The `{id}` is the partition's own id — a storage session exchanges
        # for its partition, not for the repository name.
        assert resource != "https://lore.example.com/partitions/{id}"
        assert "scope" not in exchange, (
            "a resource template names the partition as a resource, one per request"
        )
