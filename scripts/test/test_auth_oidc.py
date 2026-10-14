# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
"""Smoke tests for the client OIDC path: device grant, refresh, and the
RFC 8693 exchange, against an in-process fake identity provider.

The module launches a fake OIDC IdP (plain HTTP on loopback) and one or two
lore servers configured with `[server.auth]` + `[server.auth.oidc]` and **no
`auth_url`** — the OIDC-only deployment the device grant exists for. The
server verifies the IdP's RS256 tokens against the IdP's JWKS endpoint; the
fake mints real signatures with the same recipe as `mock_auth_server.py`.

The fake has no behavior of its own beyond the standard grant shapes: device
sessions are approved as soon as they are created (the tests exercise the
happy path; refusal and expiry are unit-level), minted claims are merged
over sensible defaults, and refresh tokens rotate one-time. Every
token-request parameter the client sends is recorded so tests can assert
the wire contract (the `resource` parameter of a Tier 2 exchange, the
refresh grant being hit).

LP-011/LP-012 acceptance: this module is the end-to-end evidence for the
client OIDC login, refresh wiring, and Tier 2 exchange; the broker contract
(`docs/developing/oidc-broker-contract.md`) describes the same surface from
the provider's side.
"""

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

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.smoke, pytest.mark.xdist_group("auth_oidc")]

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

    def handle(self, path: str, params: dict[str, str]) -> tuple[int, dict]:
        with self._lock:
            self.path_hits[path] += 1
            if path == "/.well-known/openid-configuration":
                return 200, {
                    "issuer": self.issuer,
                    "token_endpoint": f"{self.issuer}/token",
                    "jwks_uri": self.jwks_url,
                    "device_authorization_endpoint": f"{self.issuer}/device",
                }
            if path == "/jwks":
                return 200, self.jwks()
            if path == "/device":
                return self._handle_device(params)
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

    def _answer(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
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
def oidc_env(request, tmp_path_factory, lore_server_executable_path):
    """The Tier 1 server: OIDC-only, global-grants authorizer."""
    idp, server = launch_oidc_server(
        request, tmp_path_factory, lore_server_executable_path, TIER1_CONFIG
    )
    try:
        yield SimpleNamespace(idp=idp, remote_url=server.remote_url)
    finally:
        stop_oidc_server(server, idp, label="oidc tier1 server")


@pytest.fixture(scope="function")
def oidc_actor(oidc_env, new_lore_repo, scratch_dir):
    """An actor factory against the Tier 1 server."""
    return make_actor_factory(new_lore_repo, scratch_dir, oidc_env.remote_url)


@pytest.fixture(autouse=True)
def _reset_idp(oidc_env):
    """Every test starts from clean fake state and default claims."""
    oidc_env.idp.reset()


def login_interactive(repo: Lore, remote_url: str) -> str:
    """`lore auth login --no-browser` under the actor's LORE_AUTH_MODE."""
    return repo.run(urc_args=["auth", "login", remote_url, "--no-browser"])


def commit_file(repo: Lore, name: str = "hello.txt", content: str = "hello") -> None:
    (Path(repo.path) / name).write_text(content)
    repo.file_stage(name)
    repo.revision_commit(f"add {name}")
    repo.push()


@pytest.mark.smoke
def test_oidc_device_grant_login_completes_and_identity_persists(oidc_env, oidc_actor):
    """`--auth-mode oidc` login runs the RFC 8628 device grant against the
    advertised issuer and stores the identity under it; `auth info` and
    `auth list` resolve it back."""
    idp = oidc_env.idp
    actor = oidc_actor("login")
    repo = actor.make_repo()

    output = login_interactive(repo, oidc_env.remote_url)

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
def test_authenticated_operation_succeeds_under_tier1_authorizer(oidc_env, oidc_actor):
    """After login, repository create and push run under the global-grants
    authorizer reading the presented token's `groups` claim."""
    idp = oidc_env.idp
    idp.set_claims({"groups": ["admin"]})
    actor = oidc_actor("tier1")
    login_interactive(actor.make_repo(), oidc_env.remote_url)

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
def test_expired_token_is_renewed_by_the_refresh_grant(oidc_env, oidc_actor):
    """A token minted with a short `exp` is renewed on the next operation:
    the refresh grant is hit, the rotation is persisted, and the operation
    succeeds with the renewed token."""
    idp = oidc_env.idp
    idp.set_claims({"groups": ["admin"], "exp": int(time.time()) + 2})
    actor = oidc_actor("refresh")
    login_interactive(actor.make_repo(), oidc_env.remote_url)

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
