# SPDX-FileCopyrightText: 2026 Epic Games, Inc.
# SPDX-License-Identifier: MIT
"""Repository permission enforcement against real authenticated servers."""

import json
import uuid
from pathlib import Path
from subprocess import CalledProcessError
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import grpc
import pytest
from error_types import LoreException
from grpc_probe import call, repository_metadata
from lore_server import (
    _kill_server_by_pid,
    allocate_free_port,
    generate_server_config,
    launch_lore_server,
)
from mock_auth_server import (
    USER1,
    MockAuthServer,
    check_user_permission_response,
    empty_response,
)
from protobuf_wire import encode_bytes_field, encode_string_field, parse_fields

pytestmark = [pytest.mark.smoke, pytest.mark.xdist_group("repository_permissions")]
REPOSITORY = "/lore.repository.v1.RepositoryService"
STORAGE = "/lore.storage.v1.StorageService"
LEGACY_STORAGE = "/urc.rpc.StorageService"
PERMISSIONS = [None, [], ["unknown"], ["read"], ["write"], ["admin"], ["owner"]]


@pytest.fixture(scope="module", params=["global", "resource", "legacy"])
def permission_server(request, tmp_path_factory, lore_server_executable_path):
    mock = MockAuthServer().start()
    mock.issuer = mock.jwks_url.rsplit("/", 1)[0]
    port = allocate_free_port()
    ports = {
        "quic": port,
        "grpc": port,
        "http": allocate_free_port(),
        "internal": allocate_free_port(),
    }
    root, environment = generate_server_config(request, tmp_path_factory, ports)
    environment["LORE__SERVER__GRPC_INTERNAL__ENABLED"] = "true"
    environment["LORE__SERVER__GRPC_INTERNAL__VERIFY_CLIENT_CERTS"] = "false"
    config = root / "lore-server" / "config" / "gha.toml"
    legacy = (
        f'\n[environment.endpoint]\nauth_url = "{mock.auth_url}"\n'
        if request.param == "legacy"
        else ""
    )
    policy = (
        'permission_claim = "permissions"'
        if request.param == "global"
        else 'resource_claim = "resources"'
        if request.param == "resource"
        else ""
    )
    with config.open("a") as output:
        output.write(
            f'{legacy}\n[server.auth]\njwt_issuer = "{mock.issuer}"\njwt_audience = ["{mock.audience[0]}"]\n{policy}\n[server.auth.jwk]\nendpoint = "{mock.jwks_url}"\n'
        )
    if request.param != "legacy":
        with config.open("a") as output:
            output.write('[server.auth.oidc]\nclient_id = "permission-test"\n')
            if request.param == "resource":
                output.write(
                    'resource_template = "https://lore.example/partitions/{id}"\n'
                )
    process, log, log_fd = launch_lore_server(
        root, environment, lore_server_executable_path
    )

    def token(repository, permissions, *, online=False, resources=None):
        grants = (
            resources
            if resources is not None
            else []
            if permissions is None
            else [{"resource_id": f"urc-{repository}", "permission": permissions}]
        )
        jwt = mock.mint_token(
            USER1,
            resources=None if online else grants,
            extra_claims={"permissions": permissions or []},
        )
        if online:
            mock.on(
                "CheckUserPermission", bearer=jwt, resource_id=f"urc-{repository}"
            ).respond(
                check_user_permission_response(f"urc-{repository}", permissions or [])
            )
        return jwt

    try:
        yield SimpleNamespace(
            tier=request.param,
            mock=mock,
            token=token,
            grpc=f"127.0.0.1:{port}",
            internal=f"127.0.0.1:{ports['internal']}",
            http=f"http://127.0.0.1:{ports['http']}",
            quic=f"lore://127.0.0.1:{port}/",
        )
    finally:
        _kill_server_by_pid(process.pid, log, label="repository-permissions server")
        log_fd.close()
        mock.stop()


def metadata(repository, token):
    return repository_metadata(repository) + (("authorization", f"Bearer {token}"),)


def create(server, repository, token, name=None, *, register_auth=True):
    if register_auth:
        server.mock.on("CreateResource", resource_id=f"urc-{repository}").respond(
            empty_response()
        )
    body = (
        encode_bytes_field(1, bytes.fromhex(repository))
        + encode_string_field(2, name or repository)
        + encode_bytes_field(4, uuid.uuid4().bytes)
        + encode_string_field(5, "main")
    )
    return call(
        server.grpc,
        f"{REPOSITORY}/RepositoryCreate",
        body,
        (("authorization", f"Bearer {token}"),),
    )


def http(server, repository, token, *, data=None, address=None):
    url = f"{server.http}/v1/repository/{repository}/content" + (
        f"/{address}" if address else ""
    )
    request = Request(
        url,
        data=data,
        headers={"Authorization": f"Bearer {token}"},
        method="PUT" if data is not None else "GET",
    )
    try:
        with urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except HTTPError as error:
        return error.code, error.read()


def stream_call(server, method, items, repository, token):
    with grpc.insecure_channel(server.grpc) as channel:
        rpc = channel.stream_stream(method, lambda body: body, lambda body: body)
        try:
            return grpc.StatusCode.OK, list(
                rpc(iter(items), metadata=metadata(repository, token), timeout=10)
            )
        except grpc.RpcError as error:
            return error.code(), []


@pytest.mark.parametrize("permissions", PERMISSIONS)
@pytest.mark.parametrize("online", [False, True], ids=["claims", "online"])
def test_read_write_matrix(permission_server, permissions, online):
    server = permission_server
    if online and server.tier != "legacy":
        pytest.skip("Online permission responses apply only to legacy auth")
    repository = uuid.uuid4().hex
    writer = server.token(repository, ["write"])
    assert create(server, repository, writer)[0] == grpc.StatusCode.OK
    status, body = http(server, repository, writer, data=b"original content")
    assert status == 200
    address = json.loads(body)["data"]["address"]
    token = server.token(repository, permissions, online=online)
    read = bool(permissions and set(permissions) & {"read", "write", "admin", "owner"})
    write = bool(permissions and set(permissions) & {"write", "admin", "owner"})
    code, _, _ = call(
        server.grpc,
        f"{REPOSITORY}/RepositoryGet",
        encode_bytes_field(1, bytes.fromhex(repository)),
        metadata(repository, token),
    )
    assert (code == grpc.StatusCode.OK) == read
    assert (http(server, repository, token, address=address)[0] == 200) == read
    assert (http(server, repository, token, data=b"new content")[0] == 200) == write
    key, initial, changed = b"k" * 32, b"i" * 32, b"c" * 32
    store = encode_bytes_field(1, key) + encode_bytes_field(2, initial)
    for service in [LEGACY_STORAGE, STORAGE]:
        assert (
            call(
                server.grpc,
                f"{service}/MutableStore",
                store,
                metadata(repository, writer),
            )[0]
            == grpc.StatusCode.OK
        )
        mutation = encode_bytes_field(1, key) + encode_bytes_field(2, changed)
        code, _, _ = call(
            server.grpc,
            f"{service}/MutableStore",
            mutation,
            metadata(repository, token),
        )
        assert (code == grpc.StatusCode.OK) == write
        assert (
            code == grpc.StatusCode.OK
            if write
            else code == grpc.StatusCode.PERMISSION_DENIED
        )
        code, body, _ = call(
            server.grpc,
            f"{service}/MutableLoad",
            encode_bytes_field(1, key),
            metadata(repository, writer),
        )
        assert code == grpc.StatusCode.OK
        assert parse_fields(body)[1][0] == (changed if write else initial)
        cas = (
            encode_bytes_field(1, key)
            + encode_bytes_field(2, changed if write else initial)
            + encode_bytes_field(3, b"x" * 32)
        )
        code, _, _ = call(
            server.grpc,
            f"{service}/MutableCompareAndSwap",
            cas,
            metadata(repository, token),
        )
        assert (code == grpc.StatusCode.OK) == write
    # Reject uploads before reading or spawning item tasks, on both storage services.
    if not write:
        for service in [LEGACY_STORAGE, STORAGE]:
            assert (
                stream_call(server, f"{service}/Put", [b""], repository, token)[0]
                == grpc.StatusCode.PERMISSION_DENIED
            )
        assert (
            stream_call(server, f"{STORAGE}/PutResolved", [b""], repository, token)[0]
            == grpc.StatusCode.PERMISSION_DENIED
        )
    assert http(server, repository, writer, address=address) == (
        200,
        b"original content",
    )


@pytest.mark.parametrize("transport", ["quic", "grpc"])
@pytest.mark.parametrize(
    "with_identity_token", [False, True], ids=["access-only", "identity-and-access"]
)
def test_reader_cannot_push_and_writer_can(
    permission_server, new_lore_repo, transport, with_identity_token
):
    server = permission_server
    repository = uuid.uuid4().hex
    writer = server.token(repository, ["write"])
    reader = server.token(repository, ["read"])
    remote = server.quic if transport == "quic" else f"grpc://{server.grpc}/"
    repo = new_lore_repo(remote_url=remote, create_repo=False)
    if server.tier == "legacy":
        server.mock.on("CreateResource", resource_id=f"urc-{repository}").respond(
            empty_response()
        )

    def credentials(token):
        return {
            "access_token": token,
            **({"identity_token": token} if with_identity_token else {}),
        }

    repo.repository_create(
        repo_id=repository,
        identity_token=writer,
        access_token=writer,
    )

    (Path(repo.path) / "content.txt").write_text("content requiring upload")
    repo.file_stage("content.txt")
    repo.revision_commit("permission check")
    with pytest.raises(LoreException) as denied:
        repo.push(**credentials(reader))
    process_error = denied.value.__context__
    assert isinstance(process_error, CalledProcessError)
    assert process_error.returncode == 17, "Denied push must return NotAuthorized, not crash"
    repo.push(**credentials(writer))


@pytest.mark.parametrize("permissions", [["read"], ["write"]])
def test_creation_requires_write_on_proposed_id(permission_server, permissions):
    server = permission_server
    if server.tier == "legacy":
        pytest.skip("Legacy new creation is authorized by CreateResource")
    repository = uuid.uuid4().hex
    token = server.token(repository, permissions)
    expected = (
        grpc.StatusCode.OK
        if permissions == ["write"]
        else grpc.StatusCode.PERMISSION_DENIED
    )
    assert create(server, repository, token)[0] == expected
    if server.tier == "resource":
        other = uuid.uuid4().hex
        assert create(server, other, token)[0] == grpc.StatusCode.PERMISSION_DENIED
        writer = server.token(other, ["write"])
        assert (
            call(
                server.grpc,
                f"{REPOSITORY}/RepositoryGet",
                encode_bytes_field(1, bytes.fromhex(other)),
                metadata(other, writer),
            )[0]
            == grpc.StatusCode.NOT_FOUND
        )


def test_creator_with_read_cannot_delete_or_repair_creation(permission_server):
    server = permission_server
    repository = uuid.uuid4().hex
    writer = server.token(repository, ["write"])
    reader = server.token(repository, ["read"])
    assert create(server, repository, writer)[0] == grpc.StatusCode.OK
    assert create(server, repository, reader)[0] == grpc.StatusCode.PERMISSION_DENIED
    code, _, _ = call(
        server.grpc,
        f"{REPOSITORY}/RepositoryDelete",
        encode_bytes_field(1, bytes.fromhex(repository)),
        metadata(repository, reader),
    )
    assert code == grpc.StatusCode.PERMISSION_DENIED
    assert (
        call(
            server.grpc,
            f"{REPOSITORY}/RepositoryGet",
            encode_bytes_field(1, bytes.fromhex(repository)),
            metadata(repository, writer),
        )[0]
        == grpc.StatusCode.OK
    )


def test_cross_repository_copy_checks_both_grants(permission_server):
    server = permission_server
    if server.tier == "global":
        pytest.skip("Global grants apply to both repositories")
    source, destination = uuid.uuid4().hex, uuid.uuid4().hex
    source_writer = server.token(source, ["write"])
    destination_writer = server.token(destination, ["write"])
    assert create(server, source, source_writer)[0] == grpc.StatusCode.OK
    assert create(server, destination, destination_writer)[0] == grpc.StatusCode.OK
    status, body = http(server, source, source_writer, data=b"copy payload")
    assert status == 200
    address = json.loads(body)["data"]["address"]
    digest, context = address.split("-")
    wire_address = encode_bytes_field(1, bytes.fromhex(digest)) + encode_bytes_field(
        2, bytes.fromhex(context)
    )
    item = encode_bytes_field(1, bytes.fromhex(source)) + encode_bytes_field(
        2, wire_address
    )
    for source_permissions, destination_permissions, allowed in [
        (["read"], ["read"], False),
        ([], ["write"], False),
        (["read"], ["write"], True),
    ]:
        token = server.token(
            destination,
            destination_permissions,
            resources=[
                {"resource_id": f"urc-{source}", "permission": source_permissions},
                {
                    "resource_id": f"urc-{destination}",
                    "permission": destination_permissions,
                },
            ],
        )
        code, responses = stream_call(
            server, f"{STORAGE}/Copy", [item], destination, token
        )
        if allowed:
            assert code == grpc.StatusCode.OK
            assert not parse_fields(parse_fields(responses[0]).get(3, [b""])[0]).get(1)
        else:
            assert code == grpc.StatusCode.PERMISSION_DENIED or (
                responses and parse_fields(responses[0]).get(3)
            )
            assert (
                http(server, destination, destination_writer, address=address)[0] == 404
            )
    assert http(server, destination, destination_writer, address=address) == (
        200,
        b"copy payload",
    )


def test_reader_cannot_change_branches_metadata_or_locks(permission_server):
    server = permission_server
    repository = uuid.uuid4().hex
    writer, reader = (
        server.token(repository, ["write"]),
        server.token(repository, ["read"]),
    )
    assert create(server, repository, writer)[0] == grpc.StatusCode.OK
    before = call(
        server.grpc,
        f"{REPOSITORY}/RepositoryGet",
        encode_bytes_field(1, bytes.fromhex(repository)),
        metadata(repository, writer),
    )[1]
    branch = uuid.uuid4().bytes
    revision = "/lore.revision.v1.RevisionService"
    branch_body = (
        encode_bytes_field(1, branch)
        + encode_string_field(2, "permissions-branch")
        + encode_string_field(4, "default")
    )
    assert (
        call(
            server.grpc,
            f"{revision}/BranchCreate",
            branch_body,
            metadata(repository, reader),
        )[0]
        == grpc.StatusCode.PERMISSION_DENIED
    )
    assert (
        call(
            server.grpc,
            f"{revision}/BranchCreate",
            branch_body,
            metadata(repository, writer),
        )[0]
        == grpc.StatusCode.OK
    )
    branch_before = call(
        server.grpc,
        f"{revision}/BranchGet",
        encode_bytes_field(1, branch),
        metadata(repository, writer),
    )[1]
    for method in ["BranchDelete", "BranchMetadataSet", "BranchPush"]:
        assert (
            call(
                server.grpc,
                f"{revision}/{method}",
                encode_bytes_field(1, branch),
                metadata(repository, reader),
            )[0]
            == grpc.StatusCode.PERMISSION_DENIED
        )
    for method in [
        "BranchCreate",
        "BranchDelete",
        "BranchMetadataSet",
        "BranchProtect",
        "BranchUnprotect",
        "BranchPush",
    ]:
        assert (
            call(
                server.grpc,
                f"/urc.rpc.RevisionService/{method}",
                encode_bytes_field(1, branch),
                metadata(repository, reader),
            )[0]
            == grpc.StatusCode.PERMISSION_DENIED
        )
    assert (
        call(
            server.grpc,
            f"{revision}/BranchGet",
            encode_bytes_field(1, branch),
            metadata(repository, writer),
        )[1]
        == branch_before
    )
    for service in [REPOSITORY, "/urc.rpc.RepositoryService"]:
        assert (
            call(
                server.grpc,
                f"{service}/RepositoryMetadataSet",
                encode_bytes_field(1, bytes.fromhex(repository)),
                metadata(repository, reader),
            )[0]
            == grpc.StatusCode.PERMISSION_DENIED
        )
    resource = (
        encode_bytes_field(1, branch)
        + encode_bytes_field(2, b"l" * 32)
        + encode_string_field(3, "locked.txt")
    )
    lock = encode_bytes_field(1, resource)
    lock_service = "/urc.lock.LockService"
    assert (
        call(server.grpc, f"{lock_service}/Lock", lock, metadata(repository, reader))[0]
        == grpc.StatusCode.PERMISSION_DENIED
    )
    assert (
        call(server.grpc, f"{lock_service}/Lock", lock, metadata(repository, writer))[0]
        == grpc.StatusCode.OK
    )
    lock_before = call(
        server.grpc, f"{lock_service}/Query", b"", metadata(repository, writer)
    )[1]
    assert (
        call(server.grpc, f"{lock_service}/Unlock", lock, metadata(repository, reader))[
            0
        ]
        == grpc.StatusCode.PERMISSION_DENIED
    )
    assert (
        call(server.grpc, f"{lock_service}/Query", b"", metadata(repository, writer))[1]
        == lock_before
    )
    assert (
        call(server.grpc, f"{lock_service}/Unlock", lock, metadata(repository, writer))[
            0
        ]
        == grpc.StatusCode.OK
    )
    assert (
        call(
            server.grpc,
            f"{REPOSITORY}/RepositoryGet",
            encode_bytes_field(1, bytes.fromhex(repository)),
            metadata(repository, writer),
        )[1]
        == before
    )


def test_legacy_existing_auth_resource_requires_write(permission_server):
    server = permission_server
    if server.tier != "legacy":
        pytest.skip("CreateResource belongs to the legacy auth service")
    repository = uuid.uuid4().hex
    server.mock.on("CreateResource", resource_id=f"urc-{repository}").deny(
        grpc.StatusCode.ALREADY_EXISTS
    )
    reader = server.token(repository, ["read"], online=True)
    writer = server.token(repository, ["write"], online=True)
    before = len(server.mock.requests_for("CheckUserPermission"))
    assert (
        create(server, repository, reader, register_auth=False)[0]
        == grpc.StatusCode.PERMISSION_DENIED
    )
    assert len(server.mock.requests_for("CheckUserPermission")) - before == 1
    assert (
        call(
            server.grpc,
            f"{REPOSITORY}/RepositoryGet",
            encode_bytes_field(1, bytes.fromhex(repository)),
            metadata(repository, writer),
        )[0]
        == grpc.StatusCode.NOT_FOUND
    )
    assert (
        create(server, repository, writer, register_auth=False)[0] == grpc.StatusCode.OK
    )


def test_forwarded_mutations_verify_caller_and_require_write(permission_server):
    server = permission_server
    repository = uuid.uuid4().hex
    writer, reader = (
        server.token(repository, ["write"]),
        server.token(repository, ["read"]),
    )
    assert create(server, repository, writer)[0] == grpc.StatusCode.OK
    branch = uuid.uuid4().bytes
    body = (
        encode_bytes_field(1, branch)
        + encode_string_field(2, "forwarded-permissions")
        + encode_string_field(4, "default")
    )
    service = "/lore.revision.v1.ForwardedRevisionService"

    def forwarded(token):
        return repository_metadata(repository) + (
            ("on-behalf-of-user-id", USER1.user_id),
            ("on-behalf-of-authorization", f"Bearer {token}"),
        )

    assert (
        call(server.internal, f"{service}/BranchCreate", body, forwarded(reader))[0]
        == grpc.StatusCode.PERMISSION_DENIED
    )
    assert (
        call(server.internal, f"{service}/BranchCreate", body, forwarded("invalid"))[0]
        == grpc.StatusCode.UNAUTHENTICATED
    )
    assert (
        call(server.internal, f"{service}/BranchCreate", body, forwarded(writer))[0]
        == grpc.StatusCode.OK
    )
    assert (
        call(
            server.internal,
            f"{service}/BranchDelete",
            encode_bytes_field(1, branch),
            forwarded(reader),
        )[0]
        == grpc.StatusCode.PERMISSION_DENIED
    )
    assert (
        call(
            server.grpc,
            "/lore.revision.v1.RevisionService/BranchGet",
            encode_bytes_field(1, branch),
            metadata(repository, writer),
        )[0]
        == grpc.StatusCode.OK
    )
    new_repository = uuid.uuid4().hex
    if server.tier != "legacy":
        token = server.token(new_repository, ["read"])
        creation = (
            encode_bytes_field(1, bytes.fromhex(new_repository))
            + encode_string_field(2, new_repository)
            + encode_bytes_field(4, uuid.uuid4().bytes)
            + encode_string_field(5, "main")
        )
        forwarded_metadata = repository_metadata("0" * 32) + (
            ("on-behalf-of-user-id", USER1.user_id),
            ("on-behalf-of-authorization", f"Bearer {token}"),
        )
        assert (
            call(
                server.internal,
                "/lore.repository.v1.ForwardedRepositoryService/RepositoryCreate",
                creation,
                forwarded_metadata,
            )[0]
            == grpc.StatusCode.PERMISSION_DENIED
        )
