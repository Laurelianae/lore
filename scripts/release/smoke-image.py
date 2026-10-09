#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Laurelianae
# SPDX-License-Identifier: MIT
"""Exercise a published server image and its /data volume with the released CLI."""

import argparse
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "test"))
from lore import Lore


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def transport_port():
    # lore:// uses QUIC and gRPC at the same port. Docker's independent
    # automatic allocations for TCP and UDP do not preserve that contract.
    for _ in range(32):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                try:
                    udp.bind(("127.0.0.1", port))
                except OSError:
                    continue
                return port
    raise RuntimeError("could not find a port available for both TCP and UDP")


def wait_ready(container, port):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if docker("inspect", "--format", "{{.State.Running}}", container) != "true":
            raise RuntimeError("server exited before becoming ready")
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{port}/health_check", timeout=2
            ) as response:
                if response.status == 200:
                    return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.25)
    raise TimeoutError("server did not become healthy within 90 seconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--context", type=Path, default=Path("release-context.json"))
    args = parser.parse_args()
    context = json.loads(args.context.read_text())
    expected = f"{context['upstream_package_version']}+{context['build_name']}"
    if expected not in docker("run", "--rm", args.image, "--version"):
        raise RuntimeError("image version does not match the release")
    labels = json.loads(
        docker("image", "inspect", args.image, "--format", "{{json .Config.Labels}}")
    )
    if labels["org.opencontainers.image.revision"] != context["source_commit"]:
        raise RuntimeError("image source commit does not match the release")
    volume = "lore-release-" + uuid.uuid4().hex
    container = volume + "-server"
    docker("volume", "create", volume)
    try:
        port = transport_port()
        docker(
            "run",
            "--detach",
            "--name",
            container,
            "--mount",
            f"source={volume},target=/data",
            "-p",
            f"127.0.0.1:{port}:41337/tcp",
            "-p",
            f"127.0.0.1:{port}:41337/udp",
            "-p",
            "127.0.0.1::41339/tcp",
            args.image,
        )
        ports = json.loads(
            docker("inspect", "--format", "{{json .NetworkSettings.Ports}}", container)
        )
        quic_port = ports["41337/udp"][0]["HostPort"]
        grpc_port = ports["41337/tcp"][0]["HostPort"]
        http_port = ports["41339/tcp"][0]["HostPort"]
        wait_ready(container, http_port)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Keep release checks off the developer's service and credentials.
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("LORE_")
            }
            env.update(
                LORE_USE_SERVICE="0",
                LORE_GLOBAL_PATH=str(root / "config"),
                LORE_AUTH_PATH=str(root / "auth"),
            )
            for protocol, port in (("lore", quic_port), ("grpc", grpc_port)):
                source = root / protocol
                source.mkdir()
                repo = Lore(
                    str(args.client.resolve()),
                    str(source),
                    protocol,
                    env,
                    remote_url=f"{protocol}://127.0.0.1:{port}/",
                )
                payload = f"persistent release data over {protocol}\n"
                (source / "hello.txt").write_text(payload)
                repo.stage(scan=True, offline=True)
                repo.commit("release smoke", offline=True)
                repo.push()
                clone = repo.clone(path=str(root / f"{protocol}-before"))
                if (Path(clone.path) / "hello.txt").read_text() != payload:
                    raise RuntimeError("clone did not reproduce pushed data")
                # Remove and recreate the container: only the named volume
                # survives, proving that no store relies on the writable layer.
                docker("stop", "--time", "30", container)
                docker("rm", container)
                docker(
                    "run",
                    "--detach",
                    "--name",
                    container,
                    "--mount",
                    f"source={volume},target=/data",
                    "-p",
                    f"127.0.0.1:{grpc_port}:41337/tcp",
                    "-p",
                    f"127.0.0.1:{quic_port}:41337/udp",
                    "-p",
                    f"127.0.0.1:{http_port}:41339/tcp",
                    args.image,
                )
                wait_ready(container, http_port)
                clone = repo.clone(path=str(root / f"{protocol}-after"))
                if (Path(clone.path) / "hello.txt").read_text() != payload:
                    raise RuntimeError("container recreation lost repository data")
                print(
                    f"Validated {protocol}: push, clone, and data after container recreation"
                )
    except BaseException:
        subprocess.run(["docker", "logs", container], check=False)
        raise
    finally:
        subprocess.run(["docker", "rm", "--force", container], check=False)
        subprocess.run(["docker", "volume", "rm", volume], check=False)


if __name__ == "__main__":
    main()
