# SPDX-FileCopyrightText: 2026 Laurelianae
# SPDX-License-Identifier: MIT
"""Registry lookup must distinguish missing packages from permission failures."""

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("smoke_image", SCRIPTS / "smoke-image.py")
assert spec is not None and spec.loader is not None
smoke_image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke_image)


class ImageToolsTests(unittest.TestCase):
    def lookup(self, docker_error="", github_status="404", token="", image=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / "docker"
            docker.write_text(
                '#!/bin/sh\nif [ -n "$DOCKER_ERROR" ]; then\n'
                '  printf "%s\\n" "$DOCKER_ERROR" >&2\n  exit 1\nfi\n'
                'printf "%s\\n" "$DOCKER_MANIFEST"\n'
            )
            gh = root / "gh"
            gh.write_text(
                '#!/bin/sh\nprintf "HTTP/2 %s\\n\\n" "$GITHUB_PACKAGE_STATUS"\n'
                '[ "$GITHUB_PACKAGE_STATUS" = 200 ]\n'
            )
            docker.chmod(0o755)
            gh.chmod(0o755)
            env = dict(os.environ)
            env.update(
                PATH=str(root) + os.pathsep + env["PATH"],
                DOCKER_ERROR=docker_error,
                DOCKER_MANIFEST=json.dumps({"digest": "sha256:" + "a" * 64}),
                GITHUB_PACKAGE_STATUS=github_status,
                GH_TOKEN=token,
            )
            return subprocess.run(
                [
                    "bash",
                    str(SCRIPTS / "image-digest.sh"),
                    image or "ghcr.io/laurelianae/lore/loreserver:0.1.0",
                ],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_existing_digest_is_returned(self):
        result = self.lookup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "sha256:" + "a" * 64)

    def test_missing_manifest_is_empty(self):
        result = self.lookup("manifest unknown")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_first_ghcr_package_requires_authenticated_404(self):
        result = self.lookup("403 Forbidden", token="fixture")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        for status, token in (("404", ""), ("200", "fixture"), ("503", "fixture")):
            with self.subTest(status=status, token=token):
                result = self.lookup("403 Forbidden", github_status=status, token=token)
                self.assertNotEqual(result.returncode, 0)

    def test_unrelated_registry_and_network_errors_fail_closed(self):
        for error in (
            "timeout",
            "connection refused",
            "no such host",
            "unauthorized: not found",
        ):
            with self.subTest(error=error):
                result = self.lookup(error, token="fixture")
                self.assertNotEqual(result.returncode, 0)
        result = self.lookup(
            "403 Forbidden", token="fixture", image="ghcr.io/other/server:0.1.0"
        )
        self.assertNotEqual(result.returncode, 0)

    def test_readiness_retries_connection_resets(self):
        response = MagicMock()
        response.__enter__.return_value.status = 200
        with (
            patch.object(smoke_image, "docker", return_value="true"),
            patch.object(
                smoke_image.urllib.request,
                "urlopen",
                side_effect=[ConnectionResetError(), response],
            ) as requests,
            patch.object(smoke_image.time, "sleep"),
        ):
            smoke_image.wait_ready("fixture", "12345")
            self.assertEqual(requests.call_count, 2)

    def test_transport_port_is_available_for_both_protocols(self):
        port = smoke_image.transport_port()
        with (
            smoke_image.socket.socket(
                smoke_image.socket.AF_INET, smoke_image.socket.SOCK_STREAM
            ) as tcp,
            smoke_image.socket.socket(
                smoke_image.socket.AF_INET, smoke_image.socket.SOCK_DGRAM
            ) as udp,
        ):
            tcp.bind(("127.0.0.1", port))
            udp.bind(("127.0.0.1", port))


if __name__ == "__main__":
    unittest.main()
