# SPDX-FileCopyrightText: 2026 Laurelianae
# SPDX-License-Identifier: MIT
"""Release contracts: source identity, completeness, tampering, and retries."""

import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.context = {
            "schema_version": 1,
            "tag": "aidonia-v0.1.0",
            "fork_version": "0.1.0",
            "source_commit": "a" * 40,
            "upstream_package_version": "0.10.2-nightly",
            "upstream_baseline_commit": "b" * 40,
            "default_config_sha256": "c" * 64,
            "build_name": "aidonia.0.1.0.gaaaaaaaaaaaa",
            "prerelease": False,
        }

    def assets(self):
        binaries = self.root / "bin"
        notices = self.root / "notices"
        output = self.root / "dist"
        binaries.mkdir()
        notices.mkdir()
        for name in ("lore", "loreserver", "lore.exe"):
            (binaries / name).write_bytes(b"fixture binary bytes")
        for name in ("lore", "loreserver"):
            (notices / f"{name}.txt").write_text(
                "MIT fixture __LORE_RELEASE_VERSION__\n"
            )
        with patch.object(release, "check_binary"):
            for target in release.TARGETS:
                release.package(self.context, target, binaries, notices, output)
        release.assemble(self.context, output)
        return output

    def test_tag_validation(self):
        self.assertEqual(release.version("aidonia-v0.1.0"), ((0, 1, 0), ""))
        self.assertEqual(release.version("aidonia-v1.2.3-rc.1"), ((1, 2, 3), "rc.1"))
        for tag in (
            "v1.2.3",
            "aidonia-v01.2.3",
            "aidonia-v1.2.3-rc.01",
            "aidonia-v1.2.3+local",
            "aidonia-v1.2.3\nlatest",
            "aidonia-v1.2.3-" + "x" * 96,
        ):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.version(tag)

    def test_complete_release_and_partial_download(self):
        output = self.assets()
        release.verify(self.context, output, require_all=True)
        manifest = release.read_json(output / "release-manifest.json")
        self.assertEqual(len(manifest["assets"]), 6)
        client = output / release.archive_name("lore", "0.1.0", release.TARGETS[0])
        client.unlink()
        release.verify(self.context, output)
        with self.assertRaisesRegex(ValueError, "missing release asset"):
            release.verify(self.context, output, require_all=True)

    def test_missing_target_prevents_assembly(self):
        output = self.assets()
        (output / release.archive_name("lore", "0.1.0", release.TARGETS[-1])).unlink()
        with self.assertRaisesRegex(ValueError, "incomplete release"):
            release.assemble(self.context, output)

    def test_tampered_asset_and_manifest_are_rejected(self):
        output = self.assets()
        server = output / release.archive_name(
            "loreserver", "0.1.0", release.TARGETS[0]
        )
        original = server.read_bytes()
        server.write_bytes(original + b"tampering")
        with self.assertRaisesRegex(ValueError, "asset checksum mismatch"):
            release.verify(self.context, output)
        server.write_bytes(original)
        with (output / "release-manifest.json").open("a") as stream:
            stream.write(" ")
        with self.assertRaisesRegex(ValueError, "manifest checksum mismatch"):
            release.verify(self.context, output)

    def test_duplicate_and_unsafe_checksum_entries_are_rejected(self):
        output = self.assets()
        checksums = output / "SHA256SUMS"
        original = checksums.read_text()
        for addition in (original.splitlines()[0] + "\n", "a" * 64 + "  ../payload\n"):
            checksums.write_text(original + addition)
            with self.assertRaisesRegex(ValueError, "invalid or duplicate"):
                release.verify(self.context, output)

    def test_manifest_source_mismatch_is_rejected(self):
        output = self.assets()
        wrong = dict(self.context, source_commit="d" * 40)
        with self.assertRaisesRegex(ValueError, "source_commit"):
            release.verify(wrong, output)

    def test_archive_traversal_and_symlinks_are_rejected(self):
        archive_path = self.root / "bad.tar.gz"
        for name, kind in (
            ("../loreserver", tarfile.REGTYPE),
            ("loreserver", tarfile.SYMTYPE),
        ):
            with tarfile.open(archive_path, "w:gz") as archive:
                for member_name in (name, "LICENSE.txt", "THIRD-PARTY-NOTICES.txt"):
                    member = tarfile.TarInfo(member_name)
                    member.mode = 0o755
                    member.type = kind if member_name == name else tarfile.REGTYPE
                    if member.type == tarfile.SYMTYPE:
                        member.linkname = "/tmp/payload"
                        archive.addfile(member)
                    else:
                        member.size = 1
                        archive.addfile(member, io.BytesIO(b"x"))
            with self.assertRaises(ValueError):
                release.check_archive(archive_path, "loreserver", release.TARGETS[0])

    def test_binary_version_must_match_context(self):
        with (
            patch.object(
                release.subprocess,
                "check_output",
                return_value="lore 0.10.2-nightly+local",
            ),
            self.assertRaisesRegex(ValueError, "does not report"),
        ):
            release.check_binary(self.root / "lore", self.context)

    def test_newest_stable_minor_backfill_and_prerelease_tags(self):
        releases = [
            {"tag_name": tag, "draft": draft, "prerelease": prerelease}
            for tag, draft, prerelease in (
                ("aidonia-v0.1.0", False, False),
                ("aidonia-v0.1.2", False, False),
                ("aidonia-v0.2.0", False, False),
                ("aidonia-v0.3.0-rc.1", False, True),
                ("aidonia-v9.0.0", True, False),
                ("v99.0.0", False, False),
            )
        ]
        self.assertEqual(
            release.moving_tags("aidonia-v0.2.0", releases), ["0.2.0", "0.2", "latest"]
        )
        self.assertEqual(
            release.moving_tags("aidonia-v0.1.2", releases), ["0.1.2", "0.1"]
        )
        self.assertEqual(release.moving_tags("aidonia-v0.1.0", releases), ["0.1.0"])
        self.assertEqual(
            release.moving_tags("aidonia-v0.3.0-rc.1", releases), ["0.3.0-rc.1"]
        )
        self.assertEqual(release.moving_tags("aidonia-v1.0.0", releases), ["1.0.0"])

    def git(self, *args):
        return subprocess.check_output(
            ["git", *args], cwd=self.root, text=True, stderr=subprocess.DEVNULL
        ).strip()

    def test_tagged_checkout_and_branch_ancestry(self):
        self.git("init", "--initial-branch=main")
        (self.root / "Cargo.toml").write_text(
            '[workspace.package]\nversion = "0.10.2-nightly"\n'
        )
        config = self.root / "lore-server/config/default.toml"
        config.parent.mkdir(parents=True)
        config.write_text("[server]\n")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "fixture",
        )
        baseline = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", baseline)
        self.git("checkout", "-b", "aidonia/main")
        (self.root / "patch").write_text("fork")
        self.git("add", ".")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "fork fixture",
        )
        source = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/aidonia/main", source)
        self.git("tag", "aidonia-v0.1.0")
        context = release.metadata("aidonia-v0.1.0", self.root)
        self.assertEqual(context["source_commit"], source)
        self.assertEqual(context["upstream_baseline_commit"], baseline)
        self.git("update-ref", "refs/remotes/origin/aidonia/main", baseline)
        with self.assertRaises(subprocess.CalledProcessError):
            release.metadata("aidonia-v0.1.0", self.root)
        published = release.metadata(
            "aidonia-v0.1.0", self.root, published_manifest=context
        )
        self.assertEqual(published, context)
        with self.assertRaisesRegex(ValueError, "invalid published upstream baseline"):
            release.metadata(
                "aidonia-v0.1.0",
                self.root,
                published_manifest=dict(context, upstream_baseline_commit="--invalid"),
            )
        self.git("checkout", "main")
        with self.assertRaisesRegex(ValueError, "checkout does not match"):
            release.metadata("aidonia-v0.1.0", self.root)

    def test_published_release_is_never_replaced(self):
        output = self.assets()
        releases = [[{"tag_name": self.context["tag"], "draft": False}]]
        with (
            patch.object(release, "run", return_value=json.dumps(releases)),
            patch.object(release.subprocess, "run") as mutate,
        ):
            with self.assertRaisesRegex(ValueError, "published releases"):
                release.draft(self.context, output)
            mutate.assert_not_called()

    def test_complete_draft_retry_skips_uploads(self):
        output = self.assets()
        releases = [
            [
                {
                    "tag_name": self.context["tag"],
                    "draft": True,
                    "assets": [{"name": p.name} for p in output.iterdir()],
                }
            ]
        ]

        def download(command, **kwargs):
            name = command[command.index("--pattern") + 1]
            directory = Path(command[command.index("--dir") + 1])
            (directory / name).write_bytes((output / name).read_bytes())

        with (
            patch.object(release, "run", return_value=json.dumps(releases)),
            patch.object(release.subprocess, "run", side_effect=download) as commands,
        ):
            release.draft(self.context, output)
            self.assertTrue(
                all(
                    call.args[0][1:3] == ["release", "download"]
                    for call in commands.call_args_list
                )
            )

    def test_draft_retry_rejects_changed_assets_before_uploading(self):
        output = self.assets()
        releases = [
            [
                {
                    "tag_name": self.context["tag"],
                    "draft": True,
                    "assets": [{"name": "SHA256SUMS"}],
                }
            ]
        ]

        def download(command, **kwargs):
            directory = Path(command[command.index("--dir") + 1])
            (directory / "SHA256SUMS").write_text("changed existing asset")

        with (
            patch.object(release, "run", return_value=json.dumps(releases)),
            patch.object(release.subprocess, "run", side_effect=download) as commands,
        ):
            with self.assertRaisesRegex(ValueError, "refusing to replace"):
                release.draft(self.context, output)
            self.assertEqual(commands.call_count, 1)


if __name__ == "__main__":
    unittest.main()
