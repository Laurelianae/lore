#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Laurelianae
# SPDX-License-Identifier: MIT
"""Prepare and verify Aidonia release artifacts using the Python standard library."""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
)
TAG = re.compile(
    r"aidonia-v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


def version(tag):
    match = TAG.fullmatch(tag)
    if not match:
        raise ValueError(f"invalid fork release tag: {tag}")
    prerelease = match[4] or ""
    if any(p.isdigit() and len(p) > 1 and p[0] == "0" for p in prerelease.split(".")):
        raise ValueError("numeric prerelease identifiers must not have leading zeros")
    value = tag.removeprefix("aidonia-v")
    if len(f"aidonia.{value}.g{'0' * 12}") >= 96:
        raise ValueError("release version exceeds the binary stamp capacity")
    return tuple(int(match[i]) for i in (1, 2, 3)), prerelease


def run(*args, cwd=ROOT):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def archive_name(binary, fork_version, target):
    suffix = "zip" if target.endswith("windows-msvc") else "tar.gz"
    return f"{binary}-v{fork_version}-{target}.{suffix}"


def expected_assets(fork_version):
    return {
        archive_name(binary, fork_version, target): (binary, target)
        for target in TARGETS
        for binary in (("lore", "loreserver") if "linux" in target else ("lore",))
    }


def metadata(tag, root=ROOT, published_manifest=None):
    _, prerelease = version(tag)
    source = run("git", "rev-parse", f"refs/tags/{tag}^{{commit}}", cwd=root)
    if run("git", "rev-parse", "HEAD", cwd=root) != source:
        raise ValueError("checkout does not match the release tag")
    if published_manifest is None:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", source, "origin/aidonia/main"],
            cwd=root,
            check=True,
        )
        upstream_base = run("git", "merge-base", source, "origin/main", cwd=root)
    else:
        # Published immutable releases retain their original baseline even if
        # the fork branch is subsequently rebased during an upstream replay.
        upstream_base = published_manifest["upstream_baseline_commit"]
        if not re.fullmatch(r"[0-9a-f]{40}", upstream_base):
            raise ValueError("invalid published upstream baseline")
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", upstream_base, source],
            cwd=root,
            check=True,
        )
    package = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"][
        "version"
    ]
    fork_version = tag.removeprefix("aidonia-v")
    return {
        "schema_version": 1,
        "tag": tag,
        "fork_version": fork_version,
        "source_commit": source,
        "upstream_package_version": package,
        "upstream_baseline_commit": upstream_base,
        "default_config_sha256": sha256(root / "lore-server/config/default.toml"),
        "build_name": f"aidonia.{fork_version}.g{source[:12]}",
        "prerelease": bool(prerelease),
    }


def check_binary(path, context):
    env = dict(os.environ, LORE_USE_SERVICE="0")
    output = subprocess.check_output(
        [str(path.resolve()), "--version"], env=env, text=True
    )
    expected = f"{context['upstream_package_version']}+{context['build_name']}"
    if expected not in output:
        raise ValueError(f"{path} does not report {expected}: {output.strip()}")


def check_archive(path, binary, target):
    executable = binary + (".exe" if target.endswith("windows-msvc") else "")
    expected = {executable, "LICENSE.txt", "THIRD-PARTY-NOTICES.txt"}
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if set(names) != expected or len(names) != len(expected):
                raise ValueError(f"unexpected archive contents: {path}")
            if any(
                entry.is_dir() or (entry.external_attr >> 16) & 0o170000 == 0o120000
                for entry in entries
            ):
                raise ValueError(f"non-regular archive member: {path}")
            if archive.testzip():
                raise ValueError(f"corrupt zip: {path}")
    else:
        with tarfile.open(path, "r:gz") as archive:
            entries = archive.getmembers()
            names = [entry.name for entry in entries]
            if set(names) != expected or len(names) != len(expected):
                raise ValueError(f"unexpected archive contents: {path}")
            if any(not entry.isfile() for entry in entries):
                raise ValueError(f"non-regular archive member: {path}")
            if (
                not next(entry for entry in entries if entry.name == executable).mode
                & 0o111
            ):
                raise ValueError(f"binary is not executable: {path}")


def package(context, target, bin_dir, notices_dir, output):
    if target not in TARGETS:
        raise ValueError(f"unsupported release target: {target}")
    output.mkdir(parents=True, exist_ok=True)
    binaries = ("lore", "loreserver") if "linux" in target else ("lore",)
    for binary in binaries:
        executable = binary + (".exe" if target.endswith("windows-msvc") else "")
        check_binary(bin_dir / executable, context)
        notices = (notices_dir / f"{binary}.txt").read_text(encoding="utf-8")
        notices = notices.replace("__LORE_RELEASE_VERSION__", context["tag"])
        if "__LORE_" in notices or not notices.strip():
            raise ValueError(f"unresolved or empty notices for {binary}")
        destination = output / archive_name(binary, context["fork_version"], target)
        with tempfile.TemporaryDirectory() as directory:
            staging = Path(directory)
            shutil.copyfile(bin_dir / executable, staging / executable)
            (staging / executable).chmod(0o755)
            shutil.copyfile(ROOT / "LICENSE", staging / "LICENSE.txt")
            (staging / "THIRD-PARTY-NOTICES.txt").write_text(notices, encoding="utf-8")
            if target.endswith("windows-msvc"):
                with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
                    for item in sorted(staging.iterdir()):
                        archive.write(item, item.name)
            else:
                with tarfile.open(destination, "w:gz") as archive:
                    for item in sorted(staging.iterdir()):
                        archive.add(item, arcname=item.name)
        check_archive(destination, binary, target)


def assemble(context, directory):
    expected = expected_assets(context["fork_version"])
    actual = {
        path.name
        for path in directory.iterdir()
        if path.name not in ("SHA256SUMS", "release-manifest.json")
    }
    if actual != set(expected):
        raise ValueError(
            f"incomplete release assets: missing {set(expected) - actual}, extra {actual - set(expected)}"
        )
    assets = {}
    for name, (binary, target) in expected.items():
        path = directory / name
        check_archive(path, binary, target)
        assets[name] = {"binary": binary, "target": target, "sha256": sha256(path)}
    write_json(directory / "release-manifest.json", dict(context, assets=assets))
    names = sorted([*expected, "release-manifest.json"])
    (directory / "SHA256SUMS").write_text(
        "".join(f"{sha256(directory / name)}  {name}\n" for name in names),
        encoding="utf-8",
    )


def verify(context, directory, require_all=False):
    manifest = read_json(directory / "release-manifest.json")
    for key, value in context.items():
        if manifest.get(key) != value:
            raise ValueError(f"release manifest {key} does not match the tagged source")
    expected = expected_assets(context["fork_version"])
    if set(manifest["assets"]) != set(expected):
        raise ValueError("manifest does not contain the complete release target set")
    checksums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if not match or match[2] in checksums:
            raise ValueError("invalid or duplicate checksum entry")
        checksums[match[2]] = match[1]
    if set(checksums) != {*expected, "release-manifest.json"}:
        raise ValueError(
            "checksum file does not contain the complete release target set"
        )
    if (
        sha256(directory / "release-manifest.json")
        != checksums["release-manifest.json"]
    ):
        raise ValueError("manifest checksum mismatch")
    for name, (binary, target) in expected.items():
        if manifest["assets"][name] != {
            "binary": binary,
            "target": target,
            "sha256": checksums[name],
        }:
            raise ValueError(f"asset metadata mismatch: {name}")
        path = directory / name
        if not path.is_file():
            if require_all:
                raise ValueError(f"missing release asset: {name}")
            continue
        if sha256(path) != checksums[name]:
            raise ValueError(f"asset checksum mismatch: {name}")
        check_archive(path, binary, target)
    return manifest


def extract(context, directory, binary, target, destination):
    verify(context, directory)
    archive_path = directory / archive_name(binary, context["fork_version"], target)
    check_archive(archive_path, binary, target)
    destination.mkdir(parents=True, exist_ok=True)
    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(destination)
    else:
        with tarfile.open(archive_path, "r:gz") as archive:
            archive.extractall(destination, filter="data")
    executable = binary + (".exe" if target.endswith("windows-msvc") else "")
    check_binary(destination / executable, context)


def moving_tags(tag, releases):
    number, prerelease = version(tag)
    tags = [tag.removeprefix("aidonia-v")]
    stable = []
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        try:
            candidate, suffix = version(release["tag_name"])
        except ValueError:
            continue
        if not suffix:
            stable.append(candidate)
    if not prerelease and number in stable:
        series = [v for v in stable if v[:2] == number[:2]]
        if number == max(series):
            tags.append(f"{number[0]}.{number[1]}")
        if number == max(stable):
            tags.append("latest")
    return tags


def draft(context, directory):
    verify(context, directory, require_all=True)
    tag = context["tag"]
    # Listing drafts requires authentication; a failed API call must not be
    # mistaken for a missing release and bypass preservation checks.
    pages = json.loads(
        run("gh", "api", "--paginate", "--slurp", "repos/{owner}/{repo}/releases")
    )
    release = next((r for page in pages for r in page if r["tag_name"] == tag), None)
    if release and not release["draft"]:
        raise ValueError("published releases cannot be replaced")
    files = sorted(directory.iterdir())
    if release:
        # Preflight every existing asset before uploading anything else.
        existing = release["assets"]
        if any(a["name"] not in {p.name for p in files} for a in existing):
            raise ValueError("draft contains unexpected assets; use a new release tag")
        with tempfile.TemporaryDirectory() as temporary:
            for asset in existing:
                subprocess.run(
                    [
                        "gh",
                        "release",
                        "download",
                        tag,
                        "--pattern",
                        asset["name"],
                        "--dir",
                        temporary,
                    ],
                    check=True,
                    cwd=ROOT,
                )
                if sha256(Path(temporary) / asset["name"]) != sha256(
                    directory / asset["name"]
                ):
                    raise ValueError(
                        f"refusing to replace draft asset {asset['name']}; use a new tag"
                    )
    else:
        notes = (
            f"Aidonia fork release **{context['fork_version']}**.\n\n"
            f"Source: `{context['source_commit']}`\n\n"
            f"Upstream package: `{context['upstream_package_version']}`; "
            f"baseline: `{context['upstream_baseline_commit']}`.\n\n"
            "Review these notes and downloads before publishing. Linux clients require glibc 2.39+. "
            "The server image is published after this draft is published.\n"
        )
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        ) as stream:
            stream.write(notes)
            notes_path = stream.name
        try:
            command = [
                "gh",
                "release",
                "create",
                tag,
                "--verify-tag",
                "--draft",
                "--title",
                f"Aidonia {context['fork_version']}",
                "--notes-file",
                notes_path,
            ]
            if context["prerelease"]:
                command.append("--prerelease")
            subprocess.run(command, check=True, cwd=ROOT)
        finally:
            Path(notes_path).unlink()
        existing = []
    names = {asset["name"] for asset in existing}
    missing = [str(path) for path in files if path.name not in names]
    if missing:
        subprocess.run(["gh", "release", "upload", tag, *missing], check=True, cwd=ROOT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    meta = commands.add_parser("metadata")
    meta.add_argument("--tag", required=True)
    meta.add_argument("--output", type=Path, default=Path("release-context.json"))
    meta.add_argument("--github-output", type=Path)
    meta.add_argument("--published-manifest", type=Path)
    for command in ("package", "assemble", "verify", "draft", "extract"):
        child = commands.add_parser(command)
        child.add_argument("--context", type=Path, default=Path("release-context.json"))
        child.add_argument("--directory", type=Path, default=Path("dist"))
        if command == "package":
            child.add_argument("--target", choices=TARGETS, required=True)
            child.add_argument("--bin-dir", type=Path, required=True)
            child.add_argument(
                "--notices-dir", type=Path, default=Path("release-notices")
            )
        if command == "verify":
            child.add_argument("--require-all", action="store_true")
        if command == "extract":
            child.add_argument(
                "--binary", choices=("lore", "loreserver"), required=True
            )
            child.add_argument("--target", choices=TARGETS, required=True)
            child.add_argument("--destination", type=Path, required=True)
    tags = commands.add_parser("tags")
    tags.add_argument("--tag", required=True)
    tags.add_argument("--releases", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "metadata":
        published = (
            read_json(args.published_manifest) if args.published_manifest else None
        )
        context = metadata(args.tag, published_manifest=published)
        write_json(args.output, context)
        if args.github_output:
            with args.github_output.open("a", encoding="utf-8") as stream:
                for key, value in context.items():
                    if isinstance(value, (str, bool)):
                        stream.write(
                            f"{key}={str(value).lower() if isinstance(value, bool) else value}\n"
                        )
    elif args.command == "tags":
        pages = read_json(args.releases)
        print("\n".join(moving_tags(args.tag, [r for page in pages for r in page])))
    else:
        context = read_json(args.context)
        if args.command == "package":
            package(
                context, args.target, args.bin_dir, args.notices_dir, args.directory
            )
        elif args.command == "verify":
            verify(context, args.directory, args.require_all)
        elif args.command == "assemble":
            assemble(context, args.directory)
        elif args.command == "extract":
            extract(context, args.directory, args.binary, args.target, args.destination)
        else:
            draft(context, args.directory)


if __name__ == "__main__":
    main()
