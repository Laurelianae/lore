---
title: Fork releases
description: Publish Aidonia client downloads and signed server images.
---

<!--
SPDX-FileCopyrightText: 2026 Laurelianae
SPDX-License-Identifier: MIT
-->

# Fork releases

Aidonia releases use independent `aidonia-v<version>` tags. Client downloads live in [GitHub Releases](https://github.com/Laurelianae/lore/releases); server images live at `ghcr.io/laurelianae/lore/loreserver`. Publication requires GitHub release immutability and workflow access to the public GHCR package.

## Publish a release

From an up-to-date `aidonia/main`, choose an unused version:

```bash
git tag -a aidonia-v0.1.0 -m 'Aidonia 0.1.0'
git push origin aidonia-v0.1.0
```

**Prepare fork release** checks the tag's ancestry, runs Linux unit/integration checks and native smoke tests, and prepares a draft after every job passes. Builds use the pinned Rust toolchain, lockfile, and production `release-lto` profile, without fault injection or Graviton tuning.

Review the downloads and release notes, then publish the draft as a maintainer to trigger **Publish loreserver image**. Keep prereleases marked as prereleases. For older maintenance releases, leave GitHub's **Set as the latest release** unchecked so installers keep selecting the current release.

## Downloads

| Artifact | Platforms |
| --- | --- |
| `lore-v<version>-<target>.tar.gz` | Linux AMD64/ARM64, macOS Apple Silicon |
| `lore-v<version>-x86_64-pc-windows-msvc.zip` | Windows AMD64 |
| `loreserver-v<version>-<target>.tar.gz` | Linux AMD64/ARM64 |
| `SHA256SUMS`, `release-manifest.json` | Checksums, source commit, and upstream baseline |

Every archive includes the executable, license, and third-party notices. Binaries report both the upstream package version and fork identity, for example `0.10.2-nightly+aidonia.0.1.0.g0123456789ab`. Linux downloads require glibc 2.39 or newer; macOS and Windows downloads have no certificate signing or notarization.

## Images and retries

Image publication packages checksum-verified released binaries into one portable AMD64/ARM64 image. Both architectures must pass health, push/clone, and persisted-data checks before the image receives release tags. Images include provenance, an SBOM, and a keyless cosign signature; the workflow summary provides the digest and verification command. Pin that digest for deployment. See [Docker usage](../../lore-server/DOCKER.md).

Exact versions such as `0.1.0` are preserved. `0.1` follows the newest stable release in its series, and `latest` follows the highest stable fork version. Prereleases such as `0.2.0-rc.1` receive only their exact tag.

Retry failed jobs from the original Actions run to reuse its artifacts. Both workflows also accept a release tag through manual dispatch on the default branch. Existing draft assets and exact image versions are never replaced; if a rebuild differs from an uploaded asset, use a new release tag. Published releases remain usable for image retries after the fork branch is rebased.
