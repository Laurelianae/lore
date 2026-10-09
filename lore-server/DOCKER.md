# Running loreserver in Docker

The Aidonia fork publishes a portable server image at `ghcr.io/laurelianae/lore/loreserver`. Each release tag supports both `linux/amd64` and `linux/arm64`, including Apple Silicon Linux VMs and general ARM servers. The image uses local filesystem storage by default; authorization, replication, and telemetry require deployment configuration.

## Published images

| Tag | Meaning |
| --- | --- |
| `0.1.0` | Exact Aidonia fork release |
| `0.1` | Newest stable release in that fork series |
| `latest` | Highest stable fork release |
| `0.2.0-rc.1` | Exact prerelease; never moves stable tags |

Versions are independent of upstream Lore. Each binary reports the upstream package version plus the Aidonia release version and source commit, for example `0.10.2-nightly+aidonia.0.1.0.g0123456789ab`. The image's OCI labels identify the source repository, full commit, release version, and packaged server archive's SHA-256.

The publish workflow packages checksum-verified Linux server archives from a published fork release. It compiles nothing, takes `default.toml` from the same release commit, tests each architecture natively, and signs the final multi-platform index with keyless cosign. It includes build provenance and an image SBOM. The workflow summary supplies the image digest and signature verification command. Pin that digest for deployments:

```bash
docker pull ghcr.io/laurelianae/lore/loreserver@sha256:<digest-from-workflow-summary>
```

For the publication and retry process, see [fork releases](../docs/developing/releases.md). Graviton-specific `-graviton` images are outside this fork's initial release stream; the default ARM64 image uses no Neoverse tuning.

## Building from source

From the repository root, with Docker BuildKit:

```bash
docker build -f lore-server/Dockerfile -t loreserver .
```

The Dockerfile builds `loreserver` with Rust 1.98.1, the lockfile, and the production `release-lto` profile. Both architectures use the portable baseline. To build and push both architectures, use a builder with native workers where possible:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  -f lore-server/Dockerfile -t <your-registry>/loreserver:<tag> --push .
```

`lore-server/Dockerfile.release` packages an already built server from `dist/<arch>/` with its license and notices. It is the release workflow's packaging path, not a standalone source build.

## Running and persisting data

```bash
docker run --name loreserver \
  -p 41337:41337/tcp -p 41337:41337/udp -p 41339:41339/tcp \
  --mount source=lore-data,target=/data \
  ghcr.io/laurelianae/lore/loreserver:0.1.0
```

The named volume persists stores across container replacement. To use a host directory instead, replace `--mount` with `-v /path/to/local/data:/data`. Stop the server gracefully before replacing it so buffered writes are flushed. Preserve the data volume when removing the container.

| Port | Protocol | Service |
| --- | --- | --- |
| 41337 | TCP | gRPC |
| 41337 | UDP | QUIC |
| 41339 | TCP | HTTP, including `/health_check` |

Both TCP and UDP mappings on port 41337 are required. With no configured QUIC certificate, the server generates an ephemeral self-signed certificate at startup. For durable deployments, mount a certificate and configure `[server.quic.certificate]`.

## Configuration

`LORE_CONFIG_PATH=/etc/lore/config` and `LORE_ENV=docker` select:

- `default.toml`: the source defaults from the release commit, layered over compiled-in defaults.
- `docker.toml`: immutable and mutable stores under `/data`; no configured QUIC certificate.

Mount configuration files under `/etc/lore/config` or use environment overrides with the `LORE__` prefix and `__` separator. For example:

```bash
docker run -e LORE__SERVER__HTTP__PORT=8080 \
  -p 8080:8080/tcp -p 41337:41337/tcp -p 41337:41337/udp \
  --mount source=lore-data,target=/data \
  ghcr.io/laurelianae/lore/loreserver:0.1.0
```
