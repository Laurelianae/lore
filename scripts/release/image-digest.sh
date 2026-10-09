#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Laurelianae
# SPDX-License-Identifier: MIT
# Print an existing image digest, or nothing for a missing manifest. Registry
# failures are fatal: they must not be interpreted as permission to overwrite.
set -euo pipefail

image_ref="${1:?expected an image reference}"
errors="$(mktemp)"
trap 'rm -f "$errors"' EXIT
if digest=$(docker buildx imagetools inspect "$image_ref" --format '{{json .Manifest}}' 2> "$errors"); then
    jq -er '.digest | select(test("^sha256:[0-9a-f]{64}$"))' <<< "$digest"
elif [[ "$image_ref" == ghcr.io/laurelianae/lore/loreserver:* && -n "${GH_TOKEN:-}" ]] \
    && grep -qi '403 Forbidden' "$errors"; then
    # GHCR can return 403 even for the first pull of a package that does not
    # exist. Corroborate it with GitHub's authenticated package API. A package
    # inaccessible to this token also cannot be overwritten by its later push;
    # exact-tag preservation is checked again after the package exists.
    if response=$(gh api --include users/Laurelianae/packages/container/lore%2Floreserver 2>> "$errors"); then
        cat "$errors" >&2
        exit 1
    elif ! grep -qE '^HTTP/[^ ]+ 404([[:space:]]|$)' <<< "$response"; then
        cat "$errors" >&2
        exit 1
    fi
elif grep -Eqi 'unauthorized|denied|forbidden|timeout|TLS|connection|no such host' "$errors"; then
    cat "$errors" >&2
    exit 1
elif ! grep -Eqi 'manifest unknown|not found' "$errors"; then
    cat "$errors" >&2
    exit 1
fi
