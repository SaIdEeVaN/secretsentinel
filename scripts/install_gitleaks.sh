#!/usr/bin/env bash
# Download a PINNED Gitleaks release for Linux x64, verify its SHA-256 against a
# reviewed value, and install only the `gitleaks` binary.
#
#   scripts/install_gitleaks.sh <version> <expected-sha256> <dest-dir>
#
# The expected hash must come from a reviewed source (the workflow file), never
# from the same download as the archive.
set -euo pipefail

version="${1:?version required, e.g. 8.30.1}"
expected="${2:?expected sha256 required}"
dest="${3:?destination directory required}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid version: $version" >&2; exit 2
fi
if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo "invalid sha256" >&2; exit 2
fi

archive="gitleaks_${version}_linux_x64.tar.gz"
url="https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 -o "$work/$archive" "$url"
actual="$(sha256sum "$work/$archive" | awk '{print $1}')"
if [[ "$actual" != "$expected" ]]; then
  echo "checksum mismatch for $archive" >&2
  echo "  expected $expected" >&2
  echo "  actual   $actual" >&2
  exit 1
fi
echo "checksum OK for $archive"

mkdir -p "$dest"
tar -xzf "$work/$archive" -C "$work" gitleaks
install -m 0755 "$work/gitleaks" "$dest/gitleaks"
"$dest/gitleaks" version
