#!/usr/bin/env bash
set -euo pipefail
umask 077
dest=$1
mkdir -p "$dest"
archive=trivy_0.76.2_Linux-64bit.tar.gz
curl --silent --show-error --fail --location --retry 2 \
  "https://github.com/aquasecurity/trivy/releases/download/v0.76.2/$archive" -o "$dest/$archive"
echo "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf  $dest/$archive" | sha256sum --check
tar -xzf "$dest/$archive" -C "$dest" trivy
curl --silent --show-error --fail --location --retry 2 \
  https://github.com/google/osv-scanner/releases/download/v2.7.1/osv-scanner_linux_amd64 -o "$dest/osv-scanner"
echo "fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8  $dest/osv-scanner" | sha256sum --check
chmod 0755 "$dest/osv-scanner"
