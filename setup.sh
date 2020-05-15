#!/bin/bash
set -euo pipefail

dest="$1"
echo "Saving CA private keys to $dest"

echo "Generating CA key to sign user keys"
ssh-keygen -t ed25519 -C "User CA" -f "$dest/ca"

echo "Generating CA key to sign host keys"
ssh-keygen -t ed25519 -C "Host CA" -f "$dest/host"

cp "$dest/ca.pub" ./
cp "$dest/host.pub" ./
