#!/bin/bash
set -euo pipefail

dest="$1"
mkdir -p "$dest"

if [[ ! -f "$dest/ca" ]]; then
    echo "[+] Saving CA private keys to $dest"

    echo "[+] Generating CA key to sign user keys"
    ssh-keygen -t ed25519 -C "User CA" -f "$dest/ca"

    echo "[+] Generating CA key to sign host keys"
    ssh-keygen -t ed25519 -C "Host CA" -f "$dest/host"
fi

echo "[+] Generating new krl"
ssh-keygen -k -f config/revoked.krl
touch config/revoked-log.txt

cp "$dest/ca.pub" ./config/
cp "$dest/host.pub" ./config/
