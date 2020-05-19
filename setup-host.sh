#!/bin/bash
set -euo pipefail

CONFIG="/etc/ssh/sshd_config"
PRINCIPALS="/etc/ssh/principals"
CERTIFICATE="/etc/ssh/host-cert.pub"

# check for the correct number of arguments
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 CA_PUBLIC_KEY"
    echo "This script will overwrite any current CA public key!"
    exit 1
fi

# root check
if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root"
    exit 1
fi

PUBKEY="$1"

echo "[+] 1/2: Installing CA public key"
echo "$PUBKEY" > "/etc/ssh/ca.pub"

echo "[+] 2/2: Reconfiguring sshd"
if ! grep -q HostCertificate "$CONFIG"; then
    backup="$CONFIG.original"
    echo "[*] Backed up $CONFIG as $backup"
    cp "$CONFIG" "$backup"

    cat >> "$CONFIG" << EOF

# ========== begin sshca configuration ==========
# HostCertificate $CERTIFICATE
TrustedUserCAKeys /etc/ssh/ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
EOF
else
    echo "[!] sshd appears to already be configured, skipping"
    echo "[!] If this is incorrect, remove the line with HostCertificate in it and try again"
fi

mkdir -p "$PRINCIPALS"

systemctl restart sshd

echo
echo "[*] SSH public keys"
find /etc/ssh/ -iname '*ssh_host*pub' -not -iname '*cert*' -exec cat {} \;
find /etc/ssh/ -iname '*ssh_host*pub' -not -iname '*cert*' -exec ssh-keygen -l -f {} \;

echo
echo "[*] Host certificate path: $CERTIFICATE"
