#!/bin/bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
	echo "Usage: $0 toRevoke [publicKey]"
	exit 1
fi

revoke="$1"
publicKey=""

# check if a second argument was provided
if [ -z "${2+x}" ]; then
	publicKey="ca.pub"
else
	publicKey="$2"
fi

echo "[+] Revoking $revoke with public key $publicKey"
echo "$revoke" | ssh-keygen -s "$publicKey" -f revoked.krl -u -k -

echo "$revoke" >> revoked-log.txt
logger -t sshca "$USER revoked \"$revoke\" with public key \"$publicKey\""

echo "[+] Successfully revoked $revoke"
