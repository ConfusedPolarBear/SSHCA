#!/bin/bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 hostname notAfter"
    exit 1
fi

host="$1"
valid="+$2"
file="/dev/shm/host.pub"

echo "Creating certificate for $host valid for $valid with key from $file"

ssh-keygen -U -s host.pub -I "$host" -V "$valid" -n "$host" -h "$file"

echo "Certificate created"
echo
cat "$(echo $file | sed 's/.pub/-cert.pub/g')" | cut -d " " -f -2
