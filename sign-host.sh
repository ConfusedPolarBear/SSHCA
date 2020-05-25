#!/bin/bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
    echo "Usage: $0 hostname notAfter publicKey"
    exit 1
fi

host="$1"
valid="+$2"
key="$3"

file="/dev/shm/host.pub"
echo "$key" > "$file"

echo "Hostname:    $host"
echo "Validity:    $valid"
echo "Public key:  $(cat "$file")"
echo "Fingerprint: $(ssh-keygen -lf "$file")"

echo
read -n 1 -p "Are you sure? " sure
echo

case "$sure" in
    [yY])
        # continuing
        ;;

    *)
        echo Abort
        exit 0
        ;;
esac

ssh-keygen -U -s config/host.pub -I "$host" -V "$valid" -n "$host" -h "$file"

echo Certificate created
echo
cat "$(echo $file | sed 's/.pub/-cert.pub/g')" | cut -d " " -f -2

echo
echo Unload Host CA key with: ssh-add -d host.pub
