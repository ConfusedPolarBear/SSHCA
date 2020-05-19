#!/bin/bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 hostname notAfter"
    exit 1
fi

host="$1"
valid="+$2"
file="/dev/shm/host.pub"

echo "Hostname:    $host"
echo "Validity:    $valid"
echo "Public key:  $(cat "$file")"
echo "Fingerprint: $(ssh-keygen -lf "$file")"
echo "Filename:    $file"

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

ssh-keygen -U -s host.pub -I "$host" -V "$valid" -n "$host" -h "$file"

echo Certificate created
echo
cat "$(echo $file | sed 's/.pub/-cert.pub/g')" | cut -d " " -f -2

echo Unload Host CA key with: ssh-add -d host.pub
