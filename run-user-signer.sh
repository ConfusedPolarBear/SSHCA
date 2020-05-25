#!/bin/bash
set -euo pipefail

dir="$1"

eval `ssh-agent`
SOCK="$SSH_AUTH_SOCK"

echo "$SOCK" > /tmp/sshca-socket

ssh-add -l || true
ssh-add "$dir"/{ca,host}

echo "Current keys in agent are:"
ssh-add -l
