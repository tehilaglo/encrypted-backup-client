#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

FILES_DIR="$PROJECT_ROOT/client"

ME_INFO_FILE="$FILES_DIR/me.info"
KEY_FILE="$FILES_DIR/private.key"
LOG_FILE="$FILES_DIR/client.log"


# Check if the file exists in the current directory and remove it
if [ -f "$ME_INFO_FILE" ]; then
    rm "$ME_INFO_FILE"
    echo "$ME_INFO_FILE removed."
else
    echo "$ME_INFO_FILE not found."
fi

if [ -f "$KEY_FILE" ]; then
    rm "$KEY_FILE"
    echo "$KEY_FILE removed."
else
    echo "$KEY_FILE not found."
fi

if [ -f "$LOG_FILE" ]; then
    rm "$LOG_FILE"
    echo "$LOG_FILE removed."
else
    echo "$LOG_FILE not found."
fi

echo "Cleanup complete."
