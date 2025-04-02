#!/bin/bash

# rep_add_subject <session file> <username> <name> <email> <credentials file>

if [ "$#" -ne 5 ]; then
    echo "Usage: $0 <session_file> <username> <name> <email> <credentials_file>"
    exit 1
fi

SESSION_FILE="$1"
USERNAME="$2"
NAME="$3"
EMAIL="$4"
CREDENTIALS_FILE="$5"

if [ ! -f "$SESSION_FILE" ]; then
    echo "Error: Session file '$SESSION_FILE' not found."
    exit 1
fi

if [ ! -f "$CREDENTIALS_FILE" ]; then
    echo "Error: Credentials file '$CREDENTIALS_FILE' not found."
    exit 1
fi

python3 api/cli/authorized_api_cli.py rep_add_subject "$SESSION_FILE" "$USERNAME" "$NAME" "$EMAIL" "$CREDENTIALS_FILE"
