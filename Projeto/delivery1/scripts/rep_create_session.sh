#!/bin/bash

# rep_create_session
if [ "$#" -ne 5 ]; then
    echo "Usage: $0 <organization> <username> <password> <credentials_file> <session_file>"
    exit 1
fi

python3 api/cli/anonymous_api_cli.py rep_create_session "$1" "$2" "$3" "$4" "$5"
