#!/bin/bash

if [ $# -ne 5 ]; then
    echo "Usage: ./rep_create_org.sh <organization> <username> <full_name> <email> <public_key_file>"
    exit 1
fi

# Chama o comando Python com os argumentos corretos
python3 api/cli/anonymous_api_cli.py rep_create_org "$1" "$2" "$3" "$4" "$5"
