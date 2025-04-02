#!/bin/bash

# rep_list_docs <session file> [-s username] [-d nt/ot/et date]

if [ -n "$2" ]; then
    if [ -n "$3" ]; then
        python3 api/cli/authenticated_api_cli.py rep_list_docs $1 $2 $3
    else
        python3 api/cli/authenticated_api_cli.py rep_list_docs $1 $2
    fi
else
    python3 api/cli/authenticated_api_cli.py rep_list_docs $1
fi
