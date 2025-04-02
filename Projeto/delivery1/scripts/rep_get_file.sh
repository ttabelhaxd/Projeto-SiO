#! bin/bash

#rep_get_file <file handle> [file]
if [ -n "$2" ]; then
    python3 api/cli/anonymous_api_cli.py rep_get_file $1 $2
else
    python3 api/cli/anonymous_api_cli.py rep_get_file $1 
fi