#! bin/bash

#rep_get_doc_file <session file> <document name> [file]

if [ -n "$3" ]; then
    python3 api/cli/authorized_api_cli.py rep_get_doc_file $1 $2 $3
else
    python3 api/cli/authorized_api_cli.py rep_get_doc_file $1 $2
fi