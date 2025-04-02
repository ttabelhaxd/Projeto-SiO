#! bin/bash

#rep_list_subjects
if [ -n "$2" ]; then
    python3 api/cli/authenticated_api_cli.py rep_list_subjects $1 $2
else
    python3 api/cli/authenticated_api_cli.py rep_list_subjects $1
fi 