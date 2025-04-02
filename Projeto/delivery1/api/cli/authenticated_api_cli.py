# rep_list_subjects, rep_list_docs

import requests
import argparse
import json
import os

BASE_URL = "http://localhost:5000/api/authenticated" 

# Helper function to load the session_id
def load_session(session_file):
    try:
        with open(session_file, 'r') as f:
            session_id = f.read().strip()
        return session_id
    except FileNotFoundError:
        print(f"Error: Session file '{session_file}' not found.")
        return None

# Function for command `rep_list_subjects`
def list_subjects(session_file, username=None):
    session_id = load_session(session_file)
    if not session_id:
        return 1

    headers = {"Authorization": f"Bearer {session_id}"}
    params = {}
    if username:
        params['username'] = username

    response = requests.get(f"{BASE_URL}/subjects", headers=headers, params=params)
    
    if response.status_code == 200:
        subjects = response.json()
        for subject in subjects:
            print(f"ID: {subject['id']}, Username: {subject['username']}, Full Name: {subject['full_name']}, Email: {subject['email']}, Status: {subject['status']}")
        return 0
    else:
        print(f"Error listing subjects: ")
        return 1

# Function for command `rep_list_docs`
def list_docs(session_file, username=None, date=None, filter=None):
    session_id = open(session_file).read().strip()
    headers = {"Authorization": f"Bearer {session_id}"}
    params = {}
    if username:
        params["username"] = username
    if date:
        params["date"] = date
    if filter:
        params["filter"] = filter

    response = requests.get(f"{BASE_URL}/documents", headers=headers, params=params)
    if response.status_code == 200:
        response_data = response.json()

        if "message" in response_data:
            print(response_data["message"])
            return 0

        for doc in response_data:
            print(f"Document Name: {doc['name']}, Created By: {doc['creator']}, Created At: {doc['create_date']}")
        return 0
    else:
        print(f"Error listing documents: {response.json().get('error', 'Unknown error')}")
        return 1

# Main parser function
def main():
    parser = argparse.ArgumentParser(description="CLI for Repository API Authenticated Commands")
    
    subparsers = parser.add_subparsers(dest="command")
    
    # Command `rep_list_subjects`
    parser_list_subjects = subparsers.add_parser("rep_list_subjects", help="List subjects")
    parser_list_subjects.add_argument("session_file", help="Session file path")
    parser_list_subjects.add_argument("username", nargs="?", help="Optional username to filter")

    # Command `rep_list_docs`
    parser_list_docs = subparsers.add_parser("rep_list_docs", help="List documents")
    parser_list_docs.add_argument("session_file", help="Session file path")
    parser_list_docs.add_argument("-s", "--username", help="Filter by creator username")
    parser_list_docs.add_argument("-d", "--date", help="Filter by date (DD-MM-YYYY)")
    parser_list_docs.add_argument("-f", "--filter", choices=["nt", "ot", "et"], help="Date filter type")

    args = parser.parse_args()

    # Executes the correct function based on the command
    if args.command == "rep_list_subjects":
        return list_subjects(args.session_file, args.username)
    elif args.command == "rep_list_docs":
        return list_docs(args.session_file, args.username, args.date, args.filter)
    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    exit(main())
