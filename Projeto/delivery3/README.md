# Students:
- Abel Teixeira, Nº 113655;
- Filipe Sousa, Nº 114196;
- Tiago Albuquerque, Nº 112901

## Local Commands

These commands interact with the local filesystem without the API.

### rep_subject_credentials 
```bash
./rep_subject_credentials <password> <credentials file>
```
Arguments:
- password: the password to encrypt the credentials file
- credentials file: the file to store the encrypted credentials

Function:
- This command does not interact with the Repository and creates a key pair for a subject.

---

### rep_decrypt_file
```bash
./rep_decrypt_file <encrypted file> <encryption metadata>
```
Arguments:
- encrypted file: the file to decrypt
- encryption metadata: the file with the encryption metadata

Function:
- This command does not interact with the Repository and decrypts a file.
---

## Commands that use the Anonymous API

These commands interact with the Repository using the Anonymous API without the need of a session.

### rep_create_org 
```bash
./rep_create_org <organization> <username> <name> <email> <public key file>
```
Arguments:
- organization: the organization to create
- username: the username of the subject
- name: the name of the subject
- email: the email of the subject
- public key file: the file with the public key of the subject

Function:
- This command creates an organization and defines its first subject in the Repository.
---

### rep_list_orgs
```bash
./rep_list_orgs
```
Arguments:
- None

Function:
- This command lists all organizations defined in a Repository.
---

### rep_create_session
```bash
./rep_create_session <organization> <username> <password> <credentials file> <session file>
```
Arguments:
- organization: the organization to create the session
- username: the username of the subject
- password: the password of the subject
- credentials file: the file with the encrypted credentials of the subject
- session file: the file to store the session

Function:
- This command creates a session for a username belonging to an organization, and stores the session context in a file.

---

### rep_get_file 
```bash
./rep_get_file <file handle> [file]
```
Arguments:
- file handle: a digest of the file to retrieve
- file: the file to store the retrieved file

Function:
- This command downloads a file given its handle. The file contents are written to stdout or to the file referred in the optional last argument.

---

## Commands that use the Authenticated API

These commands interact with the Repository using the Authenticated API and require a session file, but not a role.

### rep_list_subjects
```bash
./rep_list_subjects <session file> [username]
```
Arguments:
- session file: the file with the session context
- username: the username to list the subjects

Function:
- This command lists the subjects of the organization with which I have currently a session. The listing should show the status of all the subjects (active or suspended). This command accepts an extra command to show only one subject.

---

### rep_list_docs
```bash
./rep_list_docs <session file> [-s username] [-d nt/ot/et date]
```
Arguments:
- session file: the file with the session context
- -s username: the username to list the documents
- -d nt/ot/et date: the date to list the documents

Function:
- This command lists the documents of the organization with which I have currently a session, possibly filtered by a subject that created them and by a date (newer than, older than, equal to), expressed in the DD-MM-YYYY format

---

### rep_assume_role
```bash
./rep_assume_role <session file> <role>
```
Arguments:
- session file: the file with the session context
- role: the role to assume

Function:
- This command requests the given role for the subject in the session context

---

### rep_drop_role
```bash
./rep_drop_role <session file> <role>
```

Arguments:
- session file: the file with the session context
- role: the role to drop

Function:
- This command drops the given role for the subject in the session context

---

### rep_list_roles
```bash
./rep_list_roles <session file>
```

Arguments:
- session file: the file with the session context

Function:
- This command lists the current session roles 

---

### rep_list_role_subjects 
```bash
./rep_list_role_subjects <session file> <role>
```

Arguments:
- session file: the file with the session context
- role: the role to list

Function:
- This command lists the subjects of a role of the organization with which I have currently a session.

---

### rep_list_subject_roles
```bash
./rep_list_subject_roles <session file> <username>
```

Arguments:
- session file: the file with the session context
- username: the username to list the roles

Function:
- This command lists the roles of a subject of the organization with which I have currently a session.

---

### rep_list_role_permissions
```bash
./rep_list_role_permissions <session file> <role>
```

Arguments:
- session file: the file with the session context
- role: the role to list

Function:
This command lists the permissions of a role of the organization with which I have currently a session.

---

### rep_list_permission_roles 
```bash
./rep_list_permission_roles <session file> <permission>
```

Arguments:
- session file: the file with the session context
- permission: the permission to list the roles

Function:
This command lists the roles of the organization with which I have currently a session that have a given permission. Use the names previously referred for the permission rights.

As roles can be used in documents’ ACLs to associate subjects to permissions, this command should also list the roles per document that have the given permission. Note: permissions for documents are different from the other organization permissions.

---

## Commands that use the Authorized API

These commands interact with the Repository using the Authorized API and require a session file and at least a role.

### rep_add_subject
```bash
./rep_add_subject <session file> <username> <name> <email> <credentials file>
```
Arguments:
- session file: the file with the session context
- username: the username of the subject
- name: the name of the subject
- email: the email of the subject
- credentials file: the file with the encrypted credentials of the subject

Function:
- This command adds a new subject to the organization with which I have currently a session. By default the subject is created in the active status. This commands requires a SUBJECT_NEW permission

---

### rep_suspend_subject 
```bash
./rep_suspend_subject <session file> <username>
```
Arguments:
- session file: the file with the session context
- username: the username of the subject

Function:
- This command suspends a subject of the organization with which I have currently a session. This commands requires a SUBJECT_DOWN permission
---

### rep_activate_subject
```bash
./rep_activate_subject <session file> <username>
```
Arguments:
- session file: the file with the session context
- username: the username of the subject

Function:
- This command activates a subject of the organization with which I have currently a session. This commands requires a SUBJECT_UP permission

---

### rep_add_doc
```bash
./rep_add_doc <session file> <document name> <file>
```
Arguments:
- session file: the file with the session context
- document name: the name of the document
- file: the file to upload

Function:
- This command adds a document with a given name to the organization with which I have currently a session. The document’s contents is provided as parameter with a file name. This commands requires a DOC_NEW permission.

---

### rep_get_doc_metadata
```bash
./rep_get_doc_metadata <session file> <document name>
```
Arguments:
- session file: the file with the session context
- document name: the name of the document

Function:
- This command fetches the metadata of a document with a given name to the organization with which I have currently a session. The output of this command is useful for getting the clear text contents of a document’s file. This commands requires a DOC_READ permission.

---

### rep_get_doc_file
```bash
./rep_get_doc_file <session file> <document name> [file]
```
Arguments:
- session file: the file with the session context
- document name: the name of the document
- file: the file to store the retrieved file

 Function:
 - This command is a combination of rep_get_doc_metadata with rep_get_file and rep_decrypt_file. The file contents are written to stdout or to the file referred in the optional last argument. This commands requires a DOC_READ permission.
---

### rep_delete_doc
```bash
./rep_delete_doc <session file> <document name>
```
Arguments:
- session file: the file with the session context
- document name: the name of the document

Function:
- This command clears file_handle in the metadata of a document with a given name on the organization with which I have currently a session. The output of this command is the file_handle that ceased to exist in the document’s metadata. This commands requires a DOC_DELETE permission.

### rep_add_role
```bash
./rep_add_role <session file> <role>
```

Arguments:
- session file: the file with the session context
- role: the role to add

Function:
This command adds a role to the organization with which I have currently a session. This commands requires a ROLE_NEW permission.

---

### rep_suspend_role 
```bash
./rep_suspend_role <session file> <role>
```

Arguments:
- session file: the file with the session context
- role: the role to suspend

Function:
This command suspends a role of the organization with which I have currently a session. This commands requires a ROLE_DOWN permission.

---

### rep_reactivate_role
```bash
./rep_reactivate_role <session file> <role>
```

Arguments:
- session file: the file with the session context
- role: the role to reactivate

Function:
This command reactivates a role of the organization with which I have currently a session. This commands requires a ROLE_UP permission.

---

### rep_add_permission
```bash
./rep_add_permission <session file> <role> <username/permission>
```

Arguments:
- session file: the file with the session context
- role: the role to add the permission
- username: the username to add the permission
- permission: the permission to add

Function:
This command adds a permission to a role of the organization with which I have currently a session. This commands requires a ROLE_MOD permission.

---

### rep_remove_permission
```bash
./rep_remove_permission <session file> <role> <username/permission>
```

Arguments:
- session file: the file with the session context
- role: the role to remove the permission
- username: the username to remove the permission
- permission: the permission to remove

Function:
This command removes a permission from a role of the organization with which I have currently a session. This commands requires a ROLE_MOD permission.

---

### rep_acl_doc
```bash
./rep_acl_doc <session file> <document name> [+/-] <role> <permission>
```

Arguments:
- session file: the file with the session context
- document name: the name of the document
- role: the role to add or remove the permission
- permission: the permission to add or remove

Function:
This command changes the ACL of a document by adding (+) or removing (-) a permission for a given role. Use the names previously referred for the permission rights. This commands requires a DOC_ACL permission.

# Roles and Permissions

## The available roles are:
- manager
- supervisor
- member
- guest

## The available permissions are:
### Document permissions:
    - DOC_READ
    - DOC_DELETE
    - DOC_ACL

### Organization permissions:
    - SUBJECT_NEW
    - SUBJECT_DOWN
    - SUBJECT_UP
    - DOC_NEW

### Role permissions:
    - ROLE_NEW
    - ROLE_DOWN
    - ROLE_UP
    - ROLE_MOD

## Permissions for the roles:
### manager 
    - DOC_READ
    - DOC_DELETE
    - DOC_NEW
    - DOC_ACL
    - ROLE_NEW
    - ROLE_DOWN
    - ROLE_UP
    - ROLE_MOD 
    - SUBJECT_NEW
    - SUBJECT_DOWN
    - SUBJECT_UP

### supervisor
    - DOC_READ
    - DOC_DELETE
    - DOC_NEW
    - DOC_ACL
    - ROLE_NEW
    - SUBJECT_DOWN
    - SUBJECT_UP

### member
    - DOC_READ
    - DOC_DELETE
    - DOC_NEW

### guest
    - DOC_READ