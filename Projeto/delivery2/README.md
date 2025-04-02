# Delivery 2 commands 

## Commands that use the Authenticated API

These commands interact with the Repository using the Authenticated API and require a session file, but not a role.

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