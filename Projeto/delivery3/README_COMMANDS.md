# **Fluxo de Teste da Aplicação - Sistema de Repositório Seguro**

Este README contém instruções para testar todas as funcionalidades do sistema de repositório seguro. Todos os comandos são executados na pasta `./scripts/`, e o servidor deve estar ativo antes de iniciar os testes.

---

## **1. Configuração Inicial**

Certifique-se de ter o seguinte configurado antes de começar:

1. **Instalar dependências**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Iniciar o servidor** (executar no diretório raiz do projeto):
   ```bash
   python3 delivery2/api/app.py
   ```
3. **Executar comandos**: Abra outro terminal e navegue até o diretório `scripts` para testar os comandos.

---

## **2. Fluxo Completo de Teste**

### **Passo 1: Gerar Credenciais**

Crie credenciais do sujeito, gerando um par de chaves privadas/públicas:

```bash
./rep_subject_credentials "password123" "../api/keys/subjectKeys/key.pem"
```

---

### **Passo 2: Criar uma Organização**

Crie uma nova organização e o administrador inicial (com o papel `manager`):

```bash
./rep_create_org "org1" "admin" "Admin User" "admin@example.com" "../api/keys/subjectKeys/key.pem.pub"
```

---

### **Passo 3: Listar Organizações**

Verifique as organizações criadas:

```bash
./rep_list_orgs
```

---

### **Passo 4: Criar uma Sessão**

Crie uma sessão para o administrador da organização:

```bash
./rep_create_session "org1" "admin" "Abcdabcd123?" "../api/keys/subjectKeys/key.pem" "../api/sessions/session_file.txt"
```

---

### **Passo 5: Gerir Roles**

1. **Criar um role**:

   ```bash
   ./rep_add_role "../api/sessions/session_file.txt" "guest"
   ```

2. **Suspender um role**:

   ```bash
   ./rep_suspend_role "../api/sessions/session_file.txt" "guest"
   ```

3. **Reativar um role**:

   ```bash
   ./rep_reactivate_role "../api/sessions/session_file.txt" "guest"
   ```

4. **Listar roles atuais da sessão**:

   ```bash
   ./rep_list_roles "../api/sessions/session_file.txt"
   ```

5. **Assumir um role**:

   ```bash
   ./rep_assume_role "../api/sessions/session_file.txt" "manager"
   ```

6. **Liberar um role**:

   ```bash
   ./rep_drop_role "../api/sessions/session_file.txt" "manager"
   ```

---

### **Passo 6: Gerir Permissões**

1. **Adicionar permissão a um role**:

   ```bash
   ./rep_add_permission "../api/sessions/session_file.txt" "guest" "DOC_NEW"
   ```

2. **Adicionar uma role a um sujeito**:

   ```bash
   ./rep_add_permission "../api/sessions/session_file.txt" "manager" "username"
   ```

3. **Remover permissão de um role**:

   ```bash
   ./rep_remove_permission "../api/sessions/session_file.txt" "guest" "DOC_NEW"
   ```

4. **Remover a role de um sujeito**:

   ```bash
   ./rep_remove_permission "../api/sessions/session_file.txt" "guest" "username"
   ```

5. **Listar permissões de um role**:

   ```bash
   ./rep_list_role_permissions "../api/sessions/session_file.txt" "guest"
   ```

6. **Listar roles com uma permissão específica**:

   ```bash
   ./rep_list_permission_roles "../api/sessions/session_file.txt" "DOC_READ"
   ```

---

### **Passo 7: Gerir Sujeitos**

1. **Criar um novo sujeito**:

   ```bash
   ./rep_add_subject "../api/sessions/session_file.txt" "john_doe" "John Doe" "john@example.com" "../api/keys/subjectKeys/key.pem.pub"
   ```

2. **Suspender um sujeito**:

   ```bash
   ./rep_suspend_subject "../api/sessions/session_file.txt" "john_doe"
   ```

3. **Reativar um sujeito**:

   ```bash
   ./rep_activate_subject "../api/sessions/session_file.txt" "john_doe"
   ```

4. **Listar sujeitos da organização**:

   ```bash
   ./rep_list_subjects "../api/sessions/session_file.txt"
   ```

5. **Listar roles de um sujeito específico**:

   ```bash
   ./rep_list_subject_roles "../api/sessions/session_file.txt" "john_doe"
   ```

6. **Listar sujeitos associados a um role**:

   ```bash
   ./rep_list_role_subjects "../api/sessions/session_file.txt" "guest"
   ```

---

### **Passo 8: Manipular Documentos**

1. **Adicionar um documento**:

   ```bash
   ./rep_add_doc "../api/sessions/session_file.txt" "file1.txt" "../api/files/file1.txt"
   ```

2. **Listar documentos da organização**:

   ```bash
   ./rep_list_docs "../api/sessions/session_file.txt"
   ```

3. **Baixar metadados do documento**:

   ```bash
   ./rep_get_doc_metadata "../api/sessions/session_file.txt" "file1.txt"
   ```

4. **Baixar conteúdo do documento**:

   ```bash
   ./rep_get_doc_file "../api/sessions/session_file.txt" "file1.txt" "../api/files/downloaded_file1.txt"
   ```

5. **Descriptografar um arquivo local**:

   ```bash
   ./rep_decrypt_file "../api/files/encrypted_file1.txt" "../api/files/encryption_metadata.json"
   ```

6. **Alterar ACL de um documento**:

   - Adicionar permissão:
     ```bash
     ./rep_acl_doc "../api/sessions/session_file.txt" "file1.txt" "+" "guest" "DOC_READ"
     ```
   - Remover permissão:
     ```bash
     ./rep_acl_doc "../api/sessions/session_file.txt" "file1.txt" "-" "guest" "DOC_READ"
     ```

7. **Excluir um documento**:

   ```bash
   ./rep_delete_doc "../api/sessions/session_file.txt" "file1.txt"
   ```

8. **Retornar o conteúdo do documento**:
   ```bash
   ./rep_get_file <file handle>
   ```

---

### **Passo 9: Verificar Integridade**

1. **Descriptografar e verificar a integridade de um arquivo baixado**:

   ```bash
   ./rep_decrypt_file "../api/files/encrypted_file1.txt" "../api/files/encryption_metadata.json"
   ```

---

## **Resumo do Fluxo Completo**

1. Gerar credenciais.
2. Criar organização e usuário administrador.
3. Criar sessão.
4. Gerenciar roles (criar, suspender, reativar, assumir, liberar).
5. Gerenciar permissões (adicionar, remover, listar).
6. Criar sujeitos e associar a roles.
7. Manipular documentos (upload, download, metadados, ACL, delete).
8. Verificar integridade e descriptografar arquivos.

---
