import os, json, base64, getpass, traceback

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def encrypt_data(data, public_key_path):
    if not os.path.exists(public_key_path):
        print(f"Error: Public key file '{public_key_path}' not found.")
        return None

    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    json_data = json.dumps(data).encode("utf-8")
    max_chunk_size = public_key.key_size // 8 - 66

    chunks = [
        json_data[i : i + max_chunk_size]
        for i in range(0, len(json_data), max_chunk_size)
    ]

    encrypted_chunks = [
        public_key.encrypt(chunk, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        for chunk in chunks
    ]

    encoded_chunks = []

    for chunk in encrypted_chunks:
        encoded_chunks.append(base64.b64encode(chunk).decode("utf-8"))

    return encoded_chunks

def load_private_key(private_key_path):
    """Carrega a chave privada diretamente a partir do caminho fornecido."""
    with open(private_key_path, "rb") as f:
            password = getpass.getpass("Enter the password for the private key: ")
            try:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode(),
                    backend=default_backend()
                )
            except:
                print("Wrong credentials. Exiting.")
                exit(-1)
    return private_key

def decrypt_response(encrypted_data, key_name):
    """Desencripta os dados recebidos do servidor usando a chave privada."""
    try:
        private_key_path = os.path.join("../api/keys/subjectKeys/", key_name).replace(".pub", "")

        private_key = load_private_key(private_key_path)
        decrypted_data = b"".join([
            private_key.decrypt(
                base64.b64decode(chunk),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ) for chunk in encrypted_data
        ])
        return json.loads(decrypted_data)
    except Exception as e:
        traceback.print_exc()
        raise ValueError(f"Error decrypting response: {str(e)}")