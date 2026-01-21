# crypto.py
import hashlib
import secrets
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# ===== ZKP PARAMETERS =====
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16
)
G = 2

# ===== ZKP UTILITIES =====
def H(*args):
    h = hashlib.sha256()
    for a in args:
        h.update(str(a).encode('utf-8'))
    return int(h.hexdigest(), 16)

def generate_salt():
    return secrets.token_hex(16)

def password_to_secret(password, salt):
    return H(salt, password) % (P - 1)

def generate_verifier(password, salt):
    x = password_to_secret(password, salt)
    return pow(G, x, P)

def generate_challenge():
    return secrets.randbits(256)

# ===== RSA FILE CRYPTO =====
KEYS_DIR = "user_keys"
os.makedirs(KEYS_DIR, exist_ok=True)

def get_user_key_path(username: str) -> str:
    return os.path.join(KEYS_DIR, f"{username}.pem")

def ensure_user_rsa_keypair(username: str):
    key_path = get_user_key_path(username)
    if not os.path.exists(key_path):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(key_path, "wb") as f:
            f.write(pem)

def encrypt_file_for_user(data: bytes, username: str) -> bytes:
    key_path = get_user_key_path(username)
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    public_key = private_key.public_key()
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_file_for_user(encrypted_data: bytes, username: str) -> bytes:
    key_path = get_user_key_path(username)
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )