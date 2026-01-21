# crypto.py
import hashlib
import secrets
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

# ======================
# ZKP PARAMETERS (RFC 3526 Group 5 - 1536-bit safe prime)
# ======================
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16
)
G = 2

# ======================
# ZKP UTILITIES
# ======================
def H(*args):
    """Hash function used in ZKP: SHA-256 of concatenated string representations."""
    h = hashlib.sha256()
    for a in args:
        h.update(str(a).encode('utf-8'))
    return int(h.hexdigest(), 16)

def generate_salt():
    """Generate random 16-byte salt as hex string."""
    return secrets.token_hex(16)

def password_to_secret(password, salt):
    """Derive secret x = H(salt, password) mod (P-1)."""
    return H(salt, password) % (P - 1)

def generate_verifier(password, salt):
    """Compute verifier v = g^x mod P."""
    x = password_to_secret(password, salt)
    return pow(G, x, P)

def generate_challenge():
    """Generate 256-bit random challenge."""
    return secrets.randbits(256)

# ======================
# FILE ENCRYPTION SYSTEM (HYBRID RSA+AES)
# ======================
KEYS_DIR = "user_keys"
os.makedirs(KEYS_DIR, exist_ok=True)

def get_user_key_path(username: str) -> str:
    """Get path to user's RSA private key file."""
    safe_name = "".join(c for c in username if c.isalnum() or c in "._-")
    return os.path.join(KEYS_DIR, f"{safe_name}.pem")

def ensure_user_rsa_keypair(username: str):
    """Generate RSA key pair if it doesn't exist."""
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
    """
    Hybrid encryption:
    1. Generate random AES-256 key and IV
    2. Encrypt data with AES-CBC + PKCS7 padding
    3. Encrypt AES key with RSA-OAEP
    4. Return: [encrypted_aes_key (256 bytes)] + [iv (16)] + [ciphertext]
    """
    # Step 1: Generate AES key and IV
    aes_key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)       # 128-bit IV

    # Step 2: Pad and encrypt data with AES
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Step 3: Encrypt AES key with RSA
    key_path = get_user_key_path(username)
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    public_key = private_key.public_key()
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 4: Bundle everything
    return encrypted_aes_key + iv + ciphertext

def decrypt_file_for_user(encrypted_data: bytes, username: str) -> bytes:
    """
    Hybrid decryption:
    1. Split bundle into encrypted AES key, IV, and ciphertext
    2. Decrypt AES key with RSA
    3. Decrypt data with AES
    4. Remove PKCS7 padding
    """
    # Validate input size
    rsa_encrypted_size = 256  # 2048-bit RSA → 256 bytes
    if len(encrypted_data) < rsa_encrypted_size + 16:
        raise ValueError("Encrypted data too short")

    # Step 1: Split bundle
    encrypted_aes_key = encrypted_data[:rsa_encrypted_size]
    iv = encrypted_data[rsa_encrypted_size:rsa_encrypted_size + 16]
    ciphertext = encrypted_data[rsa_encrypted_size + 16:]

    # Step 2: Decrypt AES key
    key_path = get_user_key_path(username)
    if not os.path.exists(key_path):
        raise FileNotFoundError("User key not found")
    
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Step 3: Decrypt data
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Step 4: Unpad
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext