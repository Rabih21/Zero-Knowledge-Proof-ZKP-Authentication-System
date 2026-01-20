import hashlib
import secrets

# Large safe prime (demo-grade but strong)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
)
G = 2

def H(*args):
    h = hashlib.sha256()
    for a in args:
        h.update(str(a).encode())
    return int(h.hexdigest(), 16)

def generate_salt():
    return secrets.token_hex(16)

def password_to_secret(password, salt):
    return H(password, salt) % (P - 1)

def generate_verifier(password, salt):
    x = password_to_secret(password, salt)
    return pow(G, x, P)

def generate_commitment():
    r = secrets.randbelow(P - 1)
    A = pow(G, r, P)
    return r, A

def generate_challenge():
    return secrets.randbits(256)
