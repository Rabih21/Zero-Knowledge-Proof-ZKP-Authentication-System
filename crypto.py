import hashlib
import secrets

P = 208351617316091241234326746312124448251235562226470491514186331217050270460481
G = 2

def H(*args):
    h = hashlib.sha256()
    for a in args:
        h.update(str(a).encode())
    return int(h.hexdigest(), 16)

def generate_salt():
    return secrets.token_hex(16)

def generate_verifier(password, salt):
    x = H(password, salt)
    return pow(G, x, P)

def generate_A():
    r = secrets.randbits(256)
    A = pow(G, r, P)
    return r, A

def generate_challenge():
    return secrets.randbits(256)

def generate_proof(A, C, password, salt):
    x = H(password, salt)
    return H(A, C, x)
