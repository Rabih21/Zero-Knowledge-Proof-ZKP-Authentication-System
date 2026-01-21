# app.py
import os
import sqlite3
from flask import (
    Flask, render_template, request, jsonify, session,
    redirect, url_for, send_file
)
from io import BytesIO
from werkzeug.utils import secure_filename
from crypto import (
    generate_salt, generate_verifier, generate_challenge, H, P, G,
    ensure_user_rsa_keypair, encrypt_file_for_user, decrypt_file_for_user,
    get_user_key_path
)

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_CHANGE_IN_PROD_2026!"
DB_PATH = "database.db"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ======================
# DATABASE
# ======================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt TEXT NOT NULL,
                verifier TEXT NOT NULL
            )
        """)
        conn.commit()

# ======================
# AUTHENTICATION (ZKP)
# ======================
@app.route("/")
def index():
    return redirect(url_for("register_page"))

@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    salt = generate_salt()
    verifier = generate_verifier(password, salt)

    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO users (username, salt, verifier) VALUES (?, ?, ?)",
            (username, salt, str(verifier))
        )
        conn.commit()

    return jsonify({"status": "REGISTERED", "redirect": "/login"})

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/login/start", methods=["POST"])
def login_start():
    data = request.get_json()
    username = data.get("username", "").strip()
    
    with get_db() as conn:
        row = conn.execute(
            "SELECT salt FROM users WHERE username = ?", (username,)
        ).fetchone()
    
    if not row:
        return jsonify({"error": "User not found"}), 404

    salt = row["salt"]
    challenge = generate_challenge()
    session["user"] = username
    session["challenge"] = challenge

    return jsonify({"salt": salt, "challenge": str(challenge)})

@app.route("/login/finish", methods=["POST"])
def login_finish():
    if "user" not in session or "challenge" not in session:
        return jsonify({"error": "Session expired"}), 403

    data = request.get_json()
    try:
        A = int(data["A"])
        s = int(data["s"])
    except (TypeError, ValueError, KeyError):
        return jsonify({"error": "Invalid proof"}), 400

    username = session["user"]
    challenge = session["challenge"]

    with get_db() as conn:
        row = conn.execute(
            "SELECT verifier FROM users WHERE username = ?", (username,)
        ).fetchone()
    
    if not row:
        return jsonify({"error": "User not found"}), 404

    v = int(row["verifier"])
    e = H(A, challenge) % (P - 1)
    left = pow(G, s, P)
    right = (A * pow(v, e, P)) % P

    if left == right:
        session["authenticated"] = True
        session["username"] = username
        return jsonify({"status": "AUTHENTICATED", "redirect": "/dashboard"})
    else:
        return jsonify({"status": "FAILED"}), 401

# ======================
# FILE ENCRYPTION SYSTEM
# ======================
@app.route("/dashboard")
def dashboard():
    if not session.get("authenticated"):
        return redirect(url_for("login_page"))
    return render_template("dashboard.html")

@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 403
    
    username = session["username"]
    ensure_user_rsa_keypair(username)

    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    try:
        data = file.read()
        encrypted = encrypt_file_for_user(data, username)
        return send_file(
            BytesIO(encrypted),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=f"{secure_filename(file.filename)}.enc"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 403
    
    username = session["username"]
    if not os.path.exists(get_user_key_path(username)):
        return jsonify({"error": "Encrypt a file first"}), 400

    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    file = request.files["file"]
    try:
        encrypted_data = file.read()
        plaintext = decrypt_file_for_user(encrypted_data, username)
        try:
            text = plaintext.decode("utf-8")
            return jsonify({"content": text})
        except UnicodeDecodeError:
            return jsonify({"content": "BINARY_FILE", "size_bytes": len(plaintext)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ======================
# SESSION
# ======================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("register_page"))

# ======================
# MAIN
# ======================
if __name__ == "__main__":
    init_db()
    app.run(debug=True)