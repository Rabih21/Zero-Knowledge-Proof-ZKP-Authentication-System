from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
from crypto import *

app = Flask(__name__)
app.secret_key = "STRONG_ZKP_SECRET"
DB = "database.db"

# ---------------- DATABASE ----------------
def db():
    return sqlite3.connect(DB)

def init_db():
    con = db()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,
            salt TEXT,
            verifier TEXT
        )
    """)
    con.commit()
    con.close()

# ---------------- AUDIT LOG ----------------
audit_log = {
    "register": {},
    "login_start": {},
    "login_finish": {}
}

# ---------------- ROUTING LOGIC ----------------

@app.route("/")
def index():
    # Always start at registration
    return redirect(url_for("register_page"))

# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    user = data["username"]
    pwd = data["password"]

    salt = generate_salt()
    verifier = generate_verifier(pwd, salt)

    con = db()
    cur = con.cursor()
    cur.execute("INSERT OR REPLACE INTO users VALUES (?,?,?)",
                (user, salt, str(verifier)))
    con.commit()
    con.close()

    session.clear()
    session["registered"] = True
    session["pending_user"] = user

    audit_log["register"] = {
        "client": {"username": user},
        "server": {"salt": salt, "verifier": verifier}
    }

    return jsonify({"status": "REGISTERED", "redirect": "/login"})

# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET"])
def login_page():
    if not session.get("registered"):
        return redirect(url_for("register_page"))
    return render_template("login.html")

@app.route("/login/start", methods=["POST"])
def login_start():
    user = request.json["username"]

    con = db()
    cur = con.cursor()
    cur.execute("SELECT salt FROM users WHERE username=?", (user,))
    row = cur.fetchone()
    con.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    salt = row[0]
    C = generate_challenge()

    session["user"] = user
    session["challenge"] = C

    audit_log["login_start"] = {
        "client": {"username": user},
        "server": {"salt": salt, "challenge": C}
    }

    return jsonify({"salt": salt, "challenge": C})

@app.route("/login/finish", methods=["POST"])
def login_finish():
    data = request.json
    A = int(data["A"])
    s = int(data["s"])
    user = session.get("user")

    if not user:
        return jsonify({"error": "Session expired"}), 403

    con = db()
    cur = con.cursor()
    cur.execute("SELECT verifier FROM users WHERE username=?", (user,))
    v = int(cur.fetchone()[0])
    con.close()

    C = session.get("challenge")
    e = H(A, C) % (P - 1)

    left = pow(G, s, P)
    right = (A * pow(v, e, P)) % P

    audit_log["login_finish"] = {
        "client": {"A": A, "s": s},
        "server": {"g^s": left, "A·v^e": right}
    }

    if left == right:
        session["authenticated"] = True
        return jsonify({"status": "AUTHENTICATED", "redirect": "/dashboard"})

    return jsonify({"status": "FAILED"})

# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():
    if not session.get("authenticated"):
        return redirect(url_for("login_page"))
    return render_template("dashboard.html")

# ---------------- AUDIT API ----------------

@app.route("/audit")
def audit():
    if not session.get("authenticated"):
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify(audit_log)

# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("register_page"))

# ---------------- MAIN ----------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
