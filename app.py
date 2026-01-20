# app.py
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
from crypto import *

app = Flask(__name__)
app.secret_key = "TEST!"
DB = "database.db"

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

audit_log = {
    "register": {},
    "login_start": {},
    "login_finish": {}
}

@app.route("/")
def index():
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

    audit_log["register"] = {
        "client": {"username": user},
        "server": {"salt": salt, "verifier": verifier}
    }

    return jsonify({"status": "REGISTERED", "redirect": "/login"})

# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET"])
def login_page():
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
    C = generate_challenge()  # int

    session["user"] = user
    session["challenge"] = C  # store as int

    # SEND CHALLENGE AS STRING TO AVOID JS PRECISION LOSS
    return jsonify({"salt": salt, "challenge": str(C)})

@app.route("/login/finish", methods=["POST"])
def login_finish():
    if "user" not in session or "challenge" not in session:
        return jsonify({"error": "Session expired"}), 403

    data = request.json
    try:
        A = int(data["A"])
        s = int(data["s"])
    except (ValueError, TypeError, KeyError):
        return jsonify({"error": "Invalid input"}), 400

    user = session["user"]
    C = session["challenge"]  # this is an int

    con = db()
    cur = con.cursor()
    cur.execute("SELECT verifier FROM users WHERE username=?", (user,))
    row = cur.fetchone()
    con.close()

    if not row:
        return jsonify({"error": "User not found"}), 404

    v = int(row[0])
    e = H(A, C) % (P - 1)  # C is int → str(C) is decimal string

    left = pow(G, s, P)
    right = (A * pow(v, e, P)) % P

    audit_log["login_finish"] = {
        "client": {"A": A, "s": s},
        "server": {"g^s": left, "A·v^e": right}
    }

    if left == right:
        session["authenticated"] = True
        return jsonify({"status": "AUTHENTICATED", "redirect": "/dashboard"})
    else:
        return jsonify({"status": "FAILED"}), 401

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