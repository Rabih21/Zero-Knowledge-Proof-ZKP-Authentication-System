from flask import Flask, render_template, request, jsonify, session, redirect
import sqlite3
import os
from crypto import *

app = Flask(__name__)
app.secret_key = "ZKP_DEMO_SECRET"

DB = "database.db"

# ----------------- DATABASE -----------------

def init_db():
    con = sqlite3.connect(DB)
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

def db():
    return sqlite3.connect(DB)

# ----------------- AUDIT LOG -----------------

audit_log = {
    "register": {},
    "login_start": {},
    "login_finish": {}
}

# ----------------- ROUTES -----------------

@app.route("/")
def login_page():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# -------- REGISTRATION --------

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
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

        audit_log["register"] = {
            "client": {"username": user, "password": "***HIDDEN***"},
            "server": {"salt": salt, "verifier": str(verifier)}
        }

        return jsonify({"status":"REGISTERED","salt":salt,"verifier":str(verifier)})

    return render_template("register.html")

# -------- LOGIN PHASE 1 --------

@app.route("/login/start", methods=["POST"])
def login_start():
    data = request.json
    user = data["username"]

    con = db()
    cur = con.cursor()
    cur.execute("SELECT salt FROM users WHERE username=?", (user,))
    row = cur.fetchone()
    con.close()

    if not row:
        return jsonify({"error":"User not found"}), 404

    salt = row[0]
    C = generate_challenge()
    session["challenge"] = C
    session["user"] = user

    audit_log["login_start"] = {
        "client": {"username": user},
        "server": {"challenge": C, "salt": salt}
    }

    return jsonify({"challenge": C, "salt": salt})

# -------- LOGIN PHASE 2 --------

@app.route("/login/finish", methods=["POST"])
def login_finish():
    data = request.json
    A = int(data["A"])
    proof = int(data["proof"])
    user = session.get("user")

    con = db()
    cur = con.cursor()
    cur.execute("SELECT verifier FROM users WHERE username=?", (user,))
    v = int(cur.fetchone()[0])
    con.close()

    C = session.get("challenge")
    expected = H(A, C, v)

    audit_log["login_finish"] = {
        "client": {"A": A, "proof": proof},
        "server": {"expected_proof": expected}
    }

    if expected == proof:
        return jsonify({"status":"AUTHENTICATED"})
    return jsonify({"status":"FAILED"})

# -------- AUDIT API --------

@app.route("/audit")
def audit():
    return jsonify(audit_log)

# ----------------- MAIN -----------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
