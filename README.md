# 🔐 Zero-Knowledge Password Proof (ZKPP) Demo

A secure, educational implementation of a **password-based authentication system** using **zero-knowledge principles**. The server never sees the user's password not even a hash of it and cannot impersonate the user.

Built with **Flask**, **JavaScript**, and cryptographic primitives based on the **Schnorr identification protocol** adapted for password authentication.

## ✨ Features

- **Zero-Knowledge**: Server stores only a *verifier* (`g^x mod P`), not the password or its hash.
- **No plaintext exposure**: Password never leaves the client.
- **Secure randomness**: Uses `crypto.getRandomValues()` (browser) and `secrets` (Python).
- **Audit dashboard**: View cryptographic values used during registration and login.
- **Automatic flow**: Register → Login → Dashboard with seamless redirects.
- **Large safe prime**: Uses a 1536-bit RFC 3526 MODP group for strong security.

## 🛠️ How It Works

### Registration
1. User submits username + password.
2. Server generates random **salt**.
3. Client & server compute secret `x = H(salt, password)`.
4. Server stores `verifier = g^x mod P`.

### Login (Zero-Knowledge Proof)
1. Client requests login → gets `salt` and **challenge** (large random number).
2. Client computes:
   - `x = H(salt, password)`
   - Random `r`, then `A = g^r mod P`
   - `e = H(A, challenge)`
   - Proof `s = r + e·x mod (P-1)`
3. Client sends `(A, s)` to server.
4. Server verifies: `g^s ≟ A · verifier^e mod P`

✅ If equal → user is authenticated.  
❌ No password, hash, or secret is ever transmitted.


## 📦 Requirements

- Python 3.7+
- Flask
- Web browser with modern JavaScript support

## ▶️ Quick Start

```bash
# Clone or create project directory
git clone <your-repo>  # or just save the files
cd zkpp-demo

# Install dependencies
pip install flask

# Run the app
python app.py
```

Open your browser to:  
👉 **http://localhost:5000**

---

## 🗂️ Project Structure

```
zkpp-demo/
├── app.py                 # Main Flask application
├── crypto.py              # Cryptographic utilities (Python)
├── database.db            # SQLite user database (auto-created)
├── static/
│   ├── crypto.js          # Frontend crypto logic
│   └── style.css          # Styling
└── templates/
    ├── register.html      # Registration page
    ├── login.html         # Login page
    └── dashboard.html     # Audit dashboard
```


## 🔒 Security Notes

- **For educational/demo purposes only**.
- Uses a **custom ZKPP scheme**  not standardized like SRP or OPAQUE.

## 🧪 Testing

1. Go to **http://localhost:5000**
2. **Register** a new user (e.g., `alice` / `mypassword`)
3. You’ll be **automatically redirected to login**
4. Enter the same credentials → should show **"AUTHENTICATED"**
5. You’ll be redirected to the **Audit Dashboard**
6. View the full cryptographic trace of your session!