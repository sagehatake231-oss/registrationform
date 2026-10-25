import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)
app.secret_key = "development-key-change-this"
SECURITY_PASSWORD_SALT = "salt-key-for-tokens"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "users.db")

def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.secret_key)
    return serializer.dumps(email, salt=SECURITY_PASSWORD_SALT)

def confirm_verification_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.secret_key)
    try:
        return serializer.loads(token, salt=SECURITY_PASSWORD_SALT, max_age=expiration)
    except (SignatureExpired, BadSignature):
        return None

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fullname TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_verified INTEGER DEFAULT 0
            )
        """)
        conn.commit()

init_db()

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("register"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        print("\n" + "=" * 50)
        print(">>> REGISTRATION FORM SUBMITTED <<<")
        print(f"Full Name: '{fullname}'")
        print(f"Username: '{username}'")
        print(f"Email: '{email}'")
        print(f"Password length: {len(password)}")

        # Validation checks
        if not fullname or not username or not email or not password or not confirm_password:
            print("[FAILED] One or more fields are completely empty!")
            print("=" * 50 + "\n")
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            print("[FAILED] Password and Confirm Password do not match!")
            print("=" * 50 + "\n")
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            print("[FAILED] Password is under 8 characters!")
            print("=" * 50 + "\n")
            flash("Password must be at least 8 characters long.", "danger")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password)

        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (fullname, username, email, password_hash, is_verified) VALUES (?, ?, ?, ?, 0)",
                    (fullname, username, email, hashed_pw)
                )
                conn.commit()
            print("[SUCCESS] User written to users.db successfully!")
        except sqlite3.IntegrityError as err:
            print(f"[FAILED] Database Integrity Error (duplicate username or email): {err}")
            print("=" * 50 + "\n")
            flash("Username or email already exists.", "danger")
            return redirect(url_for("register"))
        except Exception as err:
            print(f"[FAILED] Unexpected DB error: {err}")
            print("=" * 50 + "\n")
            flash("Database error.", "danger")
            return redirect(url_for("register"))

        # Create verification link
        token = generate_verification_token(email)
        verify_url = url_for("verify_email", token=token, _external=True)

        print("\n" + "*" * 60)
        print(f"CLICK THIS LINK TO VERIFY {email}:")
        print(verify_url)
        print("*" * 60 + "\n")

        flash("Registration successful! Check your terminal for the verification link.", "info")
        return redirect(url_for("login"))

    return render_template("registration.html")

@app.route("/verify/<token>")
def verify_email(token):
    email = confirm_verification_token(token)
    if not email:
        flash("The verification link is invalid or expired.", "danger")
        return redirect(url_for("register"))

    with get_db() as conn:
        conn.execute("UPDATE users SET is_verified = 1 WHERE email = ?", (email,))
        conn.commit()

    flash("Email verified successfully! You can now log in.", "success")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            if user["is_verified"] == 0:
                flash("Please verify your email first! (Check VS Code terminal).", "warning")
                return redirect(url_for("login"))

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["fullname"] = user["fullname"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in to view the dashboard.", "warning")
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        fullname=session.get("fullname"),
        username=session.get("username"),
        email=session.get("email")
    )

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)