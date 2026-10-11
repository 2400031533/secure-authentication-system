from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sqlite3

import bcrypt
import jwt
from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from flask_wtf.csrf import CSRFProtect

load_dotenv()
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "auth.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "development-only-change-me")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "development-jwt-only-change-me")
app.config["JWT_COOKIE_SECURE"] = os.getenv("JWT_COOKIE_SECURE", "false").lower() == "true"
app.config["JWT_COOKIE_HTTPONLY"] = True
app.config["JWT_COOKIE_SAMESITE"] = "Lax"
app.config["WTF_CSRF_TIME_LIMIT"] = 3600
csrf = CSRFProtect(app)

JWT_COOKIE_NAME = "access_token"
JWT_ALGORITHM = "HS256"
JWT_TTL_MINUTES = 30

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

def create_token(user_id, username):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_TTL_MINUTES),
    }
    return jwt.encode(payload, app.config["JWT_SECRET_KEY"], algorithm=JWT_ALGORITHM)

def current_user():
    token = request.cookies.get(JWT_COOKIE_NAME)
    if not token:
        return None
    try:
        payload = jwt.decode(token, app.config["JWT_SECRET_KEY"], algorithms=[JWT_ALGORITHM])
        with get_db() as conn:
            user = conn.execute(
                "SELECT id, username, created_at FROM users WHERE id = ?",
                (int(payload["sub"]),)
            ).fetchone()
        return dict(user) if user else None
    except (jwt.InvalidTokenError, ValueError, KeyError, TypeError):
        return None

@app.get("/")
def index():
    user = current_user()
    return render_template("index.html", user=user)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not (3 <= len(username) <= 30) or not username.replace("_", "").isalnum():
        flash("Username must be 3–30 characters and use only letters, numbers, or underscores.", "error")
        return render_template("register.html"), 400
    if len(password) < 10:
        flash("Password must contain at least 10 characters.", "error")
        return render_template("register.html"), 400
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    try:
        with get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, datetime.now(timezone.utc).isoformat())
            )
            user_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        flash("That username is already registered. Please choose another.", "error")
        return render_template("register.html"), 409

    response = redirect(url_for("dashboard"))
    response.set_cookie(
        JWT_COOKIE_NAME, create_token(user_id, username),
        httponly=True, secure=app.config["JWT_COOKIE_SECURE"],
        samesite=app.config["JWT_COOKIE_SAMESITE"],
        max_age=JWT_TTL_MINUTES * 60, path="/"
    )
    return response

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    with get_db() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"]):
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401

    response = redirect(url_for("dashboard"))
    response.set_cookie(
        JWT_COOKIE_NAME, create_token(user["id"], user["username"]),
        httponly=True, secure=app.config["JWT_COOKIE_SECURE"],
        samesite=app.config["JWT_COOKIE_SAMESITE"],
        max_age=JWT_TTL_MINUTES * 60, path="/"
    )
    return response

@app.get("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        flash("Please sign in to view your dashboard.", "error")
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=user, token_minutes=JWT_TTL_MINUTES)

@app.post("/logout")
def logout():
    response = redirect(url_for("index"))
    response.delete_cookie(JWT_COOKIE_NAME, path="/", httponly=True,
                           secure=app.config["JWT_COOKIE_SECURE"],
                           samesite=app.config["JWT_COOKIE_SAMESITE"])
    flash("You have been signed out.", "success")
    return response

@app.get("/api/me")
def api_me():
    user = current_user()
    if not user:
        return jsonify({"error": "Authentication required or token expired."}), 401
    return jsonify({"id": user["id"], "username": user["username"], "created_at": user["created_at"]})

@app.get("/health")
def health():
    return jsonify({"status": "ok"})

init_db()

if __name__ == "__main__":
    # Local development only. Use a production WSGI server and HTTPS for deployment.
    app.run(debug=True, port=5001)
