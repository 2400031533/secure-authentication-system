# Secure Authentication System

A Flask web application demonstrating registration and login, bcrypt password hashing, JWT authentication, HttpOnly cookies, CSRF-protected forms, and a private dashboard.

## Features
- Registration with username/password validation.
- bcrypt password hashing (no plain-text passwords stored).
- Signed JWT access token with 30-minute expiration.
- JWT stored in an HttpOnly, SameSite=Lax cookie.
- CSRF protection for form submissions with Flask-WTF.
- Protected dashboard and `/api/me` endpoint.
- SQLite persistence and unit tests.

## Setup
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```
Edit `.env` and set unique, long random values for `SECRET_KEY` and `JWT_SECRET_KEY`. Start:
```bash
python app.py
```
Open http://127.0.0.1:5001

On macOS/Linux, activate with `source .venv/bin/activate` and copy with `cp .env.example .env`.

## Test
```bash
python -m unittest discover -s tests -v
```

## Routes
- `GET /` — landing page
- `GET/POST /register` — create account
- `GET/POST /login` — sign in
- `GET /dashboard` — protected page
- `POST /logout` — clear authentication cookie
- `GET /api/me` — authenticated profile JSON
- `GET /health` — health check

## Security notes
This is an educational starter, not a production-ready identity service. Use HTTPS in deployment and set `JWT_COOKIE_SECURE=true`. Add rate limiting, email verification, password reset, account lockout, monitoring, stronger operational secret management, and a professional security review before real-world use. Never commit `.env` or a database containing real user information.
