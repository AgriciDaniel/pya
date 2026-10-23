#!/usr/bin/env bash
# Scaffold for the clean-baseline eval case: a small Flask notes app written
# with safe patterns. The only credential is the AWS documentation example key.
set -euo pipefail

# Write only into the eval run's empty workspace. Refuse anywhere else.
if [ "$PWD" = "/" ] || [ -n "$(ls -A .)" ]; then
  echo "refusing to scaffold: run this from an empty eval workspace" >&2
  exit 1
fi

mkdir -p app/templates tests

cat > requirements.txt <<'EOF'
Flask==3.1.2
Flask-WTF==1.2.2
Werkzeug==3.1.4
gunicorn==23.0.0
EOF

cat > app/__init__.py <<'EOF'
import os

from flask import Flask
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    csrf.init_app(app)

    from .routes import bp
    app.register_blueprint(bp)
    return app
EOF

cat > app/db.py <<'EOF'
import sqlite3

from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config.get("DATABASE", "notes.db"))
        g.db.row_factory = sqlite3.Row
    return g.db


def notes_for(user_id):
    return get_db().execute(
        "SELECT id, title, body FROM notes WHERE owner_id = ? ORDER BY id DESC",
        (user_id,),
    ).fetchall()


def add_note(user_id, title, body):
    db = get_db()
    db.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (user_id, title, body),
    )
    db.commit()


def find_user(email):
    return get_db().execute(
        "SELECT id, password_hash FROM users WHERE email = ?", (email,)
    ).fetchone()
EOF

cat > app/routes.py <<'EOF'
import subprocess

from flask import Blueprint, abort, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from . import db

bp = Blueprint("notes", __name__)


@bp.post("/login")
def login():
    user = db.find_user(request.form.get("email", ""))
    if user is None or not check_password_hash(user["password_hash"], request.form.get("password", "")):
        abort(401)
    session.clear()
    session["user_id"] = user["id"]
    return redirect(url_for("notes.index"))


@bp.get("/")
def index():
    user_id = session.get("user_id")
    if user_id is None:
        return redirect(url_for("notes.login_form"))
    return render_template("index.html", notes=db.notes_for(user_id))


@bp.get("/login")
def login_form():
    return render_template("login.html")


@bp.post("/notes")
def create():
    user_id = session.get("user_id")
    if user_id is None:
        abort(401)
    title = request.form.get("title", "")[:200]
    body = request.form.get("body", "")[:5000]
    db.add_note(user_id, title, body)
    return redirect(url_for("notes.index"))


@bp.get("/healthz")
def health():
    out = subprocess.run(["uptime"], capture_output=True, text=True, timeout=5, check=False)
    return {"ok": out.returncode == 0}
EOF

cat > app/templates/index.html <<'EOF'
<!doctype html>
<title>Notes</title>
<form method="post" action="/notes">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="title"><textarea name="body"></textarea><button>Save</button>
</form>
{% for n in notes %}<article><h2>{{ n.title }}</h2><p>{{ n.body }}</p></article>{% endfor %}
EOF

cat > app/templates/login.html <<'EOF'
<!doctype html>
<title>Sign in</title>
<form method="post" action="/login">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="email" type="email"><input name="password" type="password"><button>Sign in</button>
</form>
EOF

cat > tests/test_config.py <<'EOF'
import os

# Dummy values for unit tests. AKIAIOSFODNN7EXAMPLE is the AWS documentation example key.
os.environ.setdefault("SECRET_KEY", "test-only-not-a-secret")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")

from app import create_app


def test_app_builds():
    app = create_app()
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
EOF

cat > README.md <<'EOF'
# notes

A tiny Flask notes service. Configure `SECRET_KEY` in the environment and run
`gunicorn 'app:create_app()'`.
EOF
