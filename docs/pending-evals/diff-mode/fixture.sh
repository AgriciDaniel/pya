#!/usr/bin/env bash
# Scaffold for the diff-mode eval case: a git repo where main holds an older
# command injection in app/legacy_export.py, and the feature branch's single
# commit adds a SQL injection in app/search.py. HEAD~1..HEAD and main...HEAD
# both show only the new commit.
set -euo pipefail

# Write only into the eval run's empty workspace. Refuse anywhere else.
if [ "$PWD" = "/" ] || [ -n "$(ls -A .)" ]; then
  echo "refusing to scaffold: run this from an empty eval workspace" >&2
  exit 1
fi

g() {
  git -c user.name="PYA Eval" -c user.email="eval@example.invalid" \
    -c commit.gpgsign=false -c init.defaultBranch=main \
    -c core.hooksPath=/dev/null "$@"
}

mkdir -p app

cat > requirements.txt <<'EOF'
Flask==3.1.2
EOF

cat > app/db.py <<'EOF'
import sqlite3

conn = sqlite3.connect("shop.db", check_same_thread=False)
EOF

cat > app/legacy_export.py <<'EOF'
import os

from flask import Blueprint, request

bp = Blueprint("legacy_export", __name__)


@bp.post("/export")
def export_report():
    name = request.form["name"]
    os.system("tar czf /srv/exports/" + name + ".tgz /srv/reports")
    return {"ok": True}
EOF

cat > app/__init__.py <<'EOF'
from flask import Flask


def create_app():
    app = Flask(__name__)
    from .legacy_export import bp as export_bp
    app.register_blueprint(export_bp)
    return app
EOF

g init -q --template=
g add -A
g commit -q -m "Initial shop service"

g checkout -q -b feature/order-search

cat > app/search.py <<'EOF'
from flask import Blueprint, jsonify, request

from .db import conn

bp = Blueprint("search", __name__)


@bp.get("/orders/search")
def search_orders():
    term = request.args.get("q", "")
    rows = conn.execute(
        f"SELECT id, customer, total FROM orders WHERE customer LIKE '%{term}%'"
    ).fetchall()
    return jsonify([dict(id=r[0], customer=r[1], total=r[2]) for r in rows])
EOF

cat > app/__init__.py <<'EOF'
from flask import Flask


def create_app():
    app = Flask(__name__)
    from .legacy_export import bp as export_bp
    from .search import bp as search_bp
    app.register_blueprint(export_bp)
    app.register_blueprint(search_bp)
    return app
EOF

g add -A
g commit -q -m "Add order search endpoint"
