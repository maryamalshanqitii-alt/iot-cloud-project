"""
IoT Environmental Monitoring - Cloud Application
CE6100 - Edge and Cloud Computing

Runs on EC2 instances behind an Application Load Balancer,
managed by an Auto Scaling group.
"""

import os
import secrets
import socket
from datetime import datetime, timezone, timedelta

from functools import wraps

from flask import (Flask, request, jsonify, render_template, session,
                   redirect, url_for, abort)
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import RealDictCursor
from jinja2 import ChoiceLoader, FileSystemLoader

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

# Templates may live either in ./templates or beside app.py.
# Looking in both keeps the app working whichever layout the repo has.
def _load_secret_key():
    """
    The session secret is kept in the database so that every instance the
    Auto Scaling group launches signs sessions with the same key. Without
    this, scaling out would silently log everybody out.
    """
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""CREATE TABLE IF NOT EXISTS app_settings (
                                 key   TEXT PRIMARY KEY,
                                 value TEXT NOT NULL);""")
                cur.execute("""INSERT INTO app_settings (key, value)
                               VALUES ('secret_key', %s)
                               ON CONFLICT (key) DO NOTHING;""",
                            (secrets.token_hex(32),))
                cur.execute("SELECT value FROM app_settings WHERE key = 'secret_key';")
                return cur.fetchone()[0]
    except Exception:
        # Last resort: the app still runs, sessions just reset on restart.
        return secrets.token_hex(32)


app.permanent_session_lifetime = timedelta(hours=8)

app.jinja_loader = ChoiceLoader([
    FileSystemLoader(os.path.join(BASE_DIR, "templates")),
    FileSystemLoader(BASE_DIR),
])

DB_HOST = os.environ.get("DB_HOST", "10.0.3.183")
DB_NAME = os.environ.get("DB_NAME", "iotdb")
DB_USER = os.environ.get("DB_USER", "iotuser")
DB_PASS = os.environ.get("DB_PASS", "")
API_KEY = os.environ.get("API_KEY", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")

ALERT_THRESHOLD = float(os.environ.get("ALERT_THRESHOLD", "32.0"))
SERVER_NAME_TAG = socket.gethostname()


def get_conn():
    return psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME,
        user=DB_USER, password=DB_PASS, connect_timeout=5
    )


def query(sql, params=None, one=False):
    with get_conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params or ())
            return cur.fetchone() if one else cur.fetchall()


app.secret_key = _load_secret_key()


# ----------------------------------------------------------------------
# Health check (used by the ALB target group)
# ----------------------------------------------------------------------

# ======================= AUTHENTICATION =======================

def audit(action, detail=None, username=None):
    """Write one line to the audit trail. Never breaks the request."""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO audit_log (username, action, detail, ip_address)
                       VALUES (%s, %s, %s, %s);""",
                    (username or session.get("username"), action, detail,
                     request.headers.get("X-Forwarded-For", request.remote_addr))
                )
    except Exception:
        pass


def current_user():
    if "username" not in session:
        return None
    return {"username": session["username"], "role": session.get("role", "viewer")}


@app.context_processor
def inject_user():
    """Makes `user` available inside every template."""
    return {"user": current_user()}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    """Authorisation: only an admin may pass."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login", next=request.path))
        if user["role"] != "admin":
            audit("access_denied", request.path)
            if request.path.startswith("/api/"):
                return jsonify(error="admin role required"), 403
            return render_template("forbidden.html"), 403
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if current_user():
            return redirect(url_for("page_dashboard"))
        return render_template("login.html", error=None)

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not username or not password:
        return render_template("login.html",
                               error="Enter both a username and a password."), 400

    try:
        row = query("SELECT * FROM users WHERE username = %s;", (username,), one=True)
    except Exception as e:
        return render_template("login.html", error=f"Database error: {e}"), 500

    if not row or not check_password_hash(row["password_hash"], password):
        audit("login_failed", username, username=username)
        return render_template("login.html",
                               error="Wrong username or password."), 401

    session.permanent = True
    session["username"] = row["username"]
    session["role"] = row["role"]

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET last_login = NOW() WHERE id = %s;",
                            (row["id"],))
    except Exception:
        pass

    audit("login_success", f"role={row['role']}")
    nxt = request.args.get("next") or url_for("page_dashboard")
    return redirect(nxt)


@app.route("/logout")
def logout():
    audit("logout")
    session.clear()
    return redirect(url_for("login"))



@app.route("/account", methods=["GET", "POST"])
@login_required
def page_account():
    """Any signed-in user can change their own password here."""
    user = current_user()
    message, ok = None, False

    if request.method == "POST":
        old = request.form.get("current_password") or ""
        new = request.form.get("new_password") or ""
        confirm = request.form.get("confirm_password") or ""

        row = query("SELECT * FROM users WHERE username = %s;",
                    (user["username"],), one=True)

        if not row or not check_password_hash(row["password_hash"], old):
            message = "The current password is not correct."
            audit("password_change_failed")
        elif len(new) < 8:
            message = "The new password must be at least 8 characters."
        elif new != confirm:
            message = "The two new passwords do not match."
        elif new == old:
            message = "The new password must be different from the old one."
        else:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE users SET password_hash = %s WHERE id = %s;",
                                (generate_password_hash(new), row["id"]))
            audit("password_changed")
            message, ok = "Your password has been changed.", True

    return render_template("account.html", message=message, ok=ok,
                           server=SERVER_NAME_TAG)


@app.route("/users")
@admin_required
def page_users():
    rows = query("SELECT username, role, created_at, last_login "
                 "FROM users ORDER BY username;")
    logs = query("SELECT username, action, detail, ip_address, created_at "
                 "FROM audit_log ORDER BY created_at DESC LIMIT 30;")
    return render_template("users.html", users=rows, logs=logs,
                           server=SERVER_NAME_TAG, message=None)


@app.route("/users/add", methods=["POST"])
@admin_required
def add_user():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    role     = request.form.get("role") or "viewer"

    message = None
    if len(username) < 3:
        message = "Username must be at least 3 characters."
    elif len(password) < 8:
        message = "Password must be at least 8 characters."
    elif role not in ("admin", "viewer"):
        message = "Role must be admin or viewer."

    if message is None:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """INSERT INTO users (username, password_hash, role)
                           VALUES (%s, %s, %s);""",
                        (username, generate_password_hash(password), role))
            audit("user_created", f"{username} as {role}")
            message = f"User {username} created as {role}."
        except psycopg2.errors.UniqueViolation:
            message = f"User {username} already exists."
        except Exception as e:
            message = f"Could not create the user: {e}"

    rows = query("SELECT username, role, created_at, last_login "
                 "FROM users ORDER BY username;")
    logs = query("SELECT username, action, detail, ip_address, created_at "
                 "FROM audit_log ORDER BY created_at DESC LIMIT 30;")
    return render_template("users.html", users=rows, logs=logs,
                           server=SERVER_NAME_TAG, message=message)


@app.route("/users/delete", methods=["POST"])
@admin_required
def delete_user():
    username = request.form.get("username") or ""
    if username == session.get("username"):
        message = "You cannot delete the account you are signed in with."
    else:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM users WHERE username = %s;", (username,))
            audit("user_deleted", username)
            message = f"User {username} deleted."
        except Exception as e:
            message = f"Could not delete the user: {e}"

    rows = query("SELECT username, role, created_at, last_login "
                 "FROM users ORDER BY username;")
    logs = query("SELECT username, action, detail, ip_address, created_at "
                 "FROM audit_log ORDER BY created_at DESC LIMIT 30;")
    return render_template("users.html", users=rows, logs=logs,
                           server=SERVER_NAME_TAG, message=message)


@app.route("/health")
def health():
    return jsonify(status="ok", server=SERVER_NAME_TAG), 200


# ----------------------------------------------------------------------
# API
# ----------------------------------------------------------------------
@app.route("/api/readings", methods=["POST"])
def add_reading():
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify(error="unauthorized"), 401

    data = request.get_json(silent=True) or {}

    required = ["device_id", "temperature", "humidity", "mode"]
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify(error="missing fields", fields=missing), 400

    try:
        temperature = float(data["temperature"])
        humidity = float(data["humidity"])
    except (TypeError, ValueError):
        return jsonify(error="temperature and humidity must be numbers"), 400

    server_ts = datetime.now(timezone.utc)

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO readings
                       (device_id, temperature, humidity, mode, anomaly_flag, device_ts, server_ts)
                       VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id;""",
                    (data["device_id"], temperature, humidity, data["mode"],
                     bool(data.get("anomaly_flag", False)),
                     data.get("device_ts"), server_ts)
                )
                new_id = cur.fetchone()[0]
    except Exception as e:
        app.logger.error("db error: %s", e)
        return jsonify(error="database error"), 500

    return jsonify(id=new_id, server_ts=server_ts.isoformat(), server=SERVER_NAME_TAG), 201


@app.route("/api/readings", methods=["GET"])
@login_required
def list_readings_api():
    limit = min(int(request.args.get("limit", 50)), 500)
    try:
        rows = query(
            "SELECT * FROM readings ORDER BY server_ts DESC LIMIT %s;", (limit,)
        )
        return jsonify(rows), 200
    except Exception as e:
        app.logger.error("db error: %s", e)
        return jsonify(error="database error"), 500


@app.route("/api/config", methods=["GET"])
def get_config():
    """The edge device polls this to learn which mode it should run in."""
    device_id = request.args.get("device_id", "esp32-01")
    row = query(
        "SELECT mode, updated_at FROM device_config WHERE device_id = %s;",
        (device_id,), one=True
    )
    if not row:
        return jsonify(device_id=device_id, mode="naive"), 200
    return jsonify(
        device_id=device_id,
        mode=row["mode"],
        updated_at=row["updated_at"].isoformat(),
    ), 200


@app.route("/api/config", methods=["POST"])
@admin_required
def set_config():
    """Switch a device between naive and smart mode from the web UI."""
    data = request.get_json(silent=True) or request.form
    device_id = data.get("device_id", "esp32-01")
    mode = data.get("mode")

    if mode not in ("naive", "smart", "adaptive"):
        return jsonify(error="mode must be 'naive', 'smart' or 'adaptive'"), 400

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO device_config (device_id, mode, updated_at)
                   VALUES (%s, %s, NOW())
                   ON CONFLICT (device_id)
                   DO UPDATE SET mode = EXCLUDED.mode, updated_at = NOW();""",
                (device_id, mode)
            )
    audit("mode_changed", f"{device_id} -> {mode}")
    return jsonify(device_id=device_id, mode=mode), 200



@app.route("/api/decision", methods=["POST"])
def add_decision():
    """
    Called by the device whenever its adaptive policy changes behaviour.
    Machine-to-machine, so it authenticates with the API key, not a session.
    """
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify(error="unauthorized"), 401

    d = request.get_json(silent=True) or {}
    decision = d.get("decision")
    if decision not in ("naive", "smart"):
        return jsonify(error="decision must be 'naive' or 'smart'"), 400

    device_ts = d.get("device_ts")
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO adaptive_decisions
                         (device_id, decision, reason, rtt_ms, fail_pct,
                          rssi_dbm, free_heap, device_ts)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s);""",
                    (d.get("device_id", "esp32-01"), decision,
                     d.get("reason", "")[:200], d.get("rtt_ms"),
                     d.get("fail_pct"), d.get("rssi_dbm"),
                     d.get("free_heap"), device_ts))
    except Exception as e:
        return jsonify(error=str(e)), 500

    return jsonify(status="recorded", decision=decision), 201


@app.route("/api/decisions", methods=["GET"])
@login_required
def list_decisions():
    rows = query("""SELECT * FROM adaptive_decisions
                    ORDER BY server_ts DESC LIMIT 100;""")
    return jsonify([{
        "device_id": r["device_id"], "decision": r["decision"],
        "reason": r["reason"], "rtt_ms": r["rtt_ms"],
        "fail_pct": r["fail_pct"], "rssi_dbm": r["rssi_dbm"],
        "server_ts": r["server_ts"].isoformat(),
    } for r in rows])


@app.route("/api/stats")
@login_required
def stats_api():
    try:
        return jsonify(_collect_stats()), 200
    except Exception as e:
        app.logger.error("db error: %s", e)
        return jsonify(error="database error"), 500


@app.route("/api/series")
@login_required
def series_api():
    """Time series for the charts page."""
    hours = int(request.args.get("hours", 6))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = query(
        """SELECT server_ts, temperature, humidity, mode
           FROM readings WHERE server_ts >= %s
           ORDER BY server_ts ASC;""", (since,)
    )
    return jsonify([
        {
            "t": r["server_ts"].isoformat(),
            "temperature": r["temperature"],
            "humidity": r["humidity"],
            "mode": r["mode"],
        } for r in rows
    ])


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _collect_stats():
    latest = query(
        "SELECT * FROM readings ORDER BY server_ts DESC LIMIT 1;", one=True
    )

    totals = query(
        """SELECT
             COUNT(*) AS total,
             COUNT(*) FILTER (WHERE mode = 'naive') AS naive_count,
             COUNT(*) FILTER (WHERE mode = 'smart') AS smart_count,
             COUNT(*) FILTER (WHERE anomaly_flag) AS anomalies,
             ROUND(AVG(temperature)::numeric, 2) AS avg_temp,
             ROUND(MAX(temperature)::numeric, 2) AS max_temp,
             ROUND(AVG(humidity)::numeric, 2) AS avg_hum
           FROM readings;""", one=True
    )

    devices = query(
        """SELECT device_id, COUNT(*) AS readings,
                  MAX(server_ts) AS last_seen
           FROM readings GROUP BY device_id ORDER BY device_id;"""
    )

    online = False
    last_seen = None
    if latest and latest.get("server_ts"):
        last_seen = latest["server_ts"]
        online = (datetime.now(timezone.utc) - last_seen) < timedelta(minutes=2)

    return {
        "latest": latest,
        "totals": totals,
        "devices": devices,
        "online": online,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "threshold": ALERT_THRESHOLD,
        "server": SERVER_NAME_TAG,
    }


# ----------------------------------------------------------------------
# Web pages
# ----------------------------------------------------------------------
@app.route("/")
@login_required
def page_dashboard():
    try:
        s = _collect_stats()
    except Exception as e:
        app.logger.error("db error: %s", e)
        return render_template("error.html", message=str(e)), 500
    return render_template("index.html", s=s, server=SERVER_NAME_TAG)


@app.route("/readings")
@login_required
def page_readings():
    mode = request.args.get("mode", "all")
    limit = min(int(request.args.get("limit", 100)), 1000)

    if mode in ("naive", "smart"):
        rows = query(
            "SELECT * FROM readings WHERE mode = %s ORDER BY server_ts DESC LIMIT %s;",
            (mode, limit)
        )
    else:
        rows = query(
            "SELECT * FROM readings ORDER BY server_ts DESC LIMIT %s;", (limit,)
        )

    return render_template("readings.html", rows=rows, mode=mode,
                           limit=limit, server=SERVER_NAME_TAG)


@app.route("/charts")
@login_required
def page_charts():
    hours = int(request.args.get("hours", 6))
    return render_template("charts.html", hours=hours,
                           threshold=ALERT_THRESHOLD, server=SERVER_NAME_TAG)


@app.route("/alerts")
@login_required
def page_alerts():
    rows = query(
        """SELECT * FROM readings WHERE anomaly_flag = TRUE
           ORDER BY server_ts DESC LIMIT 200;"""
    )
    return render_template("alerts.html", rows=rows,
                           threshold=ALERT_THRESHOLD, server=SERVER_NAME_TAG)


@app.route("/control")
@admin_required
def page_control():
    device_id = request.args.get("device_id", "esp32-01")
    try:
        row = query(
            "SELECT mode, updated_at FROM device_config WHERE device_id = %s;",
            (device_id,), one=True
        )
    except Exception as e:
        return render_template("error.html", message=str(e)), 500

    mode = row["mode"] if row else "naive"
    updated = row["updated_at"].strftime("%Y-%m-%d %H:%M:%S") if row else None

    try:
        decisions = query("""SELECT * FROM adaptive_decisions
                             WHERE device_id = %s
                             ORDER BY server_ts DESC LIMIT 15;""", (device_id,))
    except Exception:
        decisions = []

    return render_template("control.html", device_id=device_id, mode=mode,
                           updated_at=updated, decisions=decisions,
                           server=SERVER_NAME_TAG)


@app.route("/readings.csv")
@login_required
def export_csv():
    """Download every reading as CSV - used for the offline analysis."""
    rows = query("""SELECT device_id, temperature, humidity, mode, anomaly_flag,
                           device_ts, server_ts
                    FROM readings ORDER BY server_ts;""")
    lines = ["device_id,temperature,humidity,mode,anomaly_flag,device_ts,server_ts"]
    for r in rows:
        lines.append(",".join([
            str(r["device_id"]), str(r["temperature"]), str(r["humidity"]),
            str(r["mode"]), str(r["anomaly_flag"]),
            r["device_ts"].isoformat() if r["device_ts"] else "",
            r["server_ts"].isoformat() if r["server_ts"] else "",
        ]))
    audit("export_csv", f"{len(rows)} rows")
    return ("\n".join(lines), 200, {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": "attachment; filename=readings.csv",
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
