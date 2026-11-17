"""
IoT Environmental Monitoring - Cloud Application
CE6100 - Edge and Cloud Computing

Runs on EC2 instances behind an Application Load Balancer,
managed by an Auto Scaling group.
"""

import os
import socket
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify, render_template
import psycopg2
from psycopg2.extras import RealDictCursor
from jinja2 import ChoiceLoader, FileSystemLoader

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

# Templates may live either in ./templates or beside app.py.
# Looking in both keeps the app working whichever layout the repo has.
app.jinja_loader = ChoiceLoader([
    FileSystemLoader(os.path.join(BASE_DIR, "templates")),
    FileSystemLoader(BASE_DIR),
])

DB_HOST = os.environ.get("DB_HOST", "10.0.3.183")
DB_NAME = os.environ.get("DB_NAME", "iotdb")
DB_USER = os.environ.get("DB_USER", "iotuser")
DB_PASS = os.environ.get("DB_PASS", "")
API_KEY = os.environ.get("API_KEY", "")

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


# ----------------------------------------------------------------------
# Health check (used by the ALB target group)
# ----------------------------------------------------------------------
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
def set_config():
    """Switch a device between naive and smart mode from the web UI."""
    data = request.get_json(silent=True) or request.form
    device_id = data.get("device_id", "esp32-01")
    mode = data.get("mode")

    if mode not in ("naive", "smart"):
        return jsonify(error="mode must be 'naive' or 'smart'"), 400

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO device_config (device_id, mode, updated_at)
                   VALUES (%s, %s, NOW())
                   ON CONFLICT (device_id)
                   DO UPDATE SET mode = EXCLUDED.mode, updated_at = NOW();""",
                (device_id, mode)
            )
    return jsonify(device_id=device_id, mode=mode), 200


@app.route("/api/stats")
def stats_api():
    try:
        return jsonify(_collect_stats()), 200
    except Exception as e:
        app.logger.error("db error: %s", e)
        return jsonify(error="database error"), 500


@app.route("/api/series")
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
def page_dashboard():
    try:
        s = _collect_stats()
    except Exception as e:
        app.logger.error("db error: %s", e)
        return render_template("error.html", message=str(e)), 500
    return render_template("index.html", s=s, server=SERVER_NAME_TAG)


@app.route("/readings")
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
def page_charts():
    hours = int(request.args.get("hours", 6))
    return render_template("charts.html", hours=hours,
                           threshold=ALERT_THRESHOLD, server=SERVER_NAME_TAG)


@app.route("/alerts")
def page_alerts():
    rows = query(
        """SELECT * FROM readings WHERE anomaly_flag = TRUE
           ORDER BY server_ts DESC LIMIT 200;"""
    )
    return render_template("alerts.html", rows=rows,
                           threshold=ALERT_THRESHOLD, server=SERVER_NAME_TAG)


@app.route("/control")
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
    return render_template("control.html", device_id=device_id, mode=mode,
                           updated_at=updated, server=SERVER_NAME_TAG)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
