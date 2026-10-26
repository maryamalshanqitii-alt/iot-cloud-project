import os
from datetime import datetime, timezone
from flask import Flask, request, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

DB_HOST = os.environ.get("DB_HOST", "10.0.3.183")
DB_NAME = os.environ.get("DB_NAME", "iotdb")
DB_USER = os.environ.get("DB_USER", "iotuser")
DB_PASS = os.environ.get("DB_PASS", "")
API_KEY = os.environ.get("API_KEY", "")

def get_conn():
    return psycopg2.connect(
        host=DB_HOST, dbname=DB_NAME,
        user=DB_USER, password=DB_PASS, connect_timeout=5
    )

@app.route("/health")
def health():
    return jsonify(status="ok"), 200

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

    return jsonify(id=new_id, server_ts=server_ts.isoformat()), 201

@app.route("/api/readings", methods=["GET"])
def list_readings():
    try:
        with get_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM readings ORDER BY server_ts DESC LIMIT 20;")
                rows = cur.fetchall()
        return jsonify(rows), 200
    except Exception as e:
        app.logger.error("db error: %s", e)
        return jsonify(error="database error"), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
