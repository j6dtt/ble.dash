import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

import json
import os
import queue
import socket
import sqlite3
import threading
from flask import Flask, Response, jsonify, render_template, request
import comlibv3

UDP_HOST = "0.0.0.0"
UDP_PORT = int(os.environ.get("UDP_PORT", 9002))
HTTP_PORT = int(os.environ.get("HTTP_PORT", 8080))
DB_PATH = os.environ.get("DB_PATH", "tracks.db")

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()


def init_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    if os.path.exists(DB_PATH):
        logging.info("Using existing database at %s", DB_PATH)
    else:
        logging.info("No database found at %s, creating new one", DB_PATH)
    with sqlite3.connect(DB_PATH) as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("""
            CREATE TABLE IF NOT EXISTS observations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid        TEXT NOT NULL,
                name        TEXT,
                lat         REAL NOT NULL,
                lon         REAL NOT NULL,
                obs_time    TEXT,
                ingest_time TEXT,
                accuracy    INTEGER,
                confidence  INTEGER,
                device_id   TEXT,
                received_at TEXT DEFAULT (datetime('now'))
            )
        """)
        con.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_uuid_obs_time
            ON observations(uuid, obs_time)
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_uuid ON observations(uuid)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS device_meta (
                uuid        TEXT PRIMARY KEY,
                archived    INTEGER NOT NULL DEFAULT 0,
                archived_at TEXT
            )
        """)
        con.commit()


def get_archived_uuids() -> set:
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute("SELECT uuid FROM device_meta WHERE archived = 1").fetchall()
    return {r[0] for r in rows}


def store_observations(records: list[dict]) -> list[dict]:
    stored = []
    with sqlite3.connect(DB_PATH) as con:
        con.execute("PRAGMA journal_mode=WAL")
        for rec in records:
            try:
                lat = float(rec.get("lat", 0))
                lon = float(rec.get("lon", 0))
            except (ValueError, TypeError):
                continue
            row = {
                "uuid":        rec.get("uuid", "unknown"),
                "name":        rec.get("name", "unknown"),
                "lat":         lat,
                "lon":         lon,
                "obs_time":    rec.get("timestamp"),
                "ingest_time": rec.get("ingest_time"),
                "accuracy":    int(rec.get("accuracy") or 0),
                "confidence":  int(rec.get("confidence") or 0),
                "device_id":   rec.get("id"),
            }
            cur = con.execute("""
                INSERT OR IGNORE INTO observations
                    (uuid, name, lat, lon, obs_time, ingest_time, accuracy, confidence, device_id)
                VALUES
                    (:uuid, :name, :lat, :lon, :obs_time, :ingest_time, :accuracy, :confidence, :device_id)
            """, row)
            if cur.rowcount:
                stored.append(row)
        con.commit()
    return stored


def notify_sse(obs_list: list[dict]):
    if not obs_list:
        return
    payload = json.dumps(obs_list)
    with _sse_lock:
        dead = [q for q in _sse_clients if not _try_put(q, payload)]
        for q in dead:
            _sse_clients.remove(q)


def _try_put(q: queue.Queue, payload: str) -> bool:
    try:
        q.put_nowait(payload)
        return True
    except queue.Full:
        return False


def udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_HOST, UDP_PORT))
    logging.info("UDP listener on %s:%d", UDP_HOST, UDP_PORT)
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            text = data.decode("utf-8", errors="replace")
            records = comlibv3.parse_data_cef(text)
            if records:
                stored = store_observations(records)
                if stored:
                    # Archived devices are still recorded (in case they're
                    # unarchived later) but shouldn't reappear live on the map.
                    archived = get_archived_uuids()
                    notify_sse([r for r in stored if r["uuid"] not in archived])
                logging.info("Stored %d/%d record(s) from %s", len(stored), len(records), addr)
        except Exception:
            logging.exception("UDP recv error")


# --- Flask routes ---

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def api_devices():
    want_archived = request.args.get("archived") == "1"
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""
            SELECT o.uuid, o.name, o.lat, o.lon, o.obs_time AS last_seen,
                   o.accuracy, o.confidence, cnt.fix_count, m.archived_at
            FROM observations o
            INNER JOIN (
                SELECT uuid, MAX(obs_time) AS max_time FROM observations GROUP BY uuid
            ) latest ON o.uuid = latest.uuid AND o.obs_time = latest.max_time
            INNER JOIN (
                SELECT uuid, COUNT(*) AS fix_count FROM observations GROUP BY uuid
            ) cnt ON o.uuid = cnt.uuid
            LEFT JOIN device_meta m ON m.uuid = o.uuid
            WHERE COALESCE(m.archived, 0) = ?
            ORDER BY last_seen DESC
        """, (1 if want_archived else 0,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/devices/<uuid>/archive", methods=["POST"])
def archive_device(uuid):
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            INSERT INTO device_meta (uuid, archived, archived_at)
            VALUES (?, 1, datetime('now'))
            ON CONFLICT(uuid) DO UPDATE SET archived = 1, archived_at = datetime('now')
        """, (uuid,))
        con.commit()
    return jsonify({"uuid": uuid, "archived": True})


@app.route("/api/devices/<uuid>/unarchive", methods=["POST"])
def unarchive_device(uuid):
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            INSERT INTO device_meta (uuid, archived, archived_at)
            VALUES (?, 0, NULL)
            ON CONFLICT(uuid) DO UPDATE SET archived = 0, archived_at = NULL
        """, (uuid,))
        con.commit()
    return jsonify({"uuid": uuid, "archived": False})


@app.route("/api/tracks")
def api_tracks():
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""
            SELECT o.uuid, o.name, o.lat, o.lon, o.obs_time, o.ingest_time, o.accuracy, o.confidence
            FROM observations o
            LEFT JOIN device_meta m ON m.uuid = o.uuid
            WHERE COALESCE(m.archived, 0) = 0
            ORDER BY o.uuid, o.obs_time
        """).fetchall()
    tracks: dict = {}
    for r in rows:
        d = dict(r)
        uid = d["uuid"]
        if uid not in tracks:
            tracks[uid] = {"uuid": uid, "name": d["name"], "points": []}
        tracks[uid]["points"].append({
            "lat": d["lat"], "lon": d["lon"],
            "timestamp": d["obs_time"],
            "ingest_time": d["ingest_time"],
            "accuracy": d["accuracy"],
            "confidence": d["confidence"],
        })
    return jsonify(list(tracks.values()))


@app.route("/stream")
def stream():
    q: queue.Queue = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_clients.append(q)

    def generate():
        try:
            while True:
                try:
                    payload = q.get(timeout=25)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    yield ":\n\n"  # keepalive
        finally:
            with _sse_lock:
                try:
                    _sse_clients.remove(q)
                except ValueError:
                    pass

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


init_db()
threading.Thread(target=udp_listener, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=HTTP_PORT, threaded=True)
