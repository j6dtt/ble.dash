import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

import json
import os
import queue
import re
import secrets
import socket
import sqlite3
import threading
import time
from datetime import timedelta, datetime, timezone
from functools import wraps
from flask import (
    Flask, Response, jsonify, render_template, request,
    session, redirect, url_for, abort,
)
from werkzeug.security import generate_password_hash, check_password_hash
import comlibv3

TCP_HOST = "0.0.0.0"
TCP_PORT = int(os.environ.get("TCP_PORT", 9002))
HTTP_PORT = int(os.environ.get("HTTP_PORT", 8080))
DB_PATH = os.environ.get("DB_PATH", "tracks.db")
BACKUP_DIR = os.path.join(os.path.dirname(DB_PATH) or ".", "backup")
AUDIT_LOG_RETENTION_DAYS = int(os.environ.get("AUDIT_LOG_RETENTION_DAYS", 90))


def _load_or_create_secret_key() -> str:
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    key_path = os.path.join(os.path.dirname(DB_PATH) or ".", "secret_key.txt")
    if os.path.exists(key_path):
        with open(key_path) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(key_path, "w") as f:
        f.write(key)
    os.chmod(key_path, 0o600)
    return key


app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.secret_key = _load_or_create_secret_key()
app.config.update(
    SESSION_COOKIE_SECURE=True,      # app is TLS-only already
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

_sse_clients: list[tuple] = []   # (queue.Queue, is_admin: bool, group_ids: frozenset[int])
_sse_lock = threading.Lock()


# --- Auth helpers ---

def _wants_json() -> bool:
    return request.path.startswith("/api/") or request.path == "/stream"


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if _wants_json():
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if _wants_json():
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login", next=request.path))
        if not session.get("is_admin"):
            if _wants_json():
                return jsonify({"error": "admin privileges required"}), 403
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def _visible_group_ids() -> list[int]:
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute(
            "SELECT group_id FROM user_groups WHERE user_id = ?", (session["user_id"],)
        ).fetchall()
    return [r[0] for r in rows]


_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def _valid_hex_color(s) -> bool:
    return isinstance(s, str) and bool(_HEX_COLOR_RE.match(s))


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
        existing_cols = {row[1] for row in con.execute("PRAGMA table_info(device_meta)")}
        if "notes" not in existing_cols:
            con.execute("ALTER TABLE device_meta ADD COLUMN notes TEXT")
        con.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin      INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT DEFAULT (datetime('now'))
            )
        """)
        existing_user_cols = {row[1] for row in con.execute("PRAGMA table_info(users)")}
        if "first_name" not in existing_user_cols:
            con.execute("ALTER TABLE users ADD COLUMN first_name TEXT")
        if "last_name" not in existing_user_cols:
            con.execute("ALTER TABLE users ADD COLUMN last_name TEXT")
        con.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id   INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        """)
        existing_group_cols = {row[1] for row in con.execute("PRAGMA table_info(groups)")}
        if "color" not in existing_group_cols:
            con.execute("ALTER TABLE groups ADD COLUMN color TEXT")
        con.execute("""
            CREATE TABLE IF NOT EXISTS group_codes (
                code     TEXT PRIMARY KEY,
                group_id INTEGER NOT NULL REFERENCES groups(id)
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS user_groups (
                user_id  INTEGER NOT NULL REFERENCES users(id),
                group_id INTEGER NOT NULL REFERENCES groups(id),
                PRIMARY KEY (user_id, group_id)
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        TEXT NOT NULL DEFAULT (datetime('now')),
                user_id   INTEGER,
                username  TEXT,
                action    TEXT NOT NULL,
                target    TEXT,
                detail    TEXT,
                ip        TEXT
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
        con.commit()


def bootstrap_admin():
    admin_user = os.environ.get("ADMIN_USER")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    with sqlite3.connect(DB_PATH) as con:
        existing = con.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
        if existing:
            return
        if not admin_user or not admin_password:
            logging.warning(
                "No admin user exists and ADMIN_USER/ADMIN_PASSWORD are not set — "
                "no one will be able to log in until an admin is created."
            )
            return
        con.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
            (admin_user, generate_password_hash(admin_password)),
        )
        con.commit()
        logging.info("Bootstrapped initial admin user %r", admin_user)


def get_archived_uuids() -> set:
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute("SELECT uuid FROM device_meta WHERE archived = 1").fetchall()
    return {r[0] for r in rows}


def get_setting(key: str, default=None):
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_setting(key: str, value: str):
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            INSERT INTO app_settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """, (key, value))
        con.commit()


def log_activity(action: str, target: str | None = None, detail: str | None = None,
                  username: str | None = None):
    """Records one audit_log row. Defaults to the current session's user/username
    (the common case — an authenticated action); pass `username` explicitly for
    pre-auth events like a failed login, where there is no session user yet."""
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            "INSERT INTO audit_log (user_id, username, action, target, detail, ip) VALUES (?, ?, ?, ?, ?, ?)",
            (session.get("user_id"), username or session.get("username"), action, target, detail,
             request.remote_addr),
        )
        con.commit()


def _prune_audit_log():
    """Deletes audit_log rows older than AUDIT_LOG_RETENTION_DAYS. Row-level
    security events are small individually, but the table has no other size
    bound, so this keeps it from growing forever on a long-running deployment."""
    with sqlite3.connect(DB_PATH) as con:
        cur = con.execute(
            "DELETE FROM audit_log WHERE ts < datetime('now', ?)",
            (f"-{AUDIT_LOG_RETENTION_DAYS} days",),
        )
        con.commit()
        if cur.rowcount:
            logging.info("Pruned %d audit_log row(s) older than %d days", cur.rowcount, AUDIT_LOG_RETENTION_DAYS)


def _audit_log_pruner():
    """Runs _prune_audit_log() immediately, then once every 24h for the life
    of the process — same daemon-thread pattern as tcp_listener()."""
    while True:
        try:
            _prune_audit_log()
        except Exception:
            logging.exception("Audit log pruning failed")
        time.sleep(24 * 60 * 60)


def device_notes_enabled() -> bool:
    return get_setting("device_notes_enabled", "0") == "1"


def _device_visible(uuid: str) -> bool:
    """True if the current session user is allowed to see/annotate this device
    (admin, or the device's derived group is one of the user's groups)."""
    if session.get("is_admin"):
        return True
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute("SELECT name FROM observations WHERE uuid = ? LIMIT 1", (uuid,)).fetchone()
    if not row:
        return False
    code_map = _code_to_group()
    gid = _device_group_id(row[0], code_map)
    return gid is not None and gid in set(_visible_group_ids())


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


def _code_to_group() -> dict[str, int]:
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute("SELECT code, group_id FROM group_codes").fetchall()
    return dict(rows)


def _device_group_id(name, code_map):
    if not name or len(name) < 2:
        return None
    return code_map.get(name[1])


def _group_colors() -> dict[int, str]:
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute("SELECT id, color FROM groups").fetchall()
    return dict(rows)


def notify_sse(obs_list: list[dict]):
    if not obs_list:
        return
    with _sse_lock:
        if not _sse_clients:
            return
        code_map = _code_to_group()
        colors = _group_colors()
        # Stamp group_id/group_color onto each observation once, up front —
        # matches what /api/devices and /api/tracks already derive, so a
        # device first seen via a live push (rather than the initial page
        # load) still renders with the right color instead of falling back
        # to "Unassigned" gray on the client.
        for o in obs_list:
            gid = _device_group_id(o.get("name"), code_map)
            o["group_id"] = gid
            o["group_color"] = colors.get(gid)
        dead = []
        for client in _sse_clients:
            q, is_admin, group_ids = client
            visible = obs_list if is_admin else [o for o in obs_list if o["group_id"] in group_ids]
            if not visible:
                continue
            if not _try_put(q, json.dumps(visible)):
                dead.append(client)
        for client in dead:
            _sse_clients.remove(client)


def _try_put(q: queue.Queue, payload: str) -> bool:
    try:
        q.put_nowait(payload)
        return True
    except queue.Full:
        return False


def _handle_tcp_connection(conn: socket.socket, addr):
    try:
        conn.settimeout(10)
        chunks = []
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break  # peer closed = EOF = end of this batch
            chunks.append(chunk)
        data = b"".join(chunks)
        if not data:
            return
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
    except socket.timeout:
        logging.error("TCP recv timeout from %s", addr)
    except Exception:
        logging.exception("TCP connection error from %s", addr)
    finally:
        conn.close()


def tcp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((TCP_HOST, TCP_PORT))
    sock.listen(5)
    logging.info("TCP listener on %s:%d", TCP_HOST, TCP_PORT)
    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=_handle_tcp_connection, args=(conn, addr), daemon=True).start()
        except Exception:
            logging.exception("TCP accept error")


# --- Flask routes ---

@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("user_id"):
            return redirect(url_for("index"))
        return render_template("login.html", error=None, next=request.args.get("next", ""))

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        user = con.execute(
            "SELECT id, password_hash, is_admin FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not user or not check_password_hash(user["password_hash"], password):
        log_activity("login_failed", target=username, username=username)
        return render_template("login.html", error="Invalid username or password",
                                next=request.form.get("next", "")), 401

    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["username"] = username
    session["is_admin"] = bool(user["is_admin"])
    log_activity("login")

    next_url = request.form.get("next") or ""
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = url_for("index")
    return redirect(next_url)


@app.route("/logout", methods=["POST"])
def logout():
    if session.get("user_id"):
        log_activity("logout")
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
@login_required
def api_me():
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        user = con.execute(
            "SELECT first_name, last_name FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        groups = con.execute("""
            SELECT g.id, g.name
            FROM user_groups ug JOIN groups g ON g.id = ug.group_id
            WHERE ug.user_id = ?
            ORDER BY g.name
        """, (session["user_id"],)).fetchall()
    return jsonify({
        "username": session["username"],
        "is_admin": bool(session["is_admin"]),
        "first_name": user["first_name"] if user else None,
        "last_name": user["last_name"] if user else None,
        "groups": [dict(g) for g in groups],
    })


@app.route("/api/settings")
@login_required
def api_settings():
    return jsonify({"device_notes_enabled": device_notes_enabled()})


@app.route("/api/admin/settings", methods=["PATCH"])
@admin_required
def admin_update_settings():
    data = request.get_json(force=True, silent=True) or {}
    if "device_notes_enabled" in data:
        set_setting("device_notes_enabled", "1" if data["device_notes_enabled"] else "0")
        log_activity("settings.update", target="device_notes_enabled",
                     detail=str(bool(data["device_notes_enabled"])))
    return jsonify({"device_notes_enabled": device_notes_enabled()})


@app.route("/api/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json(force=True, silent=True) or {}
    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""
    if not new_password:
        return jsonify({"error": "new password is required"}), 400

    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        user = con.execute(
            "SELECT password_hash FROM users WHERE id = ?", (session["user_id"],)
        ).fetchone()
        if not user or not check_password_hash(user["password_hash"], current_password):
            return jsonify({"error": "current password is incorrect"}), 400
        con.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), session["user_id"]),
        )
        con.commit()
    log_activity("password_change")
    return jsonify({"ok": True})


@app.route("/api/devices/<uuid>/notes", methods=["POST"])
@login_required
def update_device_notes(uuid):
    if not device_notes_enabled():
        return jsonify({"error": "device notes are disabled"}), 403
    if not _device_visible(uuid):
        return jsonify({"error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    notes = (data.get("notes") or "").strip()
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            INSERT INTO device_meta (uuid, notes) VALUES (?, ?)
            ON CONFLICT(uuid) DO UPDATE SET notes = excluded.notes
        """, (uuid, notes))
        con.commit()
    return jsonify({"uuid": uuid, "notes": notes})


@app.route("/api/devices")
@login_required
def api_devices():
    want_archived = request.args.get("archived") == "1"
    is_admin = bool(session.get("is_admin"))
    visible_group_ids = None if is_admin else _visible_group_ids()

    query = """
        SELECT o.uuid, o.name, o.lat, o.lon, o.obs_time AS last_seen,
               o.accuracy, o.confidence, cnt.fix_count, m.archived_at, m.notes,
               g.id AS group_id, COALESCE(g.name, 'Unassigned') AS group_name, g.color AS group_color
        FROM observations o
        INNER JOIN (
            SELECT uuid, MAX(obs_time) AS max_time FROM observations GROUP BY uuid
        ) latest ON o.uuid = latest.uuid AND o.obs_time = latest.max_time
        INNER JOIN (
            SELECT uuid, COUNT(*) AS fix_count FROM observations GROUP BY uuid
        ) cnt ON o.uuid = cnt.uuid
        LEFT JOIN device_meta m ON m.uuid = o.uuid
        LEFT JOIN group_codes gc ON gc.code = substr(o.name, 2, 1)
        LEFT JOIN groups g ON g.id = gc.group_id
        WHERE COALESCE(m.archived, 0) = ?
    """
    params = [1 if want_archived else 0]
    if visible_group_ids is not None:
        if visible_group_ids:
            placeholders = ",".join("?" * len(visible_group_ids))
            query += f" AND g.id IN ({placeholders})"
            params.extend(visible_group_ids)
        else:
            query += " AND 0=1"   # member in zero groups sees nothing
    query += " ORDER BY last_seen DESC"

    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/devices/<uuid>/archive", methods=["POST"])
@admin_required
def archive_device(uuid):
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            INSERT INTO device_meta (uuid, archived, archived_at)
            VALUES (?, 1, datetime('now'))
            ON CONFLICT(uuid) DO UPDATE SET archived = 1, archived_at = datetime('now')
        """, (uuid,))
        con.commit()
    log_activity("device.archive", target=uuid)
    return jsonify({"uuid": uuid, "archived": True})


@app.route("/api/devices/<uuid>/unarchive", methods=["POST"])
@admin_required
def unarchive_device(uuid):
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            INSERT INTO device_meta (uuid, archived, archived_at)
            VALUES (?, 0, NULL)
            ON CONFLICT(uuid) DO UPDATE SET archived = 0, archived_at = NULL
        """, (uuid,))
        con.commit()
    log_activity("device.unarchive", target=uuid)
    return jsonify({"uuid": uuid, "archived": False})


@app.route("/api/tracks")
@login_required
def api_tracks():
    is_admin = bool(session.get("is_admin"))
    visible_group_ids = None if is_admin else _visible_group_ids()

    query = """
        SELECT o.uuid, o.name, o.lat, o.lon, o.obs_time, o.ingest_time, o.accuracy, o.confidence,
               g.id AS group_id, g.color AS group_color
        FROM observations o
        LEFT JOIN device_meta m ON m.uuid = o.uuid
        LEFT JOIN group_codes gc ON gc.code = substr(o.name, 2, 1)
        LEFT JOIN groups g ON g.id = gc.group_id
        WHERE COALESCE(m.archived, 0) = 0
    """
    params = []
    if visible_group_ids is not None:
        if visible_group_ids:
            placeholders = ",".join("?" * len(visible_group_ids))
            query += f" AND g.id IN ({placeholders})"
            params.extend(visible_group_ids)
        else:
            query += " AND 0=1"
    query += " ORDER BY o.uuid, o.obs_time"

    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(query, params).fetchall()

    tracks: dict = {}
    for r in rows:
        d = dict(r)
        uid = d["uuid"]
        if uid not in tracks:
            tracks[uid] = {
                "uuid": uid, "name": d["name"], "points": [],
                "group_id": d["group_id"], "group_color": d["group_color"],
            }
        tracks[uid]["points"].append({
            "lat": d["lat"], "lon": d["lon"],
            "timestamp": d["obs_time"],
            "ingest_time": d["ingest_time"],
            "accuracy": d["accuracy"],
            "confidence": d["confidence"],
        })
    return jsonify(list(tracks.values()))


@app.route("/stream")
@login_required
def stream():
    is_admin = bool(session.get("is_admin"))
    group_ids = frozenset() if is_admin else frozenset(_visible_group_ids())

    q: queue.Queue = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_clients.append((q, is_admin, group_ids))

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
                _sse_clients[:] = [c for c in _sse_clients if c[0] is not q]

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# --- Admin routes ---

@app.route("/admin")
@admin_required
def admin_page():
    return render_template("admin.html")


@app.route("/api/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    if request.method == "GET":
        with sqlite3.connect(DB_PATH) as con:
            con.row_factory = sqlite3.Row
            users = con.execute(
                "SELECT id, username, first_name, last_name, is_admin, created_at FROM users ORDER BY username"
            ).fetchall()
            groups_by_user: dict[int, list] = {}
            for row in con.execute("""
                SELECT ug.user_id, g.id, g.name
                FROM user_groups ug JOIN groups g ON g.id = ug.group_id
            """).fetchall():
                groups_by_user.setdefault(row[0], []).append({"id": row[1], "name": row[2]})
        return jsonify([{
            "id": u["id"], "username": u["username"],
            "first_name": u["first_name"], "last_name": u["last_name"],
            "is_admin": bool(u["is_admin"]),
            "created_at": u["created_at"], "groups": groups_by_user.get(u["id"], []),
        } for u in users])

    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    first_name = (data.get("first_name") or "").strip() or None
    last_name = (data.get("last_name") or "").strip() or None
    is_admin = bool(data.get("is_admin"))
    group_ids = data.get("group_ids") or []
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    with sqlite3.connect(DB_PATH) as con:
        try:
            cur = con.execute(
                "INSERT INTO users (username, password_hash, first_name, last_name, is_admin) VALUES (?, ?, ?, ?, ?)",
                (username, generate_password_hash(password), first_name, last_name, int(is_admin)),
            )
        except sqlite3.IntegrityError:
            return jsonify({"error": "username already exists"}), 400
        user_id = cur.lastrowid
        for gid in group_ids:
            con.execute(
                "INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)",
                (user_id, gid),
            )
        con.commit()
    log_activity("user.create", target=username, detail=f"admin={is_admin}")
    return jsonify({"id": user_id, "username": username, "first_name": first_name, "last_name": last_name})


@app.route("/api/admin/users/<int:user_id>", methods=["PATCH"])
@admin_required
def admin_update_user(user_id):
    data = request.get_json(force=True, silent=True) or {}
    with sqlite3.connect(DB_PATH) as con:
        target_row = con.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        target_username = target_row[0] if target_row else str(user_id)
        changed = [f for f in ("first_name", "last_name", "is_admin", "group_ids") if f in data]

        if "first_name" in data:
            con.execute("UPDATE users SET first_name = ? WHERE id = ?",
                        ((data.get("first_name") or "").strip() or None, user_id))
        if "last_name" in data:
            con.execute("UPDATE users SET last_name = ? WHERE id = ?",
                        ((data.get("last_name") or "").strip() or None, user_id))

        if "is_admin" in data and not data["is_admin"]:
            other_admins = con.execute(
                "SELECT COUNT(*) FROM users WHERE is_admin = 1 AND id != ?", (user_id,)
            ).fetchone()[0]
            target_is_admin = con.execute(
                "SELECT is_admin FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if target_is_admin and target_is_admin[0] and other_admins == 0:
                return jsonify({"error": "cannot demote the last admin"}), 400
            con.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (user_id,))
        elif "is_admin" in data and data["is_admin"]:
            con.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))

        if "group_ids" in data:
            con.execute("DELETE FROM user_groups WHERE user_id = ?", (user_id,))
            for gid in data["group_ids"] or []:
                con.execute(
                    "INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)",
                    (user_id, gid),
                )
        con.commit()
    log_activity("user.update", target=target_username, detail=f"fields={','.join(changed)}")
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:user_id>/password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    data = request.get_json(force=True, silent=True) or {}
    password = data.get("password") or ""
    if not password:
        return jsonify({"error": "password is required"}), 400
    with sqlite3.connect(DB_PATH) as con:
        target_row = con.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        con.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                     (generate_password_hash(password), user_id))
        con.commit()
    log_activity("user.password_reset", target=target_row[0] if target_row else str(user_id))
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def admin_delete_user(user_id):
    with sqlite3.connect(DB_PATH) as con:
        target = con.execute("SELECT is_admin, username FROM users WHERE id = ?", (user_id,)).fetchone()
        if target and target[0]:
            other_admins = con.execute(
                "SELECT COUNT(*) FROM users WHERE is_admin = 1 AND id != ?", (user_id,)
            ).fetchone()[0]
            if other_admins == 0:
                return jsonify({"error": "cannot delete the last admin"}), 400
        con.execute("DELETE FROM user_groups WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM users WHERE id = ?", (user_id,))
        con.commit()
    log_activity("user.delete", target=target[1] if target else str(user_id))
    return jsonify({"ok": True})


@app.route("/api/admin/groups", methods=["GET", "POST"])
@admin_required
def admin_groups():
    if request.method == "GET":
        with sqlite3.connect(DB_PATH) as con:
            con.row_factory = sqlite3.Row
            groups = con.execute("SELECT id, name, color FROM groups ORDER BY name").fetchall()
            codes_by_group: dict[int, list] = {}
            for code, gid in con.execute("SELECT code, group_id FROM group_codes").fetchall():
                codes_by_group.setdefault(gid, []).append(code)
            counts = dict(con.execute(
                "SELECT group_id, COUNT(*) FROM user_groups GROUP BY group_id"
            ).fetchall())
        return jsonify([{
            "id": g["id"], "name": g["name"], "color": g["color"],
            "codes": codes_by_group.get(g["id"], []),
            "member_count": counts.get(g["id"], 0),
        } for g in groups])

    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    color = data.get("color")
    if not name:
        return jsonify({"error": "name is required"}), 400
    if color is not None and not _valid_hex_color(color):
        return jsonify({"error": "color must be a hex value like #2563eb"}), 400
    with sqlite3.connect(DB_PATH) as con:
        try:
            cur = con.execute("INSERT INTO groups (name, color) VALUES (?, ?)", (name, color))
        except sqlite3.IntegrityError:
            return jsonify({"error": "group already exists"}), 400
        con.commit()
    log_activity("group.create", target=name)
    return jsonify({"id": cur.lastrowid, "name": name, "color": color})


@app.route("/api/admin/groups/<int:group_id>", methods=["PATCH", "DELETE"])
@admin_required
def admin_group_detail(group_id):
    if request.method == "DELETE":
        with sqlite3.connect(DB_PATH) as con:
            name_row = con.execute("SELECT name FROM groups WHERE id = ?", (group_id,)).fetchone()
            con.execute("DELETE FROM group_codes WHERE group_id = ?", (group_id,))
            con.execute("DELETE FROM user_groups WHERE group_id = ?", (group_id,))
            con.execute("DELETE FROM groups WHERE id = ?", (group_id,))
            con.commit()
        log_activity("group.delete", target=name_row[0] if name_row else str(group_id))
        return jsonify({"ok": True})

    data = request.get_json(force=True, silent=True) or {}
    updates, params = [], []
    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name cannot be empty"}), 400
        updates.append("name = ?")
        params.append(name)
    if "color" in data:
        color = data.get("color")
        if color is not None and not _valid_hex_color(color):
            return jsonify({"error": "color must be a hex value like #2563eb"}), 400
        updates.append("color = ?")
        params.append(color)
    if not updates:
        return jsonify({"error": "nothing to update"}), 400
    params.append(group_id)
    with sqlite3.connect(DB_PATH) as con:
        con.execute(f"UPDATE groups SET {', '.join(updates)} WHERE id = ?", params)
        con.commit()
    log_activity("group.update", target=str(group_id), detail=f"fields={','.join(data.keys())}")
    return jsonify({"ok": True})


@app.route("/api/admin/group_codes", methods=["GET", "POST"])
@admin_required
def admin_group_codes():
    if request.method == "GET":
        with sqlite3.connect(DB_PATH) as con:
            con.row_factory = sqlite3.Row
            rows = con.execute("""
                SELECT gc.code, gc.group_id, g.name AS group_name
                FROM group_codes gc JOIN groups g ON g.id = gc.group_id
                ORDER BY gc.code
            """).fetchall()
        return jsonify([dict(r) for r in rows])

    data = request.get_json(force=True, silent=True) or {}
    code = (data.get("code") or "").strip()
    group_id = data.get("group_id")
    if len(code) != 1 or not group_id:
        return jsonify({"error": "code must be a single character and group_id is required"}), 400
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            INSERT INTO group_codes (code, group_id) VALUES (?, ?)
            ON CONFLICT(code) DO UPDATE SET group_id = excluded.group_id
        """, (code, group_id))
        con.commit()
    log_activity("group_code.create", target=code, detail=f"group_id={group_id}")
    return jsonify({"code": code, "group_id": group_id})


@app.route("/api/admin/group_codes/<code>", methods=["DELETE"])
@admin_required
def admin_delete_group_code(code):
    with sqlite3.connect(DB_PATH) as con:
        con.execute("DELETE FROM group_codes WHERE code = ?", (code,))
        con.commit()
    log_activity("group_code.delete", target=code)
    return jsonify({"ok": True})


@app.route("/api/admin/unassigned-devices")
@admin_required
def admin_unassigned_devices():
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""
            SELECT DISTINCT o.uuid, o.name
            FROM observations o
            LEFT JOIN group_codes gc ON gc.code = substr(o.name, 2, 1)
            LEFT JOIN groups g ON g.id = gc.group_id
            WHERE g.id IS NULL
            ORDER BY o.name
        """).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/audit-log")
@admin_required
def admin_audit_log():
    limit = min(int(request.args.get("limit", 200)), 1000)
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT id, ts, username, action, target, detail, ip FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


def _device_backup_payload(uuid: str) -> dict:
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        observations = con.execute("""
            SELECT uuid, name, lat, lon, obs_time, ingest_time, accuracy, confidence, device_id, received_at
            FROM observations WHERE uuid = ? ORDER BY obs_time
        """, (uuid,)).fetchall()
        meta = con.execute(
            "SELECT uuid, archived, archived_at, notes FROM device_meta WHERE uuid = ?", (uuid,)
        ).fetchone()
    return {
        "uuid": uuid,
        "backed_up_at": datetime.now(timezone.utc).isoformat(),
        "device_meta": dict(meta) if meta else None,
        "observations": [dict(r) for r in observations],
    }


# Standalone export — a real browser download, available any time (not tied
# to deletion). Separate from the server-side backup below.
@app.route("/api/admin/devices/<uuid>/export")
@admin_required
def export_device(uuid):
    payload = _device_backup_payload(uuid)
    resp = jsonify(payload)
    resp.headers["Content-Disposition"] = f'attachment; filename="{uuid}_backup.json"'
    log_activity("device.export", target=uuid)
    return resp


def _backup_device_to_disk(uuid: str) -> str:
    """Writes a JSON snapshot of one device's full observation history + its
    device_meta row to BACKUP_DIR (data/backup/, alongside tracks.db in the
    bind-mounted volume — survives restarts, reachable from the host).
    Filename is the device's name (sanitized), not its uuid — only used from
    the permanent-delete flow, so a repeat backup for the same device name
    intentionally overwrites the previous one."""
    payload = _device_backup_payload(uuid)
    observations = payload["observations"]
    name = observations[-1]["name"] if observations else uuid
    safe_name = os.path.basename(re.sub(r"[^A-Za-z0-9_.-]", "_", name)) or uuid
    os.makedirs(BACKUP_DIR, exist_ok=True)
    filepath = os.path.join(BACKUP_DIR, f"{safe_name}.json")
    with open(filepath, "w") as f:
        json.dump(payload, f, indent=2)
    return filepath


# Backup-to-disk is intentionally only reachable from the permanent-delete
# flow (see admin.html's deleteDevicePermanently()) — it is not a general
# export tool, that's what export_device() above is for.
@app.route("/api/admin/devices/<uuid>/backup", methods=["POST"])
@admin_required
def backup_device(uuid):
    filepath = _backup_device_to_disk(uuid)
    log_activity("device.backup", target=uuid, detail=filepath)
    return jsonify({"uuid": uuid, "backup_path": filepath})


# Permanent deletion is deliberately gated on the device already being
# archived — a device must go through the reversible archive step first,
# so this destructive action can never be a single accidental click.
@app.route("/api/admin/devices/<uuid>", methods=["DELETE"])
@admin_required
def delete_device_permanently(uuid):
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute("SELECT archived FROM device_meta WHERE uuid = ?", (uuid,)).fetchone()
        if not row or not row[0]:
            return jsonify({"error": "device must be archived before it can be permanently deleted"}), 400
        con.execute("DELETE FROM observations WHERE uuid = ?", (uuid,))
        con.execute("DELETE FROM device_meta WHERE uuid = ?", (uuid,))
        con.commit()
    log_activity("device.delete", target=uuid)
    return jsonify({"uuid": uuid, "deleted": True})


init_db()
bootstrap_admin()
threading.Thread(target=tcp_listener, daemon=True).start()
threading.Thread(target=_audit_log_pruner, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=HTTP_PORT, threaded=True)
