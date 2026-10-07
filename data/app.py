import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

import csv
import json
import math
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
    session, redirect, url_for, abort, stream_with_context,
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import comlibv3

TCP_HOST = "0.0.0.0"
TCP_PORT = int(os.environ.get("TCP_PORT", 9002))
HTTP_PORT = int(os.environ.get("HTTP_PORT", 8080))
DB_PATH = os.environ.get("DB_PATH", "tracks.db")
BACKUP_DIR = os.path.join(os.path.dirname(DB_PATH) or ".", "backup")
GEODATA_DIR = os.path.join(os.path.dirname(DB_PATH) or ".", "geodata")
AUDIT_LOG_RETENTION_DAYS = int(os.environ.get("AUDIT_LOG_RETENTION_DAYS", 90))
# Separate from AUDIT_LOG_RETENTION_DAYS on purpose — ai_messages holds free-text
# conversation content (positions, movement, label text a user asked about),
# not terse structured audit entries, so it deserves its own independently
# tunable retention window rather than being tied to the audit log's.
AI_HISTORY_RETENTION_DAYS = int(os.environ.get("AI_HISTORY_RETENTION_DAYS", 90))
# Lowered from the original 12h default — a sliding window (refreshed on
# every request via Flask's SESSION_REFRESH_EACH_REQUEST default), so this
# only actually matters after real inactivity, not a fixed cutoff from login.
SESSION_LIFETIME_HOURS = int(os.environ.get("SESSION_LIFETIME_HOURS", 3))
# How recently a user must have touched an authenticated route to count as
# "currently logged on" — see _touch_last_seen()/GET /api/admin/active-users.
ACTIVE_USER_WINDOW_MINUTES = int(os.environ.get("ACTIVE_USER_WINDOW_MINUTES", 15))

# Basemap: OpenStreetMap raster tiles by default (works anywhere, no internal
# network required — this is what dev uses). If BASEMAP_WMS_URL is set, the
# frontend switches to an NGA WMS layer instead (what prod uses, on a network
# that can actually reach it) — switching environments is then just one env
# var + `docker compose up -d`, never a code/template edit.
BASEMAP_WMS_URL = os.environ.get("BASEMAP_WMS_URL", "")
BASEMAP_WMS_LAYERS = os.environ.get("BASEMAP_WMS_LAYERS", "OSM_BASEMAP")
BASEMAP_ATTRIBUTION = os.environ.get("BASEMAP_ATTRIBUTION", "NGA OSM")

# Ask AI: OpenAI-compatible chat-completions endpoint (self-hosted vLLM in
# prod; Ollama, run as its own docker-compose service, in dev — see
# docker-compose.yml). Unset LLM_API_BASE_URL (default) disables the feature
# entirely — same graceful-degradation pattern as BASEMAP_WMS_URL.
LLM_API_BASE_URL = os.environ.get("LLM_API_BASE_URL", "").rstrip("/")
LLM_MODEL = os.environ.get("LLM_MODEL", "")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
# 60s default — measured against dev's CPU-only Ollama: ~11.5s to cold-load an
# 8B model plus ~30s to prefill a ~1300-token prompt (digest + system prompt +
# history) at ~39 tok/s. This is a per-read gap timeout (time with literally
# no bytes arriving), not a total-response cap, so it only needs to cover the
# slowest single gap — almost always the first token. Prod's GPU-backed vLLM
# should clear this with a lot of room to spare; raise it further here if a
# larger model/prompt makes cold CPU inference in dev time out again.
LLM_TIMEOUT_SECONDS = int(os.environ.get("LLM_TIMEOUT_SECONDS", 60))
LLM_MAX_CONCURRENT = int(os.environ.get("LLM_MAX_CONCURRENT", 4))
# Default ON everywhere — dev's LLM_API_BASE_URL points at a real, properly
# certed endpoint (NVIDIA hosted / Ollama on localhost) and should never skip
# validation. Prod's self-hosted vLLM sits behind an internal/self-signed
# cert, so ONLY prod's docker-compose.yml sets this to "0" — never flip this
# default itself, that would silently disable cert checking in dev too for
# zero benefit. When off, also silence urllib3's InsecureRequestWarning
# (requests emits one per unverified request otherwise, which would spam the
# gunicorn log once a second on an active Ask Goby conversation).
LLM_VERIFY_SSL = os.environ.get("LLM_VERIFY_SSL", "1") != "0"
if not LLM_VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Bump this whenever init_db() adds a table/column. Purely informational — the
# actual migration logic below is what's safe/idempotent — but it gives a
# one-line way to confirm a deploy landed (`docker logs` on startup, or query
# app_settings) without manually diffing PRAGMA table_info() across instances.
# 4 = current schema as of the private-device feature (device_meta.private +
# device_users); this is where version tracking starts, not a full history.
# 5 = super-admin override (users.is_super_admin) + private-device ownership
# (device_meta.private_owner_id).
# 6 = Labels feature (device_labels, label_users) replacing the old single
# device_meta.notes field; notes content one-time-migrated into device_labels.
# 7 = Ask AI feature (ai_messages table); no changes to existing tables.
# 8 = users.last_seen_at, for the "who's currently active" Management section.
# 9 = users.ai_access, per-user Ask Goby enable/disable (super admin only).
# 10 = device_plans (Smart Tracking stage 1: declared destination/proximity/ETA).
# 11 = device_plan_history (one row per plan create/update/delete, survives
# device_plans itself being overwritten/removed).
# 12 = device_plans.start_date / device_plan_history.start_date — explicit,
# operator-declared "this plan begins on X", replacing updated_at as the
# progress-trend cutoff (see _compute_plan_status()).
# 13 = device_plan_history.outcome — distinguishes a manual "mark arrived"
# close-out from a plain cancellation on a 'deleted' row.
SCHEMA_VERSION = 13

# App release version — bumped independently of SCHEMA_VERSION (a release can
# ship with no schema change, or vice versa). Tracked the same way: stamped
# into app_settings every startup, with a change logged to audit_log (not
# just overwritten silently) so Management's Activity Log shows a real
# history of what version was running when.
APP_VERSION = "4.3"


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
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_LIFETIME_HOURS),
)

_sse_clients: list[tuple] = []   # (queue.Queue, is_super_admin: bool, is_admin: bool, group_ids: frozenset[int], private_uuids: frozenset[str])
_sse_lock = threading.Lock()

# Bounds how many /api/ai/ask streams can be in flight at once. Each one holds
# a gunicorn thread for its duration, same budget as /stream's SSE threads
# (see gunicorn_config.py) — a modest default leaves headroom so a burst of
# chat usage can't starve ordinary dashboard tabs.
_AI_SEMAPHORE = threading.Semaphore(LLM_MAX_CONCURRENT)


# --- Auth helpers ---

def _wants_json() -> bool:
    return request.path.startswith("/api/") or request.path == "/stream"


def _touch_last_seen(user_id: int):
    """Updates users.last_seen_at — called from both auth decorators below, so
    it fires on virtually every authenticated request on both pages (not just
    /stream, which only index.html opens and wouldn't reflect Management
    activity at all). No debounce — at this app's real scale (a handful of
    users) a write per request is trivial, and debouncing would just be
    complexity this doesn't need. Never raises into the caller: a failure
    here must not break the actual request being served."""
    try:
        with sqlite3.connect(DB_PATH) as con:
            con.execute("UPDATE users SET last_seen_at = datetime('now') WHERE id = ?", (user_id,))
            con.commit()
    except Exception:
        logging.exception("Failed to update last_seen_at for user_id=%s", user_id)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            if _wants_json():
                return jsonify({"error": "authentication required"}), 401
            return redirect(url_for("login", next=request.path))
        _touch_last_seen(session["user_id"])
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
        _touch_last_seen(session["user_id"])
        return view(*args, **kwargs)
    return wrapped


def _super_admin_protected(target_user_id: int) -> bool:
    """True if target_user_id is the super admin and the current session
    belongs to a DIFFERENT account — i.e. the caller should be blocked from
    modifying them. Identity-based (self == target), not role-based (any
    is_super_admin session) — so even a second account that somehow also
    carried is_super_admin can't touch the real one; only that exact account
    can touch itself. No other admin has an override for this, matching the
    same no-escape-hatch model as private devices. See bootstrap_admin()'s
    RESET_ADMIN_PASSWORD env var for the out-of-band recovery path this
    necessitates (self-service password change needs the current password,
    which doesn't help if it's lost)."""
    if session.get("user_id") == target_user_id:
        return False
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute("SELECT is_super_admin FROM users WHERE id = ?", (target_user_id,)).fetchone()
    return bool(row and row[0])


def _visible_group_ids() -> list[int]:
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute(
            "SELECT group_id FROM user_groups WHERE user_id = ?", (session["user_id"],)
        ).fetchall()
    return [r[0] for r in rows]


def _private_visible_uuids(user_id: int) -> list[str]:
    """Uuids of private devices this specific user can see: either explicitly
    granted (device_users) or the admin who currently owns it (private_owner_id
    — whoever most recently set it private). Being an admin alone is NOT
    enough; only the super admin bypasses this (see _visibility_sql())."""
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute("""
            SELECT uuid FROM device_users WHERE user_id = ?
            UNION
            SELECT uuid FROM device_meta WHERE private = 1 AND private_owner_id = ?
        """, (user_id, user_id)).fetchall()
    return [r[0] for r in rows]


def _private_uuids() -> set[str]:
    """All uuids currently marked private, regardless of who can see them."""
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute("SELECT uuid FROM device_meta WHERE private = 1").fetchall()
    return {r[0] for r in rows}


def _visibility_sql() -> tuple[str, list]:
    """SQL fragment + params implementing device visibility for the current
    session, for queries that alias observations as o, groups as g, and
    device_meta as m (true for both api_devices() and api_tracks()).

    Three tiers:
    - Super admin (the "admin" account only): empty fragment, sees everything.
    - Regular admin: still sees every non-private device regardless of group
      (unchanged admin group-bypass) — but for PRIVATE devices, being an
      admin is no longer sufficient on its own; only ownership or an explicit
      device_users grant does (same allowlist as members get).
    - Member: non-private devices filtered by group membership; private
      devices via the same owner-or-granted allowlist.

    Private mode is an allowlist that *replaces* group visibility for that
    device, not an addition on top of it, per the feature's own definition
    ("only specific users can see them")."""
    if session.get("is_super_admin"):
        return "", []
    private_uuids = _private_visible_uuids(session["user_id"])
    private_clause = f"o.uuid IN ({','.join('?' * len(private_uuids))})" if private_uuids else "0=1"
    if session.get("is_admin"):
        clause = f" AND (COALESCE(m.private,0)=0 OR {private_clause})"
        return clause, list(private_uuids)
    group_ids = _visible_group_ids()
    group_clause = f"g.id IN ({','.join('?' * len(group_ids))})" if group_ids else "0=1"
    clause = f" AND ((COALESCE(m.private,0)=0 AND {group_clause}) OR (COALESCE(m.private,0)=1 AND {private_clause}))"
    return clause, [*group_ids, *private_uuids]


# Smart Tracking stage 2 — status computed from plain math/SQL, never the
# model (see CLAUDE.md's Smart Tracking section). Overdue: the ETA window's
# end plus this grace period has passed. Moving away: current distance to
# the destination exceeds the closest this device has ever gotten (since
# the plan's own declared start_date — NOT updated_at, a system timestamp
# of whenever the row was last saved that would conflate "edited the ETA"
# with "the plan restarted"; start_date is the operator's explicit,
# deliberate answer to that) by more than this many miles — deliberately
# NOT a "hasn't reported in N minutes" staleness check, since multi-day
# silence then a burst of updates is normal for these devices (see the
# Smart Tracking brainstorm notes) — only a real move in the wrong
# direction counts, not silence itself.
_OVERDUE_GRACE_HOURS = 24
_PROGRESS_TREND_THRESHOLD_MILES = 50


def _compute_plan_status(uuid: str, plan_row, current_lat=None, current_lon=None) -> dict:
    """Deterministic plan status for one device — `status` is "overdue",
    "moving_away", or "on_track" (overdue takes priority if both are true,
    since it's the more directly actionable signal). `current_lat`/`lon` can
    be passed in by a caller that already has the device's latest position
    (e.g. _visible_devices()) to avoid a redundant query; callers without it
    (e.g. the Ask Goby tool) get it queried here instead."""
    dest_lat, dest_lon = plan_row["dest_lat"], plan_row["dest_lon"]
    eta_end = plan_row["eta_end"]
    is_overdue = False
    if eta_end:
        try:
            cutoff = datetime.strptime(eta_end, "%Y-%m-%d") + timedelta(days=1, hours=_OVERDUE_GRACE_HOURS)
            is_overdue = datetime.now(timezone.utc).replace(tzinfo=None) > cutoff
        except ValueError:
            pass

    if current_lat is None or current_lon is None:
        with sqlite3.connect(DB_PATH) as con:
            last = con.execute(
                "SELECT lat, lon FROM observations WHERE uuid = ? ORDER BY obs_time DESC LIMIT 1", (uuid,)
            ).fetchone()
        if last:
            current_lat, current_lon = last

    current_distance_miles = closest_approach_miles = None
    if current_lat is not None:
        current_distance_miles = round(_haversine_meters(current_lat, current_lon, dest_lat, dest_lon) / _METERS_PER_MILE, 1)
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute(
            "SELECT lat, lon FROM observations WHERE uuid = ? AND obs_time >= ?",
            (uuid, plan_row["start_date"]),
        ).fetchall()
    if rows:
        closest_approach_miles = round(
            min(_haversine_meters(r[0], r[1], dest_lat, dest_lon) for r in rows) / _METERS_PER_MILE, 1
        )

    is_moving_away = (
        current_distance_miles is not None and closest_approach_miles is not None
        and current_distance_miles > closest_approach_miles + _PROGRESS_TREND_THRESHOLD_MILES
    )
    status = "overdue" if is_overdue else ("moving_away" if is_moving_away else "on_track")
    return {
        "status": status, "is_overdue": is_overdue, "is_moving_away": is_moving_away,
        "current_distance_miles": current_distance_miles, "closest_approach_miles": closest_approach_miles,
    }


def _visible_devices(want_archived: bool = False) -> list[dict]:
    """Latest position + fix count per device visible to the current session —
    the same rows /api/devices returns, as plain dicts. Single source of truth
    reused by the AI assistant's insight layer so it can never surface more
    than the dashboard itself would for that session."""
    query = """
        SELECT o.uuid, o.name, o.lat, o.lon, o.obs_time AS last_seen,
               o.accuracy, o.confidence, cnt.fix_count, m.archived_at,
               COALESCE(m.private, 0) AS private,
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
    clause, extra_params = _visibility_sql()
    query += clause
    params.extend(extra_params)
    query += " ORDER BY last_seen DESC"
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(query, params).fetchall()
        devices = [dict(r) for r in rows]
        plans = {}
        if devices:
            uuids = [d["uuid"] for d in devices]
            placeholders = ",".join("?" * len(uuids))
            plans = {r["uuid"]: r for r in con.execute(
                f"SELECT * FROM device_plans WHERE uuid IN ({placeholders})", uuids
            ).fetchall()}
    # Only the (typically few, often zero) devices with an active plan pay
    # for the extra per-device status computation — not every device on
    # every call.
    for d in devices:
        plan = plans.get(d["uuid"])
        if plan:
            d["plan_status"] = _compute_plan_status(d["uuid"], plan, d["lat"], d["lon"])["status"]
            # fix_count defaults to all-time (the cnt join above) — for a
            # device with an active plan, override it to only count fixes
            # since the plan's own start_date, same clamp reasoning as the
            # distance-traveled tools: a reused device's fix count shouldn't
            # include activity from before its current plan began.
            with sqlite3.connect(DB_PATH) as con:
                d["fix_count"] = con.execute(
                    "SELECT COUNT(*) FROM observations WHERE uuid = ? AND obs_time >= ?",
                    (d["uuid"], plan["start_date"]),
                ).fetchone()[0]
            d["fix_count_window"] = f"since plan start {plan['start_date']}"
        else:
            d["plan_status"] = None
    return devices


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
        if "private" not in existing_cols:
            con.execute("ALTER TABLE device_meta ADD COLUMN private INTEGER NOT NULL DEFAULT 0")
        if "private_owner_id" not in existing_cols:
            con.execute("ALTER TABLE device_meta ADD COLUMN private_owner_id INTEGER REFERENCES users(id)")
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
        if "is_super_admin" not in existing_user_cols:
            con.execute("ALTER TABLE users ADD COLUMN is_super_admin INTEGER NOT NULL DEFAULT 0")
        if "last_seen_at" not in existing_user_cols:
            con.execute("ALTER TABLE users ADD COLUMN last_seen_at TEXT")
        if "ai_access" not in existing_user_cols:
            # Per-user Ask Goby enable/disable, super admin only — defaults
            # to 1 (allowed) so upgrading an existing deployment doesn't
            # silently cut anyone off who was already using the feature.
            con.execute("ALTER TABLE users ADD COLUMN ai_access INTEGER NOT NULL DEFAULT 1")
        # The account literally named "admin" is always the super admin,
        # regardless of when/how it was created — re-asserted every startup
        # (not just on fresh installs) so this holds on existing deployments
        # too, not just new ones bootstrapped after this column existed.
        con.execute("UPDATE users SET is_super_admin = 1 WHERE username = 'admin'")
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
            CREATE TABLE IF NOT EXISTS device_users (
                uuid    TEXT NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id),
                PRIMARY KEY (uuid, user_id)
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS device_labels (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid       TEXT NOT NULL,
                text       TEXT NOT NULL,
                private    INTEGER NOT NULL DEFAULT 0,
                created_by INTEGER REFERENCES users(id),
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_device_labels_uuid ON device_labels(uuid)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS label_users (
                label_id INTEGER NOT NULL REFERENCES device_labels(id),
                user_id  INTEGER NOT NULL REFERENCES users(id),
                PRIMARY KEY (label_id, user_id)
            )
        """)
        # Smart Tracking, stage 1: a device's plan (declared destination +
        # proximity + ETA window). uuid is the PRIMARY KEY, not a separate id
        # — "single destination, changeable" means there's at most one row
        # per device, and a new POST upserts over it rather than creating a
        # second row. dest_lat/dest_lon/radius_miles is a PROXIMITY circle,
        # deliberately never an exact point (the destination itself is
        # sensitive) — this same circle doubles as the arrival-detection
        # zone in a later stage, so there's no separate "arrival radius" to
        # keep in sync with it. No status/history columns yet — this stage
        # is plan-setting + the map circle only; overdue/progress-trend
        # alerts and manual close-out are a deliberately separate later
        # stage (staged on purpose, not an oversight).
        con.execute("""
            CREATE TABLE IF NOT EXISTS device_plans (
                uuid         TEXT PRIMARY KEY,
                dest_lat     REAL NOT NULL,
                dest_lon     REAL NOT NULL,
                radius_miles REAL NOT NULL,
                eta_start    TEXT,
                eta_end      TEXT,
                created_by   INTEGER REFERENCES users(id),
                created_at   TEXT DEFAULT (datetime('now')),
                updated_at   TEXT DEFAULT (datetime('now'))
            )
        """)
        existing_plan_cols = {row[1] for row in con.execute("PRAGMA table_info(device_plans)")}
        if "start_date" not in existing_plan_cols:
            # Explicit, operator-declared "this plan begins on X" —
            # deliberately NOT the same as updated_at (a system timestamp of
            # whenever the row was last saved, which the progress-trend
            # calculation used before this column existed, and which
            # conflated "edited the ETA" with "the plan restarted").
            # Backfilled from created_at for rows that predate this column,
            # which is the closest honest approximation available.
            con.execute("ALTER TABLE device_plans ADD COLUMN start_date TEXT")
            con.execute("UPDATE device_plans SET start_date = date(created_at) WHERE start_date IS NULL")
        # A basic history of every create/update/delete of a plan — unlike
        # audit_log (which deliberately never logs dest_lat/dest_lon, since
        # that log has no per-device visibility filter and any admin can
        # read it), this table's own read route is gated by
        # _device_visible(uuid), the same check the live plan itself uses —
        # so it's safe to store the real destination here. One row per
        # change, not per device, so a device's full plan history survives
        # being edited or deleted (device_plans itself only ever holds the
        # CURRENT state, overwritten in place on every edit).
        con.execute("""
            CREATE TABLE IF NOT EXISTS device_plan_history (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid         TEXT NOT NULL,
                action       TEXT NOT NULL,
                dest_lat     REAL NOT NULL,
                dest_lon     REAL NOT NULL,
                radius_miles REAL NOT NULL,
                eta_start    TEXT,
                eta_end      TEXT,
                changed_by   INTEGER REFERENCES users(id),
                changed_at   TEXT DEFAULT (datetime('now'))
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_device_plan_history_uuid ON device_plan_history(uuid)")
        existing_history_cols = {row[1] for row in con.execute("PRAGMA table_info(device_plan_history)")}
        if "start_date" not in existing_history_cols:
            con.execute("ALTER TABLE device_plan_history ADD COLUMN start_date TEXT")
        if "outcome" not in existing_history_cols:
            # Distinguishes WHY a plan ended on a 'deleted' row — 'arrived'
            # (the device reached its destination) vs 'cancelled' (anything
            # else) vs NULL (a 'created'/'updated' row, which isn't an
            # ending at all). Kept as a separate column rather than adding a
            # 4th `action` value, so `action` stays the plain CRUD-style
            # vocabulary (created/updated/deleted) and `outcome` carries the
            # domain meaning — manual close-out, per the original Smart
            # Tracking design decision, now actually distinguishable in the
            # history it writes to instead of being generically "deleted."
            con.execute("ALTER TABLE device_plan_history ADD COLUMN outcome TEXT")
        # One-time backfill: the old single free-text device_meta.notes field
        # becomes an initial public label per device that had one. Guarded by
        # an app_settings flag (not "does device_labels have rows", which
        # would wrongly re-run after a user deletes their last label) so this
        # only ever runs once, even though init_db() runs on every startup.
        if con.execute(
            "SELECT value FROM app_settings WHERE key = 'notes_migrated_to_labels'"
        ).fetchone() is None:
            for uuid, notes in con.execute(
                "SELECT uuid, notes FROM device_meta WHERE notes IS NOT NULL AND TRIM(notes) != ''"
            ).fetchall():
                con.execute(
                    "INSERT INTO device_labels (uuid, text, private, created_by) VALUES (?, ?, 0, NULL)",
                    (uuid, notes),
                )
            con.execute(
                "INSERT INTO app_settings (key, value) VALUES ('notes_migrated_to_labels', '1')"
            )
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
        con.execute("""
            CREATE TABLE IF NOT EXISTS ai_messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER REFERENCES users(id),
                username   TEXT,
                role       TEXT NOT NULL,
                content    TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_ai_messages_user ON ai_messages(user_id, created_at)")
        _stamp_version(con, "schema_version", str(SCHEMA_VERSION))
        _stamp_version(con, "app_version", APP_VERSION)
        con.commit()
    logging.info("Schema version: %d", SCHEMA_VERSION)
    logging.info("App version: %s", APP_VERSION)


def _stamp_version(con, key: str, new_value: str):
    """Writes key's current value to app_settings, and — unlike a plain
    overwrite — logs a real audit_log entry when it actually CHANGED from
    last startup, so Management's Activity Log shows version history over
    time, not just "whatever it is right now". Called from init_db(), which
    runs at import time outside any Flask request context, so this can't go
    through log_activity() (needs request.remote_addr/session) — it's a
    direct INSERT with username='system' instead."""
    prev = con.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
    prev_value = prev[0] if prev else None
    if prev_value != new_value:
        con.execute(
            "INSERT INTO audit_log (user_id, username, action, target, detail, ip) "
            "VALUES (NULL, 'system', ?, ?, ?, NULL)",
            (f"{key}.change", new_value, f"from={prev_value or 'none'}"),
        )
    con.execute("""
        INSERT INTO app_settings (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    """, (key, new_value))


def bootstrap_admin():
    admin_user = os.environ.get("ADMIN_USER")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    with sqlite3.connect(DB_PATH) as con:
        existing = con.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1").fetchone()[0]
        if existing:
            _maybe_reset_super_admin_password(con)
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


def _maybe_reset_super_admin_password(con):
    """Out-of-band recovery for the super admin ('admin') account's password.
    Necessary precisely because no other admin can touch that account
    anymore (see _super_admin_protected()) and self-service password change
    needs the CURRENT password, which doesn't help if it's lost — this is
    the only remaining recovery path, and it requires host/deploy access,
    not just a web session, which is the point for the single most
    privileged account.

    Deliberately requires two separate env vars (not just reusing
    ADMIN_PASSWORD alone) so a stale ADMIN_PASSWORD left in docker-compose.yml
    can never silently clobber a real password change on an ordinary
    restart — this exact failure mode happened once already this session
    (see CLAUDE.md's auth/RBAC section). Unset RESET_ADMIN_PASSWORD (or both)
    after use, or it will keep resetting on every restart."""
    if os.environ.get("RESET_ADMIN_PASSWORD") != "1":
        return
    new_password = os.environ.get("ADMIN_PASSWORD")
    if not new_password:
        logging.warning("RESET_ADMIN_PASSWORD=1 is set but ADMIN_PASSWORD is empty — skipping reset")
        return
    cur = con.execute(
        "UPDATE users SET password_hash = ? WHERE username = 'admin'",
        (generate_password_hash(new_password),),
    )
    con.commit()
    if cur.rowcount:
        logging.warning(
            "RESET_ADMIN_PASSWORD=1: forcibly reset the 'admin' account's password from "
            "the ADMIN_PASSWORD env var. Remove RESET_ADMIN_PASSWORD before the next restart."
        )
    else:
        logging.warning("RESET_ADMIN_PASSWORD=1 is set but no user named 'admin' exists — nothing reset")


def get_archived_uuids() -> set:
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute("SELECT uuid FROM device_meta WHERE archived = 1").fetchall()
    return {r[0] for r in rows}


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


def _prune_ai_messages():
    """Deletes ai_messages rows older than AI_HISTORY_RETENTION_DAYS — same
    reasoning and structure as _prune_audit_log(), just a separate table and
    env var (see AI_HISTORY_RETENTION_DAYS)."""
    with sqlite3.connect(DB_PATH) as con:
        cur = con.execute(
            "DELETE FROM ai_messages WHERE created_at < datetime('now', ?)",
            (f"-{AI_HISTORY_RETENTION_DAYS} days",),
        )
        con.commit()
        if cur.rowcount:
            logging.info("Pruned %d ai_messages row(s) older than %d days", cur.rowcount, AI_HISTORY_RETENTION_DAYS)


def _ai_history_pruner():
    """Runs _prune_ai_messages() immediately, then once every 24h — same
    daemon-thread pattern as _audit_log_pruner()."""
    while True:
        try:
            _prune_ai_messages()
        except Exception:
            logging.exception("AI history pruning failed")
        time.sleep(24 * 60 * 60)


def _device_visible(uuid: str) -> bool:
    """True if the current session user is allowed to see/annotate this
    device. Super admin: always. Private devices need an explicit
    device_users grant or current ownership regardless of is_admin — same
    rule as _visibility_sql(). Non-private devices: unconditionally visible
    to (non-super) admins, or group-filtered for members."""
    if session.get("is_super_admin"):
        return True
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        row = con.execute("SELECT name FROM observations WHERE uuid = ? LIMIT 1", (uuid,)).fetchone()
        meta = con.execute("SELECT private FROM device_meta WHERE uuid = ?", (uuid,)).fetchone()
    if not row:
        return False
    if meta and meta["private"]:
        return uuid in set(_private_visible_uuids(session["user_id"]))
    if session.get("is_admin"):
        return True
    code_map = _code_to_group()
    gid = _device_group_id(row["name"], code_map)
    return gid is not None and gid in set(_visible_group_ids())


def _label_accessible(con, label, uuid: str) -> bool:
    """Whether the current session can see AND edit this label — the same
    predicate for both, per the feature's own definition ("users who can see
    a private label can make changes and make it public"). Super admin: always
    (same unconditional override as private devices). A regular admin is NOT
    automatically exempt from a private label's allowlist — only the creator,
    an explicit label_users grant, or the super admin can see/edit a private
    label someone else set; being a regular admin alone is not enough (fixed —
    this previously checked is_admin, which wrongly let any admin read every
    other admin's private labels). Public labels: anyone who can see the
    underlying device — a regular admin already gets that via _device_visible()
    on any non-private device, so no separate admin check is needed here."""
    if session.get("is_super_admin"):
        return True
    if not label["private"]:
        return _device_visible(uuid)
    if label["created_by"] == session.get("user_id"):
        return True
    granted = con.execute(
        "SELECT 1 FROM label_users WHERE label_id = ? AND user_id = ?",
        (label["id"], session["user_id"]),
    ).fetchone()
    return bool(granted)


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
        private_set = _private_uuids()
        # Stamp group_id/group_color onto each observation once, up front —
        # matches what /api/devices and /api/tracks already derive, so a
        # device first seen via a live push (rather than the initial page
        # load) still renders with the right color instead of falling back
        # to "Unassigned" gray on the client.
        for o in obs_list:
            gid = _device_group_id(o.get("name"), code_map)
            o["group_id"] = gid
            o["group_color"] = colors.get(gid)
            o["private"] = o["uuid"] in private_set
        dead = []
        for client in _sse_clients:
            q, is_super_admin, is_admin, group_ids, private_uuids = client
            if is_super_admin:
                visible = obs_list
            elif is_admin:
                visible = [o for o in obs_list if not o["private"] or o["uuid"] in private_uuids]
            else:
                visible = [
                    o for o in obs_list
                    if (not o["private"] and o["group_id"] in group_ids)
                    or (o["private"] and o["uuid"] in private_uuids)
                ]
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
    return render_template(
        "index.html",
        basemap_wms_url=BASEMAP_WMS_URL,
        basemap_wms_layers=BASEMAP_WMS_LAYERS,
        basemap_attribution=BASEMAP_ATTRIBUTION,
        ai_enabled=_ai_feature_enabled() and _user_ai_allowed(session["user_id"]),
    )


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
            "SELECT id, password_hash, is_admin, is_super_admin FROM users WHERE username = ?",
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
    session["is_super_admin"] = bool(user["is_super_admin"])
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
        "id": session["user_id"],
        "username": session["username"],
        "is_admin": bool(session["is_admin"]),
        "is_super_admin": bool(session.get("is_super_admin")),
        "first_name": user["first_name"] if user else None,
        "last_name": user["last_name"] if user else None,
        "groups": [dict(g) for g in groups],
    })


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


@app.route("/api/devices/<uuid>/labels")
@login_required
def get_device_labels(uuid):
    if not _device_visible(uuid):
        return jsonify({"error": "not found"}), 404
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""
            SELECT dl.*, u.username AS created_by_username
            FROM device_labels dl
            LEFT JOIN users u ON u.id = dl.created_by
            WHERE dl.uuid = ?
            ORDER BY dl.created_at
        """, (uuid,)).fetchall()
        allowed_by_label: dict[int, list] = {}
        label_ids = [r["id"] for r in rows]
        if label_ids:
            placeholders = ",".join("?" * len(label_ids))
            for lid, uid, uname in con.execute(f"""
                SELECT lu.label_id, u.id, u.username FROM label_users lu
                JOIN users u ON u.id = lu.user_id
                WHERE lu.label_id IN ({placeholders})
            """, label_ids).fetchall():
                allowed_by_label.setdefault(lid, []).append({"id": uid, "username": uname})

        result = []
        for r in rows:
            if not _label_accessible(con, r, uuid):
                continue
            result.append({
                "id": r["id"], "uuid": r["uuid"], "text": r["text"], "private": bool(r["private"]),
                "created_by": r["created_by"], "created_by_username": r["created_by_username"],
                "allowed_users": allowed_by_label.get(r["id"], []),
                "created_at": r["created_at"], "updated_at": r["updated_at"],
            })
    return jsonify(result)


@app.route("/api/devices/<uuid>/labels", methods=["POST"])
@login_required
def create_device_label(uuid):
    if not _device_visible(uuid):
        return jsonify({"error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text is required"}), 400
    private = bool(data.get("private"))
    user_ids = data.get("user_ids") or []
    with sqlite3.connect(DB_PATH) as con:
        cur = con.execute(
            "INSERT INTO device_labels (uuid, text, private, created_by) VALUES (?, ?, ?, ?)",
            (uuid, text, int(private), session["user_id"]),
        )
        label_id = cur.lastrowid
        if private:
            for uid in user_ids:
                con.execute("INSERT OR IGNORE INTO label_users (label_id, user_id) VALUES (?, ?)", (label_id, uid))
        con.commit()
    log_activity("label.create", target=uuid, detail=f"label_id={label_id} private={private}")
    return jsonify({"id": label_id, "ok": True})


@app.route("/api/labels/<int:label_id>", methods=["PATCH"])
@login_required
def update_device_label(label_id):
    data = request.get_json(force=True, silent=True) or {}
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        label = con.execute("SELECT * FROM device_labels WHERE id = ?", (label_id,)).fetchone()
        if not label or not _label_accessible(con, label, label["uuid"]):
            return jsonify({"error": "not found"}), 404

        updates, params = [], []
        if "text" in data:
            text = (data.get("text") or "").strip()
            if not text:
                return jsonify({"error": "text cannot be empty"}), 400
            updates.append("text = ?")
            params.append(text)
        if "private" in data:
            updates.append("private = ?")
            params.append(1 if data["private"] else 0)
        if updates:
            updates.append("updated_at = datetime('now')")
            params.append(label_id)
            con.execute(f"UPDATE device_labels SET {', '.join(updates)} WHERE id = ?", params)
        if "user_ids" in data:
            con.execute("DELETE FROM label_users WHERE label_id = ?", (label_id,))
            for uid in data["user_ids"] or []:
                con.execute("INSERT OR IGNORE INTO label_users (label_id, user_id) VALUES (?, ?)", (label_id, uid))
        con.commit()
    # Field names only, never the label's own text — same pattern as
    # user.update/group.update, and specifically important here since a
    # private label's content shouldn't leak into the admin-visible audit
    # trail for admins who aren't the creator/granted (see _label_accessible()).
    changed = [f for f in ("text", "private", "user_ids") if f in data]
    log_activity("label.update", target=label["uuid"], detail=f"label_id={label_id} fields={','.join(changed)}")
    return jsonify({"ok": True})


@app.route("/api/labels/<int:label_id>", methods=["DELETE"])
@login_required
def delete_device_label(label_id):
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        label = con.execute("SELECT * FROM device_labels WHERE id = ?", (label_id,)).fetchone()
        if not label or not _label_accessible(con, label, label["uuid"]):
            return jsonify({"error": "not found"}), 404
        con.execute("DELETE FROM label_users WHERE label_id = ?", (label_id,))
        con.execute("DELETE FROM device_labels WHERE id = ?", (label_id,))
        con.commit()
    log_activity("label.delete", target=label["uuid"], detail=f"label_id={label_id} was_private={bool(label['private'])}")
    return jsonify({"ok": True})


@app.route("/api/devices/<uuid>/group-members")
@login_required
def device_group_members(uuid):
    """Candidates for granting a private label — members of THIS device's
    derived group specifically, not the requester's own groups (a user can
    belong to several groups; only the device's actual group is relevant)."""
    if not _device_visible(uuid):
        return jsonify({"error": "not found"}), 404
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        name_row = con.execute("SELECT name FROM observations WHERE uuid = ? LIMIT 1", (uuid,)).fetchone()
        if not name_row:
            return jsonify([])
        code_map = _code_to_group()
        gid = _device_group_id(name_row["name"], code_map)
        if gid is None:
            return jsonify([])
        rows = con.execute("""
            SELECT u.id, u.username FROM user_groups ug JOIN users u ON u.id = ug.user_id
            WHERE ug.group_id = ? ORDER BY u.username
        """, (gid,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/devices/<uuid>/plan")
@login_required
def get_device_plan(uuid):
    """Smart Tracking stage 1 — a device's declared plan, or null if none.
    Same visibility rule as labels: anyone who can see the device at all can
    see its plan (see _device_visible(); plan visibility deliberately
    matches device visibility, not a separate tier)."""
    if not _device_visible(uuid):
        return jsonify({"error": "not found"}), 404
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        row = con.execute("""
            SELECT dp.*, u.username AS created_by_username
            FROM device_plans dp LEFT JOIN users u ON u.id = dp.created_by
            WHERE dp.uuid = ?
        """, (uuid,)).fetchone()
    return jsonify(dict(row) if row else None)


@app.route("/api/devices/<uuid>/plan", methods=["POST"])
@login_required
def set_device_plan(uuid):
    """Create or replace this device's plan — "single destination,
    changeable" means a new POST upserts over any existing one, never a
    second row (device_plans.uuid is the PRIMARY KEY). Anyone who can see
    the device can set/edit its plan, same as a public label — there's no
    separate ownership/exclusivity concept here, unlike private devices."""
    if not _device_visible(uuid):
        return jsonify({"error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    try:
        dest_lat = float(data["dest_lat"])
        dest_lon = float(data["dest_lon"])
        radius_miles = float(data["radius_miles"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "dest_lat, dest_lon, and radius_miles are required numbers"}), 400
    if radius_miles <= 0:
        return jsonify({"error": "radius_miles must be positive"}), 400
    eta_start = (data.get("eta_start") or "").strip() or None
    eta_end = (data.get("eta_end") or "").strip() or None
    # All fields required — a plan with a missing ETA is half-declared and
    # not meaningfully trackable. Enforced here too, not just client-side in
    # index.html, same as every other mutating route in this app.
    if not eta_start or not eta_end:
        return jsonify({"error": "eta_start and eta_end are required"}), 400
    # start_date: explicit, operator-declared "this plan begins on X" —
    # unlike eta_start/eta_end (no sensible default, must be stated), a
    # missing start_date defaults to today rather than erroring, since
    # that's correct for the overwhelmingly common case (declaring a plan
    # the moment it actually begins). Still always a real, stored
    # value — never left to fall back to updated_at implicitly.
    start_date = (data.get("start_date") or "").strip() or None
    if start_date:
        try:
            datetime.strptime(start_date, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "start_date must be in YYYY-MM-DD format"}), 400
    else:
        start_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with sqlite3.connect(DB_PATH) as con:
        existed = con.execute("SELECT 1 FROM device_plans WHERE uuid = ?", (uuid,)).fetchone() is not None
        con.execute("""
            INSERT INTO device_plans
                (uuid, dest_lat, dest_lon, radius_miles, eta_start, eta_end, start_date, created_by, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(uuid) DO UPDATE SET
                dest_lat = excluded.dest_lat, dest_lon = excluded.dest_lon,
                radius_miles = excluded.radius_miles, eta_start = excluded.eta_start,
                eta_end = excluded.eta_end, start_date = excluded.start_date,
                created_by = excluded.created_by, updated_at = datetime('now')
        """, (uuid, dest_lat, dest_lon, radius_miles, eta_start, eta_end, start_date, session["user_id"]))
        # Unlike audit_log (see below), this table's read route is gated by
        # _device_visible() same as the live plan, so the real destination
        # is safe to store here — this is the only place "what was the
        # destination during a device's earlier plan" can ever be answered,
        # since device_plans itself only holds the current state.
        con.execute("""
            INSERT INTO device_plan_history
                (uuid, action, dest_lat, dest_lon, radius_miles, eta_start, eta_end, start_date, changed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (uuid, "updated" if existed else "created", dest_lat, dest_lon, radius_miles,
              eta_start, eta_end, start_date, session["user_id"]))
        con.commit()
    # Never log dest_lat/dest_lon to audit_log — the destination is exactly
    # as sensitive as a private label's text, but the audit log has no
    # per-device visibility filter (any admin reads it globally), so leaking
    # the location there would bypass _device_visible()'s own protection for
    # a private device. radius_miles/eta/start_date reveal nothing about WHERE.
    log_activity("plan.update" if existed else "plan.create", target=uuid,
                  detail=f"radius_miles={radius_miles} eta={eta_start or '?'}..{eta_end or '?'} start={start_date}")
    return jsonify({"ok": True})


@app.route("/api/devices/<uuid>/plan", methods=["DELETE"])
@login_required
def delete_device_plan(uuid):
    """Manual close-out, per the original Smart Tracking design decision —
    there is no automatic "arrived" detection (no geofence-triggered
    close-out), only this. 'Mark arrived' and 'Cancel plan' in index.html
    both call this same route — the only difference is the optional
    `outcome` body field, which only affects what gets written to
    device_plan_history, never the live device_plans row itself (deleted
    either way)."""
    if not _device_visible(uuid):
        return jsonify({"error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    outcome = data.get("outcome")
    if outcome not in ("arrived", "cancelled", None):
        return jsonify({"error": "outcome must be 'arrived' or 'cancelled' if given"}), 400
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        existing = con.execute("SELECT * FROM device_plans WHERE uuid = ?", (uuid,)).fetchone()
        cur = con.execute("DELETE FROM device_plans WHERE uuid = ?", (uuid,))
        if existing:
            con.execute("""
                INSERT INTO device_plan_history
                    (uuid, action, dest_lat, dest_lon, radius_miles, eta_start, eta_end, start_date, outcome, changed_by)
                VALUES (?, 'deleted', ?, ?, ?, ?, ?, ?, ?, ?)
            """, (uuid, existing["dest_lat"], existing["dest_lon"], existing["radius_miles"],
                  existing["eta_start"], existing["eta_end"], existing["start_date"], outcome, session["user_id"]))
        con.commit()
    if cur.rowcount:
        log_activity("plan.delete", target=uuid, detail=f"outcome={outcome}" if outcome else None)
    return jsonify({"ok": True})


@app.route("/api/devices/<uuid>/plan/history")
@login_required
def get_device_plan_history(uuid):
    """Same visibility rule as the live plan — anyone who can see the device
    can see its full plan history, no new permission tier. Safe to return
    raw dest_lat/dest_lon here (unlike anything the model sees) since this
    route itself is the access control, same as GET .../plan already is."""
    if not _device_visible(uuid):
        return jsonify({"error": "not found"}), 404
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""
            SELECT h.*, u.username AS changed_by_username
            FROM device_plan_history h LEFT JOIN users u ON u.id = h.changed_by
            WHERE h.uuid = ? ORDER BY h.changed_at DESC
        """, (uuid,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/devices")
@login_required
def api_devices():
    want_archived = request.args.get("archived") == "1"
    return jsonify(_visible_devices(want_archived))


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
    clause, extra_params = _visibility_sql()
    query += clause
    params.extend(extra_params)
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
    is_super_admin = bool(session.get("is_super_admin"))
    is_admin = bool(session.get("is_admin"))
    group_ids = frozenset() if (is_super_admin or is_admin) else frozenset(_visible_group_ids())
    private_uuids = frozenset() if is_super_admin else frozenset(_private_visible_uuids(session["user_id"]))

    q: queue.Queue = queue.Queue(maxsize=50)
    with _sse_lock:
        _sse_clients.append((q, is_super_admin, is_admin, group_ids, private_uuids))

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


# --- AI assistant ---
#
# Design: tool-calling, not a pre-built context digest. The model decides what
# to look up and with what parameters (it actually understands language,
# unlike a fixed regex list) by calling one of _AI_TOOLS; every tool routes
# through _visible_devices()/_device_visible()/_label_accessible() (the same
# RBAC primitives /api/devices and labels use) and independently re-checks
# visibility itself — the model is never trusted to have only asked about
# things it's already allowed to see, since a tool-call argument is untrusted
# model output, no different from user input. No tool ever returns raw
# coordinates (see _tool_compute_distance's stripping and
# _try_exact_location_shortcut's comment) — exact locations are answered
# directly from the database, with no LLM involvement, so real coordinates
# can never be sent to an external API regardless of which one is configured.

def _llm_configured() -> bool:
    return bool(LLM_API_BASE_URL)


def _ai_feature_enabled() -> bool:
    """Whether Ask Goby is actually usable right now: an LLM endpoint must be
    configured (LLM_API_BASE_URL, an env/deploy-level capability) AND the
    runtime toggle must be on (app_settings.ai_enabled, settable only by the
    super admin via PATCH /api/admin/ai-settings — see admin_ai_settings()).
    Defaults to enabled when the setting row doesn't exist yet, so upgrading
    an existing deployment where the feature is already live doesn't silently
    turn it off underneath whoever's already using it."""
    if not _llm_configured():
        return False
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute("SELECT value FROM app_settings WHERE key = 'ai_enabled'").fetchone()
    return row is None or row[0] == "1"


def _user_ai_allowed(user_id: int) -> bool:
    """Per-user Ask Goby access (users.ai_access), independent of the global
    deploy/runtime gates above — settable only by the super admin (see
    admin_update_user()'s ai_access handling). Checked both where the panel
    is rendered (index()) and, as the real enforcement boundary, inside
    /api/ai/ask itself — the same two-layer pattern as _ai_feature_enabled()
    gating both the template var and the route."""
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute("SELECT ai_access FROM users WHERE id = ?", (user_id,)).fetchone()
    return bool(row and row[0])


def _llm_chat_once(messages: list[dict], tools: list[dict] | None = None) -> dict:
    """One non-streaming chat-completions call. Returns the full `choice`
    object (has both "message" — content and/or tool_calls — and
    "finish_reason" as siblings). Non-streaming deliberately: assembling
    tool-call argument fragments out of incrementally-streamed chunks is real
    added complexity this app has no need for, since only the FINAL round
    (plain content, no more tool calls) needs to reach the browser live — see
    _llm_chat_with_tools(), which chunks that already-complete text itself to
    preserve the streaming UI with none of that complexity. Raises on any
    failure (timeout, non-200, malformed body); the caller turns that into a
    clean error event rather than a crash."""
    payload = {
        "model": LLM_MODEL, "messages": messages,
        "temperature": 0.1, "max_tokens": 1500, "stream": False,
    }
    if tools:
        payload["tools"] = tools
    resp = requests.post(
        f"{LLM_API_BASE_URL}/chat/completions", json=payload,
        headers={"Authorization": f"Bearer {LLM_API_KEY}"} if LLM_API_KEY else {},
        timeout=(10, LLM_TIMEOUT_SECONDS),
        verify=LLM_VERIFY_SSL,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]


def _llm_chat_with_tools(messages: list[dict], max_rounds: int = 5):
    """The tool-calling dispatch loop — replaces the old single-shot design
    where _build_ai_context()/_extract_date_range()/_mentioned_device() tried
    to guess what the question needed *before* the model ever saw it. Now the
    model itself (which actually understands language, unlike a fixed regex
    list) decides what to look up and with what parameters, by calling one of
    _AI_TOOLS; each tool independently re-checks RBAC before touching data
    (see each _tool_*() function) — the model is never trusted to have only
    asked about things it's already allowed to see.

    Each round is a plain non-streaming call (_llm_chat_once): if the model
    asks for tools, they're run locally and the results fed back in, looping
    (bounded by max_rounds, so a model that never converges can't loop
    forever). Once a round returns plain content with no more tool calls,
    that's the final answer — chunked into small pieces and yielded as text
    deltas so the browser's existing streaming UI needs no changes, even
    though the full text was already generated in one non-streaming call."""
    for _ in range(max_rounds):
        choice = _llm_chat_once(messages, tools=_AI_TOOLS)
        message = choice.get("message") or {}
        tool_calls = message.get("tool_calls")
        if not tool_calls:
            content = message.get("content") or ""
            words = content.split(" ")
            for i in range(0, len(words), 3):
                piece = " ".join(words[i:i + 3])
                yield piece + (" " if i + 3 < len(words) else "")
            if choice.get("finish_reason") == "length":
                # Confirmed to happen silently otherwise — a response cut off
                # mid-sentence with a clean HTTP 200, nothing distinguishing
                # it from a complete answer.
                yield "\n\n*(That answer was cut short by a length limit — ask a narrower question, or ask Goby to continue.)*"
            return
        messages.append(message)
        for call in tool_calls:
            fn_name = call["function"]["name"]
            try:
                fn_args = json.loads(call["function"].get("arguments") or "{}")
            except ValueError:
                fn_args = {}
            handler = _AI_TOOL_DISPATCH.get(fn_name)
            if not handler:
                result = {"error": f"unknown tool '{fn_name}'"}
            else:
                try:
                    result = handler(fn_args)
                except Exception:
                    # A handful of tools do an unguarded int()/datetime.strptime()
                    # on a model-supplied argument (limit, days, start_date) —
                    # a malformed one previously propagated all the way up
                    # through this generator and killed the WHOLE turn with a
                    # generic "Goby hit an unexpected error", even though every
                    # other tool call this round might have succeeded fine.
                    # One bad argument should degrade to a per-tool error the
                    # model can see and react to (retry without it, or say it
                    # can't do that), not abort the entire answer.
                    logging.exception("Ask Goby tool '%s' raised with args=%s", fn_name, fn_args)
                    result = {"error": "that request couldn't be processed — try different or fewer parameters"}
            log_activity("ai.tool_call", target=fn_name, detail=f"args={json.dumps(fn_args, default=str)}")
            messages.append({
                "role": "tool", "tool_call_id": call["id"],
                "content": json.dumps(result, default=str),
            })
    yield "I wasn't able to finish gathering that information — try a narrower question."


_METERS_PER_MILE = 1609.344


def _haversine_meters(lat1, lon1, lat2, lon2) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlambda / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _load_geodata():
    """Loads the vendored GeoNames city/country reference data once at import
    time (same philosophy as the locally-vendored Leaflet assets — no network
    call, works identically in dev and air-gapped prod). Returns (cities,
    countries) where cities is a list of (lat, lon, name, country_code,
    admin1_name) tuples and countries maps code -> full name; both empty if
    the files aren't present, so a deployment without them just never gets
    place names rather than crashing (GEODATA_DIR's files are a few MB, not
    something every deploy is guaranteed to have copied over yet). admin1
    (state/province/governorate — whatever a country's top subdivision is
    called) is resolved deterministically from GeoNames data at vendoring
    time, same as the city/country names themselves — never left for the
    model to guess, which is exactly what went wrong before this column
    existed (see the Ask Goby section in CLAUDE.md)."""
    cities, countries = [], {}
    countries_path = os.path.join(GEODATA_DIR, "countries.csv")
    cities_path = os.path.join(GEODATA_DIR, "cities.csv")
    try:
        with open(countries_path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                countries[row["code"]] = row["name"]
        with open(cities_path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                cities.append((
                    float(row["lat"]), float(row["lon"]), row["name"],
                    row["country"], row.get("admin1") or "",
                    int(row.get("population") or 0),
                ))
        logging.info("Loaded geodata: %d cities, %d countries", len(cities), len(countries))
    except (FileNotFoundError, ValueError, KeyError):
        logging.warning("Geodata not found/invalid at %s — Ask AI will fall back to raw coordinates", GEODATA_DIR)
    return cities, countries


_GEO_CITIES, _GEO_COUNTRIES = _load_geodata()

# A "major" city is one big enough to be a recognizable reference point even
# if it's not the literal nearest place — e.g. Tampa (pop. ~415k) vs. the
# actually-nearer Gibsonton (pop. ~14k). ~9% of the vendored dataset clears
# this bar. Only mentioned as secondary context within this radius — beyond
# it, "N hundred miles from the nearest big city" isn't meaningfully useful,
# just noise.
_MAJOR_CITY_POPULATION = 100_000
_MAJOR_CITY_MAX_RADIUS_MILES = 75


def _place_label(name, admin1, country):
    return f"{name}, {admin1}, {country}" if admin1 else f"{name}, {country}"


def _nearest_place(lat, lon):
    """Nearest known city to (lat, lon) from the vendored dataset, or None if
    no geodata is loaded. A linear scan over ~70k rows is a few milliseconds
    in Python — fine for an occasional per-question lookup, not worth a
    spatial index for this access pattern. `admin1` is "" for places with no
    such subdivision (city-states like Singapore) or if an older cities.csv
    without the column is ever loaded — always a real field, never absent,
    so callers don't need a .get() with a default.

    Also finds the nearest *major* city in the same country (see
    _MAJOR_CITY_POPULATION) and folds it into `label` as secondary context
    when it's a genuinely different, reasonably-nearby place — confirmed
    live that the literal nearest city can be a small, unrecognizable town
    (Gibsonton) while a much more useful reference point (Tampa) is only
    slightly farther; reporting only the literal nearest was technically
    correct but not what a person actually wants to hear. Deliberately
    same-country only, a second pass once the primary country is known —
    the unrestricted version once suggested a Canadian device was "3.4 miles
    from Buffalo, United States" (true, but crossing a border for a
    reference point isn't something to do implicitly in an app where which
    country a device is in can itself be operationally significant)."""
    if not _GEO_CITIES:
        return None
    best, best_dist = None, None
    for city_lat, city_lon, name, cc, admin1, population in _GEO_CITIES:
        d = _haversine_meters(lat, lon, city_lat, city_lon)
        if best_dist is None or d < best_dist:
            best, best_dist = (name, cc, admin1), d
    name, cc, admin1 = best
    country = _GEO_COUNTRIES.get(cc, cc)
    best_major, best_major_dist = None, None
    for city_lat, city_lon, major_name, major_cc, major_admin1, population in _GEO_CITIES:
        if major_cc != cc or population < _MAJOR_CITY_POPULATION:
            continue
        d = _haversine_meters(lat, lon, city_lat, city_lon)
        if best_major_dist is None or d < best_major_dist:
            best_major, best_major_dist = (major_name, major_cc, major_admin1), d
    distance_miles = round(best_dist / _METERS_PER_MILE, 1)
    # A complete, ready-to-insert phrase — including the "about N miles
    # from" lead-in, not just the place name — not left for the model to
    # assemble from the separate fields below or to decide where the
    # distance goes relative to the secondary city. Confirmed live that
    # leaving any assembly to the model isn't reliable: it dropped the state
    # once, then reordered the primary distance and the secondary city
    # another time. A single field it's told to insert as one unit leaves
    # it nothing left to decide.
    label = f"about {distance_miles} miles from {_place_label(name, admin1, country)}"
    if best_major and best_major[0] != name:
        major_distance_miles = round(best_major_dist / _METERS_PER_MILE, 1)
        if major_distance_miles <= _MAJOR_CITY_MAX_RADIUS_MILES:
            major_name, major_cc, major_admin1 = best_major
            major_country = _GEO_COUNTRIES.get(major_cc, major_cc)
            label += f" (~{major_distance_miles} miles from {_place_label(major_name, major_admin1, major_country)})"
    return {
        "label": label,
        "name": name,
        "admin1": admin1,
        "country": country,
        "distance_miles": distance_miles,
    }


def _position_snapshot(pt) -> dict:
    """A single observation row as a position fact for the AI — timestamp
    plus the resolved nearest place, NEVER raw lat/lon. Same no-raw-
    coordinates rule as every other tool-facing location field in this file
    (_exact_location_lookup() is the only function allowed to produce real
    coordinates, and only _try_exact_location_shortcut() may call it,
    entirely outside the model/tool-calling pipeline) — enforced here at the
    source rather than left to whichever caller happens to strip lat/lon
    back out afterward, so a future caller of _device_insight(deep=True)
    can't accidentally leak coordinates by forgetting to."""
    snap = {"obs_time": pt["obs_time"]}
    near = _nearest_place(pt["lat"], pt["lon"])
    if near:
        snap["near"] = near
    return snap


def _parse_obs_time(s):
    if not s:
        return None
    try:
        return datetime.strptime(s.strip().rstrip(";").strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _device_cadence(uuid: str) -> dict:
    """Cadence baseline + staleness relative to the device's OWN typical
    reporting rate — not a fixed global threshold, which would mean nothing
    across devices with different normal cadences. Cheap (one bounded query),
    so it's computed for every visible device in _fleet_digest(), not just a
    named one — otherwise the model is left guessing what counts as 'stale'
    for a device it has no baseline for."""
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT obs_time FROM observations WHERE uuid = ? ORDER BY obs_time DESC LIMIT 50",
            (uuid,),
        ).fetchall()
    cadence: dict = {}
    times = [t for t in (_parse_obs_time(r["obs_time"]) for r in rows) if t]
    if len(times) >= 2:
        gaps = sorted((times[i] - times[i + 1]).total_seconds() for i in range(len(times) - 1))
        median_gap = gaps[len(gaps) // 2]
        since_last = (datetime.now(timezone.utc).replace(tzinfo=None) - times[0]).total_seconds()
        cadence["typical_fix_interval_minutes"] = round(median_gap / 60, 1)
        cadence["minutes_since_last_fix"] = round(since_last / 60, 1)
        if median_gap > 0 and since_last / median_gap > 3:
            cadence["staleness"] = (
                f"quiet {round(since_last / median_gap, 1)}x longer than its usual "
                f"~{round(median_gap / 60, 1)} min reporting cadence"
            )
        else:
            cadence["staleness"] = "reporting normally"
    else:
        cadence["staleness"] = "not enough history to establish a baseline"
    return cadence


def _plan_start_date(uuid: str) -> str | None:
    """Raw YYYY-MM-DD start_date of the device's CURRENT Smart Tracking plan,
    or None if it has no active plan. The same lifecycle boundary
    _compute_plan_status()'s closest-approach calc and index.html's
    getVisiblePoints() already use to keep a reused device's prior
    assignment's track out of the new plan — distance/movement tools below
    need the identical clamp, confirmed missing from both after a real,
    reported case: asked for a device's "latest update," Goby reported
    distance traveled over the full requested window even though the device
    had an active plan that started partway through it, double-counting
    travel from before the current plan began. Returned as a raw string
    (not parsed into a datetime) so it can be compared directly against
    obs_time/other YYYY-MM-DD[ HH:MM:SS] strings — same string-comparison
    approach _compute_plan_status() already relies on, since this format
    sorts correctly as plain text."""
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute("SELECT start_date FROM device_plans WHERE uuid = ?", (uuid,)).fetchone()
    return row[0] if row and row[0] else None


def _device_recent_distance(uuid: str, days: int | None = 30):
    """Total distance traveled in the last `days` days — cheap (one bounded
    query, same 30-day default as the dashboard's own track window) and
    computed for EVERY visible device in _fleet_digest(), not just one a
    question happens to name. `days=None` means all-time, no filter at all —
    `list_devices`'s `days` argument lets the model pass the actual period
    asked about ("last 99 days", "all-time") instead of being stuck with a
    fixed 30, closing a real gap: a fleet-wide question naming a different
    period than 30 days previously had no way to get anything but the
    hardcoded default.

    This closes a separate, earlier confirmed hallucination too: a fleet-wide
    question ("give me a summary of distance traveled of all devices") with
    no single device named left _mentioned_device() matching nothing and no
    distance data computed for ANYTHING — the model fabricated four specific,
    plausible-looking numbers anyway (two devices sharing an identical
    "2058.02 miles", and "0 miles" for a device that has actually traveled
    ~2817 miles), rather than saying it didn't have the data. The fix is
    structural, not a stronger prompt instruction: give every device a real
    number to draw from for exactly this question shape, since an explicit
    "never invent statistics" instruction alone isn't reliable enough against
    a small model when the alternative is an empty field.

    If the device has an active Smart Tracking plan whose start_date is
    LATER than the requested window's own start, the plan's start_date wins —
    see _plan_start_date(). Returns (distance_miles, clamped_to) where
    clamped_to is the plan's start_date string when the clamp actually
    narrowed the window, else None (no plan, or the plan started before the
    requested window anyway, in which case there's nothing to call out)."""
    plan_start = _plan_start_date(uuid)
    days_cutoff = None
    if days is not None:
        days_cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    clamped_to = plan_start if (plan_start and (days_cutoff is None or plan_start > days_cutoff[:10])) else None
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        if clamped_to:
            pts = con.execute(
                "SELECT lat, lon FROM observations WHERE uuid = ? AND obs_time >= ? ORDER BY obs_time",
                (uuid, clamped_to),
            ).fetchall()
        elif days is not None:
            pts = con.execute(
                "SELECT lat, lon FROM observations WHERE uuid = ? AND obs_time >= datetime('now', ?) ORDER BY obs_time",
                (uuid, f"-{days} days"),
            ).fetchall()
        else:
            pts = con.execute(
                "SELECT lat, lon FROM observations WHERE uuid = ? ORDER BY obs_time", (uuid,)
            ).fetchall()
    if len(pts) < 2:
        return None, clamped_to
    total = sum(_haversine_meters(pts[i - 1]["lat"], pts[i - 1]["lon"], pts[i]["lat"], pts[i]["lon"])
                for i in range(1, len(pts)))
    return round(total / _METERS_PER_MILE, 2), clamped_to


def _device_signal_quality(uuid: str) -> dict:
    """Average confidence/accuracy across all of a device's fixes — added
    after a confirmed real gap: asked "which device has the highest average
    confidence level?", the model correctly said it had no such metric,
    because no tool exposed it, even though `confidence`/`accuracy` are real
    columns on every observation row (and already shown per-fix on the
    regular dashboard's device cards — `_fleet_digest()` just never surfaced
    the aggregate). One cheap AVG() query, same always-included philosophy as
    distance_last_30_days_miles, so a fleet-wide comparison question has a
    real number for every device without needing a new dedicated tool."""
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute(
            "SELECT AVG(confidence), AVG(accuracy) FROM observations WHERE uuid = ?", (uuid,)
        ).fetchone()
    return {
        "avg_confidence": round(row[0], 2) if row[0] is not None else None,
        "avg_accuracy": round(row[1], 2) if row[1] is not None else None,
    }


_ISO_DATE_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
# Signals that a lone date should mean "through now", not just that one day:
# either a leading since/from/after, or a trailing "to <something open-ended>"
# — confirmed necessary live: "between 2026-09-15 to last updated" has neither
# "since" nor "from" immediately by the date, so the original since/from/after
# check alone left it defaulting to a single day (2026-09-15 only), when the
# question clearly meant "from that date through whatever's most recent."
_OPEN_ENDED_DATE_RE = re.compile(
    r"\b(since|from|after)\b|\bto\s+(now|today|present|the\s+latest|last\s+updat\w*|current\w*)\b"
)


def _extract_date_range(question: str):
    """Best-effort date-range extraction so 'how far did it travel between X
    and Y' / 'yesterday' / 'last 3 days' scope the movement calculation to
    that window instead of always using full history. Two explicit YYYY-MM-DD
    dates define an exact range; a single one means "since that date, through
    now" (not just that one calendar day) — this is how it's actually phrased
    in practice ("since/from/after X", "X to today") and defaulting to a
    single day caused a real, confirmed failure: a device's data started
    2026-09-08, "how far did it travel since 2026-09-01?" was treated as just
    2026-09-01 itself (zero points, before the device existed), and the model
    truthfully but wrongly reported no data — even though "since 2026-09-01
    through now" covers the device's entire 1,610-point history. A handful of
    common relative phrases cover the rest — same lightweight heuristic
    philosophy as _mentioned_device(), not a full date-parsing library.
    Returns (query_start, query_end, label) or None if the question doesn't
    name a range (caller falls back to all history). `label` is a ready-to-use,
    human-phrased description of the range — generated here rather than
    reconstructed from query_start/end later, because query_end is an
    exclusive boundary (end-of-day midnight) for a day-granularity range,
    which reads as confusingly off-by-one if shown to the model/user directly
    (observed: a small model given "2026-09-28 00:00 to 2026-09-30 00:00" for
    a "between the 28th and 29th" question concluded the window didn't match
    and refused to answer at all)."""
    q = question.lower()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    iso_dates = _ISO_DATE_RE.findall(question)
    if len(iso_dates) >= 2:
        d1, d2 = sorted(iso_dates[:2])
        start, end = datetime.strptime(d1, "%Y-%m-%d"), datetime.strptime(d2, "%Y-%m-%d")
        return start, end + timedelta(days=1), f"{d1} to {d2} (inclusive)"
    if len(iso_dates) == 1:
        start = datetime.strptime(iso_dates[0], "%Y-%m-%d")
        # "since/from/after X" is open-ended to now; a bare "on X" / "where was
        # it on X" means just that single day — these are genuinely different
        # questions (distance traveled vs. a point-in-time position) and both
        # use a single bare date, so the surrounding wording is the only signal
        # available. Defaulting a bare date to "since...now" (as an earlier fix
        # did, to handle the "since" case) broke the other one: "where was test
        # located on 2026-09-10?" resolved to a 3-week window instead of that
        # one day, and since movement insight only ever returns distance
        # aggregates anyway (see first_position/last_position below for the
        # actual fix to that), the model correctly reported it had no exact
        # position for that date — confirmed against a real failed query.
        if _OPEN_ENDED_DATE_RE.search(q):
            return start, now, f"{iso_dates[0]} through now"
        return start, start + timedelta(days=1), f"on {iso_dates[0]}"
    m = re.search(r"\b(?:last|past)\s+(\d+)\s+day", q)
    if m:
        days = int(m.group(1))
        return now - timedelta(days=days), now, f"the last {days} days (through now)"
    today_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if "yesterday" in q:
        return today_midnight - timedelta(days=1), today_midnight, "yesterday"
    if "today" in q:
        return today_midnight, now, "today (through now)"
    if "last week" in q or "this week" in q:
        return now - timedelta(days=7), now, "the last 7 days (through now)"
    if "last month" in q or "this month" in q:
        return now - timedelta(days=30), now, "the last 30 days (through now)"
    return None


def _device_insight(uuid: str, deep: bool = False, date_range=None) -> dict:
    """Computed facts about one visible device — the cadence baseline (see
    _device_cadence()) plus, when deep=True, a movement/dwell summary over
    `date_range` (start, end) if given, else all available history. Caller
    must have already confirmed the device is visible to this session.

    Same plan-start clamp as _device_recent_distance() (see
    _plan_start_date()) — this was the OTHER confirmed gap from the same
    report: compute_distance's "all available history" default was an even
    bigger version of the bug, since with no date named at all it would
    count a reused device's ENTIRE prior assignment's travel, not just a
    30-day slice of it."""
    insight = _device_cadence(uuid)
    plan_start = _plan_start_date(uuid)
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        labels = con.execute(
            "SELECT * FROM device_labels WHERE uuid = ? ORDER BY created_at", (uuid,)
        ).fetchall()
        insight["labels"] = [r["text"] for r in labels if _label_accessible(con, r, uuid)][:10]
        pts = None
        if deep:
            if date_range:
                start, end, label = date_range
                plan_start_dt = datetime.strptime(plan_start, "%Y-%m-%d") if plan_start else None
                # Only clamp when the requested window actually extends INTO
                # the plan (plan_start falls strictly within [start, end)) —
                # if the whole window predates the plan, the user explicitly
                # named a historical range and is asking a real "what
                # happened back then" question, not a "since the current
                # plan" one; clamping start past end here would silently
                # invert the range into an empty result instead of
                # answering the real question. Compared as real datetimes,
                # not string prefixes — `end` is an EXCLUSIVE boundary (the
                # day AFTER the actually-requested last day, see
                # _tool_compute_distance), so slicing its date string would
                # wrongly count a plan starting exactly the day after the
                # requested range as "within" it.
                if plan_start_dt and start < plan_start_dt < end:
                    start = plan_start_dt
                    label += f" (clamped to plan start {plan_start} — the plan began partway through the requested window)"
                pts = con.execute(
                    "SELECT lat, lon, obs_time FROM observations WHERE uuid = ? AND obs_time BETWEEN ? AND ? ORDER BY obs_time",
                    (uuid, start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S")),
                ).fetchall()
                insight["movement_window"] = label
            elif plan_start:
                pts = con.execute(
                    "SELECT lat, lon, obs_time FROM observations WHERE uuid = ? AND obs_time >= ? ORDER BY obs_time",
                    (uuid, plan_start),
                ).fetchall()
                insight["movement_window"] = f"since plan start {plan_start} (no date named, and device has an active plan — not all-time)"
            else:
                pts = con.execute(
                    "SELECT lat, lon, obs_time FROM observations WHERE uuid = ? ORDER BY obs_time",
                    (uuid,),
                ).fetchall()
                insight["movement_window"] = "all available history"

    if deep:
        if pts:
            # Actual position data was missing entirely before this — the
            # movement block below only ever returns aggregate distance
            # stats, never a real lat/lon, so a question like "where was it
            # on 2026-09-10?" had nothing to answer from even when the date
            # window resolved correctly and 105 real fixes existed for that
            # day (confirmed from a real failed query). first/last position
            # within whatever window was resolved covers both "where was it
            # on this single day" (first == near last for a narrow window)
            # and "where did it start/end up over this range".
            insight["first_position"] = _position_snapshot(pts[0])
            insight["last_position"] = _position_snapshot(pts[-1])
        if pts and len(pts) >= 2:
            total_distance = 0.0
            stops = 0
            longest_dwell_minutes = 0.0
            cluster_anchor, cluster_start = pts[0], _parse_obs_time(pts[0]["obs_time"])
            for i in range(1, len(pts)):
                total_distance += _haversine_meters(pts[i - 1]["lat"], pts[i - 1]["lon"], pts[i]["lat"], pts[i]["lon"])
                moved = _haversine_meters(cluster_anchor["lat"], cluster_anchor["lon"], pts[i]["lat"], pts[i]["lon"])
                if moved > 50:
                    t_prev = _parse_obs_time(pts[i - 1]["obs_time"])
                    if cluster_start and t_prev:
                        dwell = (t_prev - cluster_start).total_seconds() / 60
                        if dwell > 5:
                            stops += 1
                            longest_dwell_minutes = max(longest_dwell_minutes, dwell)
                    cluster_anchor, cluster_start = pts[i], _parse_obs_time(pts[i]["obs_time"])
            displacement = _haversine_meters(pts[0]["lat"], pts[0]["lon"], pts[-1]["lat"], pts[-1]["lon"])
            insight["movement"] = {
                "total_distance_miles": round(total_distance / _METERS_PER_MILE, 2),
                "straight_line_miles": round(displacement / _METERS_PER_MILE, 2),
                "stop_count": stops,
                "longest_dwell_minutes": round(longest_dwell_minutes, 1),
            }
        else:
            # Explicit "don't know" rather than silently omitting the key —
            # otherwise the model has no signal and might guess at a distance.
            insight["movement"] = "not enough recorded positions in that window to compute distance"
    return insight


def _fleet_digest(days: int | None = 30) -> dict:
    """Roll-up across every device visible to the current session — cheap
    (cadence and recent-distance are each one bounded query per device, no
    full-history movement/dwell math). Each device's own cadence baseline is
    included (not just a raw last-seen timestamp) so 'which devices haven't
    reported recently' has a real per-device basis for 'recently' instead of
    the model guessing at an arbitrary global threshold. `near` (nearest
    known city, via the vendored offline geodata — see _nearest_place()) is
    the ONLY location info here — raw lat/lon is deliberately never included
    anywhere the model can see it; exact coordinates are answered by
    _try_exact_location_shortcut() straight from the database, without ever
    involving the model, specifically so real coordinates can never be sent
    to an external LLM API regardless of which one is configured.

    `days` (default 30, `None` for all-time) is passed straight through from
    `_tool_list_devices`'s own `days` argument — a fleet-wide distance window
    used to be a hardcoded 30 with no way to ask for anything else; now the
    model can request "the last 99 days" or all-time, same as it already
    could for a single device via compute_distance. Field names are generic
    (`distance_miles`, not `distance_last_30_days_miles`) with a separate
    `distance_window` label stating the actual window used, so a renamed/
    reused field can never silently drift out of sync with what window it
    actually covers — same self-documenting-field philosophy as everywhere
    else distances appear, just via a sibling field instead of baking the
    number into the name (which would need the field renamed every time the
    window changes, i.e. on every call)."""
    devices = _visible_devices()
    by_group: dict[str, int] = {}
    summary = []
    for d in devices:
        by_group[d["group_name"]] = by_group.get(d["group_name"], 0) + 1
        distance_miles, clamped_to = _device_recent_distance(d["uuid"], days=days)
        entry = {
            "name": d["name"], "uuid": d["uuid"], "group": d["group_name"],
            "fix_count": d["fix_count"], "last_seen": d["last_seen"],
            "distance_miles": distance_miles,
            **_device_cadence(d["uuid"]),
            **_device_signal_quality(d["uuid"]),
            # Already computed by _visible_devices() itself — zero extra
            # cost here. null means no Smart Tracking plan exists for this
            # device; call get_plan_status for the full destination/ETA
            # detail behind a non-null value.
            "plan_status": d["plan_status"],
        }
        # Per-device override of the fleet-wide distance_window below — set
        # only when this device's plan start_date actually narrowed its own
        # distance_miles below the requested window, so the model doesn't
        # misreport a clamped number under the broader fleet label.
        if clamped_to:
            entry["distance_window"] = f"since plan start {clamped_to} (narrower than the requested window below)"
        if d.get("fix_count_window"):
            entry["fix_count_window"] = d["fix_count_window"]
        near = _nearest_place(d["lat"], d["lon"])
        if near:
            entry["near"] = near
        summary.append(entry)
    # Pre-summed so the model never has to add the per-device figures itself —
    # small models are unreliable at multi-step arithmetic (confirmed: asked
    # for "a summary of distance traveled of all devices", it reported a
    # single total that didn't match the sum of the very numbers it was given).
    total_distance = sum(e["distance_miles"] or 0 for e in summary)
    window_label = f"last {days} days" if days is not None else "all-time"
    shown = summary[:50]
    result = {
        "device_count": len(devices), "devices_by_group": by_group,
        "distance_window": window_label,
        "fleet_total_distance_miles": round(total_distance, 2),
        "devices": shown,
    }
    # Previously silent: device_count/fleet_total_distance_miles already
    # reflect every visible device, but "devices" itself was truncated with
    # zero signal — a fleet with >50 visible devices would answer "list all
    # devices" (or "which traveled farthest") from only the first 50 by
    # last_seen, possibly missing the actual answer, with nothing telling
    # the model its view was incomplete.
    if len(shown) < len(devices):
        result["note"] = (
            f"Only the {len(shown)} most recently-seen of {len(devices)} total visible devices "
            f"are listed below — device_count and fleet_total_distance_miles above still reflect "
            f"ALL {len(devices)}. Say so if asked to list/compare every device."
        )
    return result


def _mentioned_device(messages: list[dict], visible_devices: list[dict]):
    """Simple name/uuid substring match — decides whether to compute one
    device's full insight (deep) or leave it at the cheap fleet roll-up. Not a
    rigid intent classifier; just bounds how much a single question costs.

    Searches backward from the most recent message, not just the latest one —
    a natural follow-up often doesn't repeat the device name (confirmed by a
    real failure: "How far did test travel since 2026-09-01?" named it, but
    the next turn, "what about since 2026-09-14 to today", didn't — and with
    only the latest message checked, that follow-up got no device match at
    all, so no movement data was ever computed for it to answer from, even
    though the fleet digest's cadence data for every device was right there).
    Stops at the first message (scanning newest-first) that names a device,
    so the most recently discussed one wins if more than one has come up."""
    for msg in reversed(messages):
        content = (msg.get("content") or "").lower()
        for d in visible_devices:
            if (d["name"] and d["name"].lower() in content) or (d["uuid"] and d["uuid"].lower() in content):
                return d
    return None


_AI_SYSTEM_PROMPT = (
    "You are an assistant embedded in a BLE device tracking dashboard, answering "
    "questions for the person using it about the devices they can see. You have "
    "NO information about any device, label, or activity yet — you must call one "
    "of the provided tools to look up real data before answering anything "
    "specific. Never invent device names, positions, label text, plan/destination "
    "details, or statistics — only state what a tool actually returned. For "
    "get_plan_status and get_plan_history specifically: 'destination_radius_miles' "
    "(the plan's own declared proximity radius) and 'destination_near.distance_miles' "
    "(how far the nearest known city is FROM that destination) are two different numbers "
    "that happen to both be in miles — never conflate them or imply one when "
    "asked for the other. If a tool returns an error (e.g. "
    "device not found) or an empty result, say so in plain terms, the way a "
    "knowledgeable assistant would — never refer to 'the tool', 'the function', "
    "'the JSON', or any other internal/technical term for how you got the "
    "information; the person you're talking to has no idea that's how it works. "
    "None of the tools return exact GPS coordinates — only an approximate "
    "nearest place name and distance — so if asked for exact/precise "
    "coordinates, say plainly that you can give an approximate location but not "
    "exact coordinates through these tools. Whenever a tool's result includes "
    "a 'near' object, its 'label' field is a COMPLETE, ready-made phrase "
    "already including the distance and the 'about N miles from' wording — "
    "insert it into your sentence AS ONE WHOLE UNIT, in that exact order, "
    "every time you "
    "state a place — e.g. 'about 3.4 miles from Dover, Delaware, United "
    "States' or 'about 6.4 miles from Gibsonton, Florida, United States "
    "(~7.2 miles from Tampa, Florida, United States)'. Never shorten it, "
    "drop any part of it (the state, or the parenthetical secondary city "
    "when present), reorder its pieces, restate the distance again yourself "
    "before or after it, reconstruct your own version from the other near.* "
    "fields (name/admin1/country/distance_miles — those exist only for your "
    "own reference, never for you to re-assemble into text), or add a "
    "state/region that isn't already in it — there are multiple real places "
    "with the same name in different states/countries, e.g. several "
    "'Dover's across different US states, and 'label' already resolves that "
    "correctly; adding your own guess on top is inventing information just "
    "as much as inventing a position or statistic would be. "
    "Write in plain, natural prose for a "
    "human reader — never quote field names (e.g. say 'last reported 3 hours "
    "ago', not 'minutes_since_last_fix is 180') and never show raw JSON. All "
    "distances returned by tools are already in MILES — state them as miles, "
    "never kilometers, and never convert them yourself. When describing a "
    "device's location, phrase the nearest place as an approximation (e.g. "
    "'near', 'about N miles from'), never as if the device is exactly there. "
    "For a question about multiple or all devices, call list_devices. When a "
    "question names a relative period (e.g. 'last 30 days', 'the last 99 "
    "days', 'this week'), compute start_date/end_date for tool calls using "
    "the real current date given to you above — never estimate, assume, or "
    "fall back to your own sense of today's date, which will be wrong. "
    "Never add the per-device numbers yourself, you will get it wrong. "
    "Be concise and direct — EXCEPT for a near.label value, which must always "
    "be quoted completely, including any parenthetical secondary-city part "
    "(e.g. '(~7.2 miles from Tampa, Florida, United States)') — trimming it "
    "for brevity drops real information (a bigger, more recognizable "
    "reference point) just as much as dropping the state would."
)


def _resolve_device(name_or_uuid, visible_devices: list[dict]):
    """Matches a model-supplied device argument against the devices this
    session can actually see — exact name/uuid match first, then a lenient
    substring fallback. Returns None if nothing matches, same as any other
    not-found case; callers must never fall back to assuming a device exists
    just because the model named one, since that name is untrusted model
    output, no different from user input."""
    needle = (name_or_uuid or "").strip().lower()
    if not needle:
        return None
    for d in visible_devices:
        if (d["name"] and d["name"].lower() == needle) or (d["uuid"] and d["uuid"].lower() == needle):
            return d
    for d in visible_devices:
        if d["name"] and needle in d["name"].lower():
            return d
    return None


def _resolve_user(name_or_username):
    """Matches a model-supplied person reference (for get_audit_log) against
    real accounts by username OR first+last display name — same spirit as
    _resolve_device(). Closes a confirmed real gap: asked "did Tho Pham log
    in", the model had no way to know that's the display name for username
    'tpham' — audit_log only ever stores the raw username, never
    first_name/last_name, so there was nothing to match against. Admin-only
    by construction: only called from _tool_get_audit_log(), which already
    checks session.get("is_admin") before this ever runs."""
    needle = (name_or_username or "").strip().lower()
    if not needle:
        return None
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("SELECT username, first_name, last_name FROM users").fetchall()
    for r in rows:
        if r["username"].lower() == needle:
            return r["username"]
    for r in rows:
        full = f"{r['first_name'] or ''} {r['last_name'] or ''}".strip().lower()
        if full and needle in full:
            return r["username"]
    return None


def _tool_list_devices(args: dict) -> dict:
    raw_days = args.get("days")
    # 0 explicitly means all-time; omitted/falsy means the 30-day default;
    # anything else is used as given — matches compute_distance's existing
    # start_date/end_date pattern of letting the model pass the real period
    # asked about rather than being stuck with one hardcoded window.
    days = None if raw_days == 0 else (int(raw_days) if raw_days else 30)
    return _fleet_digest(days=days)


def _tool_get_device_status(args: dict) -> dict:
    d = _resolve_device(args.get("device"), _visible_devices())
    if not d:
        return {"error": "device not found"}
    near = _nearest_place(d["lat"], d["lon"])
    result = {"name": d["name"], "uuid": d["uuid"], "group": d["group_name"],
              "fix_count": d["fix_count"], "last_seen": d["last_seen"],
              **_device_cadence(d["uuid"]), **_device_signal_quality(d["uuid"])}
    if near:
        result["near"] = near
    if d.get("fix_count_window"):
        result["fix_count_window"] = d["fix_count_window"]
    # Scoped to one device, so (unlike list_devices' fleet-wide digest) the
    # full plan detail is cheap enough to include directly rather than
    # making the model issue a separate get_plan_status call for something
    # this tool is already supposed to be the complete picture of.
    result["plan"] = _tool_get_plan_status({"device": d["uuid"]})
    return result


def _tool_compute_distance(args: dict) -> dict:
    d = _resolve_device(args.get("device"), _visible_devices())
    if not d:
        return {"error": "device not found"}
    date_range = None
    start_date, end_date = args.get("start_date"), args.get("end_date")
    if start_date or end_date:
        try:
            start = datetime.strptime(start_date, "%Y-%m-%d") if start_date else datetime.min
            end = (datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)) if end_date else \
                datetime.now(timezone.utc).replace(tzinfo=None)
        except ValueError:
            return {"error": "start_date/end_date must be in YYYY-MM-DD format"}
        date_range = (start, end, f"{start_date or 'the beginning'} to {end_date or 'now'}")
    insight = _device_insight(d["uuid"], deep=True, date_range=date_range)
    # No stripping needed here — _position_snapshot() (what first_position/
    # last_position already are) never includes raw lat/lon in the first
    # place. Exact coordinates are handled entirely outside the model — see
    # _try_exact_location_shortcut().
    return {"name": d["name"], "uuid": d["uuid"], **insight}


def _tool_search_labels(args: dict) -> dict:
    visible = _visible_devices()
    device_filter = args.get("device")
    if device_filter:
        d = _resolve_device(device_filter, visible)
        devices = [d] if d else []
    else:
        devices = visible
    keyword = (args.get("keyword") or "").lower()
    matches = []
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        for d in devices:
            labels = con.execute("SELECT * FROM device_labels WHERE uuid = ? ORDER BY created_at", (d["uuid"],)).fetchall()
            for label in labels:
                if not _label_accessible(con, label, d["uuid"]):
                    continue
                if keyword in label["text"].lower():
                    matches.append({"device": d["name"], "uuid": d["uuid"], "text": label["text"]})
    return {"matches": matches}


def _tool_get_plan_status(args: dict) -> dict:
    """Smart Tracking — reports a device's declared plan, if any, including
    its deterministically-computed status (see _compute_plan_status(): plain
    math/SQL, never the model). Narration only, same as every other tool:
    the model reports what this function already decided, it never does its
    own overdue/moving-away judgment from the raw ETA/position facts — see
    the system prompt's explicit instruction not to infer a status beyond
    what `status`/`is_overdue`/`is_moving_away` already say. RBAC is just
    _resolve_device() against _visible_devices(), same as every other
    device-scoped tool — plan visibility deliberately matches device
    visibility exactly, no separate check the way private labels need
    _label_accessible().

    Never returns dest_lat/dest_lon — same no-raw-coordinates rule as
    everywhere else. The destination is resolved through _nearest_place()
    (reusing the exact same reverse-geocoding and pre-composed `label` field
    used for live positions) into `destination_near`, which is a DIFFERENT
    distance than `destination_radius_miles`: the former is how far the
    nearest known city is FROM the destination's center point, the latter is
    the plan's own declared proximity radius — two unrelated numbers that
    happen to both be in miles, kept as clearly separate fields so they
    can't get conflated when narrated (the system prompt also calls this out
    explicitly)."""
    d = _resolve_device(args.get("device"), _visible_devices())
    if not d:
        return {"error": "device not found"}
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        row = con.execute("""
            SELECT dp.*, u.username AS created_by_username
            FROM device_plans dp LEFT JOIN users u ON u.id = dp.created_by
            WHERE dp.uuid = ?
        """, (d["uuid"],)).fetchone()
    if not row:
        return {"name": d["name"], "uuid": d["uuid"], "has_plan": False}
    return {
        "name": d["name"], "uuid": d["uuid"], "has_plan": True,
        "destination_radius_miles": row["radius_miles"],
        "destination_near": _nearest_place(row["dest_lat"], row["dest_lon"]),
        "start_date": row["start_date"], "eta_start": row["eta_start"], "eta_end": row["eta_end"],
        **_compute_plan_status(d["uuid"], row, d["lat"], d["lon"]),
        "declared_by": row["created_by_username"],
        "declared_at": row["created_at"], "last_updated_at": row["updated_at"],
    }


def _tool_get_plan_history(args: dict) -> dict:
    """Smart Tracking — a device's full plan change history (create/update/
    delete), never discarded even after the current plan is edited or
    removed — see device_plan_history. Same RBAC as get_plan_status:
    _resolve_device() against _visible_devices(), no separate check, since
    plan history visibility matches device visibility exactly like the live
    plan does. Never returns raw dest_lat/dest_lon to the model — same rule
    as every other location-adjacent tool — each entry's destination is
    resolved through _nearest_place() into the same destination_near/
    destination_radius_miles shape get_plan_status uses, so the two tools
    read consistently and the same distance-conflation warning in the
    system prompt applies to both."""
    d = _resolve_device(args.get("device"), _visible_devices())
    if not d:
        return {"error": "device not found"}
    limit = min(int(args.get("limit") or 10), 50)
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""
            SELECT h.*, u.username AS changed_by_username
            FROM device_plan_history h LEFT JOIN users u ON u.id = h.changed_by
            WHERE h.uuid = ? ORDER BY h.changed_at DESC LIMIT ?
        """, (d["uuid"], limit)).fetchall()
    entries = [{
        "action": r["action"], "outcome": r["outcome"],
        "destination_radius_miles": r["radius_miles"],
        "destination_near": _nearest_place(r["dest_lat"], r["dest_lon"]),
        "start_date": r["start_date"], "eta_start": r["eta_start"], "eta_end": r["eta_end"],
        "changed_by": r["changed_by_username"], "changed_at": r["changed_at"],
    } for r in rows]
    return {"name": d["name"], "uuid": d["uuid"], "entries": entries}


def _tool_get_audit_log(args: dict) -> dict:
    # Checked here, at the point of use — not a keyword-triggered guess like
    # the old design — so a non-admin's tool call is rejected outright
    # regardless of what the model asks for.
    if not session.get("is_admin"):
        return {"error": "admin privileges required"}
    limit = min(int(args.get("limit") or 50), 500)
    query = "SELECT ts, username, action, target, detail FROM audit_log WHERE 1=1"
    params = []
    if not session.get("is_super_admin"):
        # Same restriction as GET /api/admin/audit-log — the super admin's
        # own activity is visible only to itself, so a regular admin asking
        # Goby about it must get the same filtered view the Activity Log
        # page would show them, not an unfiltered one through a back door.
        query += " AND username NOT IN (SELECT username FROM users WHERE is_super_admin = 1)"
    username_filter = args.get("username")
    if username_filter:
        # Resolves a display name ("Tho Pham") to the real username audit_log
        # actually stores ("tpham") — audit_log has no first_name/last_name of
        # its own, so without this a person-name question silently matches
        # nothing. See _resolve_user().
        resolved = _resolve_user(username_filter)
        if not resolved:
            return {"error": f"no user matching '{username_filter}'"}
        query += " AND username = ?"
        params.append(resolved)
    action_filter = args.get("action")
    if action_filter:
        # Without this, a "who logged in" question pulls from a window that
        # includes every action type — confirmed live: ai.tool_call/ai.ask
        # rows from Ask Goby's own usage dominate a recent date range (20+18
        # of a 50-row window in one real test), crowding out the small
        # number of actual login rows even when the date range is correct.
        query += " AND action = ?"
        params.append(action_filter)
    start_date, end_date = args.get("start_date"), args.get("end_date")
    if start_date:
        # Validated the same way end_date already is below — previously
        # unvalidated, so a malformed date from the model (e.g. not
        # YYYY-MM-DD) would silently become a nonsensical string comparison
        # against `ts` instead of a clear error, returning wrong/empty rows
        # with no sign anything was off.
        try:
            datetime.strptime(start_date, "%Y-%m-%d")
        except ValueError:
            return {"error": "start_date must be in YYYY-MM-DD format"}
        query += " AND ts >= ?"
        params.append(start_date)
    if end_date:
        try:
            end_dt = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
        except ValueError:
            return {"error": "end_date must be in YYYY-MM-DD format"}
        query += " AND ts < ?"
        params.append(end_dt.strftime("%Y-%m-%d %H:%M:%S"))
    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(query, params).fetchall()
    return {"rows": [dict(r) for r in rows]}


def _tool_get_reporting_gaps(args: dict) -> dict:
    """Added after a confirmed real gap: asked "what's the second longest
    interval of 6ZG0P0?", the model correctly declined rather than guessing —
    get_device_status only ever exposed the median ("typical") gap and the
    current one, never the actual list of historical gaps, so there was
    nothing for it to answer from. This computes every real consecutive gap
    for a device and returns the largest N, oldest-history included (not
    bounded to recent fixes like _device_cadence's baseline, since 'second
    longest ever' needs the full history, not just a recent sample)."""
    d = _resolve_device(args.get("device"), _visible_devices())
    if not d:
        return {"error": "device not found"}
    limit = min(int(args.get("limit") or 5), 20)
    with sqlite3.connect(DB_PATH) as con:
        rows = con.execute(
            "SELECT obs_time FROM observations WHERE uuid = ? ORDER BY obs_time", (d["uuid"],)
        ).fetchall()
    times = [t for t in (_parse_obs_time(r[0]) for r in rows) if t]
    gaps = []
    for i in range(1, len(times)):
        gap_minutes = (times[i] - times[i - 1]).total_seconds() / 60
        gaps.append({
            "gap_minutes": round(gap_minutes, 1),
            "gap_hours": round(gap_minutes / 60, 1),
            "from": times[i - 1].strftime("%Y-%m-%d %H:%M:%S"),
            "to": times[i].strftime("%Y-%m-%d %H:%M:%S"),
        })
    gaps.sort(key=lambda g: g["gap_minutes"], reverse=True)
    return {"name": d["name"], "uuid": d["uuid"], "total_fixes": len(times),
            "largest_gaps": gaps[:limit]}


_AI_TOOL_DISPATCH = {
    "list_devices": _tool_list_devices,
    "get_device_status": _tool_get_device_status,
    "compute_distance": _tool_compute_distance,
    "search_labels": _tool_search_labels,
    "get_audit_log": _tool_get_audit_log,
    "get_reporting_gaps": _tool_get_reporting_gaps,
    "get_plan_status": _tool_get_plan_status,
    "get_plan_history": _tool_get_plan_history,
}

_AI_TOOLS = [
    {"type": "function", "function": {
        "name": "list_devices",
        "description": "List every device visible to the current user, with group, fix count, last-seen time, approximate location, cadence/staleness, average confidence/accuracy, distance traveled over a given window (plus a combined fleet total), and plan_status ('on_track'/'overdue'/'moving_away', or null if the device has no Smart Tracking plan). plan_status alone is already enough for 'which devices are overdue/on track/moving away' — only call get_plan_status for a device's actual destination/ETA detail. A device with an active plan never counts distance OR fix_count from before that plan's start_date, even if the requested window reaches further back — when this clamp actually narrows a device's own window below the one you asked for, that device's entry carries its own 'distance_window' and/or 'fix_count_window' field overriding the defaults; state that device's distance/fix count using its own window field, not the fleet-wide one.",
        "parameters": {"type": "object", "properties": {
            "days": {"type": "integer", "description": "How many days back to compute distance traveled over. Default 30 if omitted. Pass 0 for all-time."},
        }},
    }},
    {"type": "function", "function": {
        "name": "get_device_status",
        "description": "Fix count, cadence/staleness, average confidence/accuracy, approximate current location, and full Smart Tracking plan detail (destination, ETA, computed status) for one specific device — already includes everything get_plan_status would return for this device, under the 'plan' field (plan.has_plan is false if none exists), so there's no need to call get_plan_status separately after this for the same device. A device with an active plan never counts fix_count from before that plan's start_date — when that clamp applies, a 'fix_count_window' field states it explicitly.",
        "parameters": {"type": "object", "properties": {
            "device": {"type": "string", "description": "Device name or UUID"},
        }, "required": ["device"]},
    }},
    {"type": "function", "function": {
        "name": "compute_distance",
        "description": "Distance traveled, movement pattern, and dwell/stop time for one device, optionally within a date range. If the device has an active Smart Tracking plan, distance never counts from before that plan's start_date, even if start_date/'all-time' would otherwise reach further back — the response's movement_window field states the actual window used (it says so explicitly when the plan start clamped it), state that window rather than assuming the one requested.",
        "parameters": {"type": "object", "properties": {
            "device": {"type": "string", "description": "Device name or UUID"},
            "start_date": {"type": "string", "description": "ISO 8601 date, e.g. 2026-09-01. Omit for all-time."},
            "end_date": {"type": "string", "description": "ISO 8601 date. Omit to mean through now."},
        }, "required": ["device"]},
    }},
    {"type": "function", "function": {
        "name": "search_labels",
        "description": "Search label text across visible devices, optionally scoped to one device. Omit keyword to list all labels.",
        "parameters": {"type": "object", "properties": {
            "keyword": {"type": "string"},
            "device": {"type": "string", "description": "Optional — limit to one device's labels"},
        }},
    }},
    {"type": "function", "function": {
        "name": "get_audit_log",
        "description": "Administrative activity log (logins, admin changes, etc). Only works for admin users — returns an error for everyone else. This log records many unrelated action types, not just logins — always pass action='login' for any question about who logged in/last logged in, otherwise other activity (especially Ask Goby's own tool-call logging) can crowd real login events out of the row cap even within the right date range. Always pass start_date/end_date too when the question names a time period (e.g. 'last 7 days', 'last 30 days') rather than relying on limit alone. Use username to scope to one person — pass whatever name or username form the question used (e.g. 'Tho Pham' or 'tpham'); it is resolved against real accounts automatically.",
        "parameters": {"type": "object", "properties": {
            "limit": {"type": "integer", "description": "Max rows to return, default 50, capped at 500"},
            "username": {"type": "string", "description": "Optional — a person's display name or username to filter to, e.g. 'Tho Pham' or 'tpham'"},
            "action": {"type": "string", "description": "Optional — exact action type to filter to. Use 'login' for login-history questions. Every other real value this system logs: logout, login_failed, password_change, user.create, user.update, user.password_reset, user.delete, group.create, group.update, group.delete, group_code.create, group_code.delete, device.archive, device.unarchive, device.access_update, device.export, device.backup, device.delete, plan.create, plan.update, plan.delete, label.create, label.update, label.delete, ai.ask, ai.tool_call, ai.enabled_toggle, ai.history_clear, schema_version.change, app_version.change."},
            "start_date": {"type": "string", "description": "Optional — YYYY-MM-DD, inclusive start of the date range"},
            "end_date": {"type": "string", "description": "Optional — YYYY-MM-DD, inclusive end of the date range"},
        }},
    }},
    {"type": "function", "function": {
        "name": "get_reporting_gaps",
        "description": "The largest historical gaps (in minutes) between consecutive fixes for one device, across its entire history — e.g. for questions about the longest, second-longest, or N largest reporting gaps it has ever had. Different from get_device_status, which only gives the typical/median gap and the current one, not historical outliers.",
        "parameters": {"type": "object", "properties": {
            "device": {"type": "string", "description": "Device name or UUID"},
            "limit": {"type": "integer", "description": "How many of the largest gaps to return, default 5"},
        }, "required": ["device"]},
    }},
    {"type": "function", "function": {
        "name": "get_plan_status",
        "description": "A device's declared Smart Tracking plan, if any — its destination (as an approximate place + proximity radius, never exact coordinates), start_date (when the plan began), ETA window, and computed status. Use for any question about a device's plan, destination, when its plan started, where it's headed, when it's expected, or whether it's on track/overdue/moving away. has_plan is false if no plan was ever declared for this device — say so plainly, don't treat that as an error. The 'status' field ('on_track'/'overdue'/'moving_away') plus 'is_overdue'/'is_moving_away' are already fully computed — always use these directly, never compute your own overdue/on-track judgment from eta_start/eta_end and today's date, and never describe a status this tool didn't return (e.g. don't say 'moving away' unless is_moving_away is true).",
        "parameters": {"type": "object", "properties": {
            "device": {"type": "string", "description": "Device name or UUID"},
        }, "required": ["device"]},
    }},
    {"type": "function", "function": {
        "name": "get_plan_history",
        "description": "A device's full Smart Tracking plan change history — every past create/update/delete, newest first, including entries for a plan that was later edited or removed (device_plans itself only ever holds the CURRENT plan; this is the only way to answer 'what was this device's previous destination/plan'). A 'deleted' entry's 'outcome' field says why it ended: 'arrived' (manually marked as reaching its destination), 'cancelled' (ended some other way), or null (an older entry from before this distinction existed, or a plan still active — a 'created'/'updated' row is never an ending at all). Use for any question about a device's past plans, previous destinations, whether a past plan was completed vs. cancelled, or how its plan has changed over time — NOT for its current plan (use get_plan_status for that). Each entry's destination is resolved the same way as get_plan_status (approximate place + radius, never exact coordinates).",
        "parameters": {"type": "object", "properties": {
            "device": {"type": "string", "description": "Device name or UUID"},
            "limit": {"type": "integer", "description": "Max entries to return, default 10, capped at 50"},
        }, "required": ["device"]},
    }},
]

_EXACT_LOCATION_RE = re.compile(
    r"\b(exact|precise|specific)\s+(location|position|coordinates?|gps)\b"
    r"|\bgps\s+coordinates?\b"
    r"|\blat(?:itude)?\s*(?:and|/|,)?\s*lon(?:gitude)?\b"
)


def _exact_location_lookup(uuid: str, date_range=None):
    """Raw lat/lon straight from the database. This is the ONLY function in
    the entire AI assistant pipeline allowed to produce exact coordinates,
    and it is never exposed to the model as a tool — see
    _try_exact_location_shortcut(), which calls this directly and answers
    without any LLM involvement at all, so real coordinates can never be
    sent to an external API regardless of which one is configured."""
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        if date_range:
            start, end, _ = date_range
            row = con.execute(
                "SELECT lat, lon, obs_time FROM observations WHERE uuid = ? AND obs_time BETWEEN ? AND ? "
                "ORDER BY obs_time DESC LIMIT 1",
                (uuid, start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S")),
            ).fetchone()
        else:
            row = con.execute(
                "SELECT lat, lon, obs_time FROM observations WHERE uuid = ? ORDER BY obs_time DESC LIMIT 1",
                (uuid,),
            ).fetchone()
    return dict(row) if row else None


def _try_exact_location_shortcut(question: str, messages: list[dict]):
    """Returns a plain-text answer if this question is specifically an
    exact-coordinates request for an identifiable device, else None (falls
    through to the normal tool-calling pipeline, where the model has no tool
    capable of returning exact coordinates at all — see _AI_SYSTEM_PROMPT).
    Runs entirely locally, with no LLM call, so this is the one path allowed
    to state real coordinates."""
    if not _EXACT_LOCATION_RE.search(question.lower()):
        return None
    device = _mentioned_device(messages, _visible_devices())
    if not device:
        return None
    date_range = _extract_date_range(question)
    pos = _exact_location_lookup(device["uuid"], date_range)
    if not pos:
        suffix = " in that window." if date_range else "."
        return f"I don't have any recorded position for \"{device['name']}\"{suffix}"
    lat, lon = pos["lat"], pos["lon"]
    ns, ew = ("N" if lat >= 0 else "S"), ("E" if lon >= 0 else "W")
    when = f"at {pos['obs_time']}" if date_range else f"(last known, {pos['obs_time']})"
    return (f"The exact location of \"{device['name']}\" {when} is "
            f"{abs(lat):.7f}° {ns}, {abs(lon):.7f}° {ew}.")


@app.route("/api/ai/ask", methods=["POST"])
@login_required
def ai_ask():
    if not _ai_feature_enabled():
        return jsonify({"error": "Goby is not available right now"}), 503
    if not _user_ai_allowed(session["user_id"]):
        return jsonify({"error": "Goby has been disabled for your account"}), 403
    data = request.get_json(force=True, silent=True) or {}
    history = data.get("messages") or []
    if not history or not isinstance(history, list) or not history[-1].get("content"):
        return jsonify({"error": "messages is required"}), 400
    question = str(history[-1]["content"]).strip()
    if not question:
        return jsonify({"error": "empty question"}), 400
    if len(question) > 2000:
        return jsonify({"error": "question too long"}), 400
    history = [{"role": m.get("role"), "content": m.get("content")} for m in history[-12:]]

    # Exact-coordinate requests are answered directly from the database and
    # never reach the model — checked before the concurrency semaphore since
    # this path makes no LLM call at all and shouldn't consume a scarce slot.
    shortcut_answer = _try_exact_location_shortcut(question, history)

    if shortcut_answer is None and not _AI_SEMAPHORE.acquire(blocking=False):
        return jsonify({"error": "Goby is busy, try again shortly"}), 429

    def generate():
        full_answer = ""
        try:
            if shortcut_answer is not None:
                full_answer = shortcut_answer
                yield f"data: {json.dumps({'delta': shortcut_answer})}\n\n"
            else:
                # The model has no reliable way to know the real current date
                # on its own — confirmed live: asked for "the last 99 days",
                # it computed an internally-consistent 99-day span but anchored
                # it to a guessed "today" 11 days in the future, silently
                # skewing every relative-date tool argument it would compute.
                # Grounding "now" here fixes it the same way every other fact
                # is grounded — give it the real value, don't make it guess.
                today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                system_msg = {"role": "system", "content": f"Today's date is {today_str} (UTC). {_AI_SYSTEM_PROMPT}"}
                for piece in _llm_chat_with_tools([system_msg, *history]):
                    full_answer += piece
                    yield f"data: {json.dumps({'delta': piece})}\n\n"
            with sqlite3.connect(DB_PATH) as con:
                con.execute(
                    "INSERT INTO ai_messages (user_id, username, role, content) VALUES (?, ?, 'user', ?)",
                    (session["user_id"], session.get("username"), question),
                )
                con.execute(
                    "INSERT INTO ai_messages (user_id, username, role, content) VALUES (?, ?, 'assistant', ?)",
                    (session["user_id"], session.get("username"), full_answer),
                )
                con.commit()
            log_activity("ai.ask", target=session.get("username"), detail=f"len={len(full_answer)}")
            yield "data: [DONE]\n\n"
        except requests.exceptions.Timeout:
            logging.exception("AI assistant request timed out")
            yield f"data: {json.dumps({'error': 'Goby took too long to respond (it may still be loading the model) — try again in a moment.'})}\n\n"
        except requests.exceptions.ConnectionError:
            logging.exception("AI assistant request failed to connect")
            yield f"data: {json.dumps({'error': 'Could not reach Goby. Check that the LLM backend is running and LLM_API_BASE_URL is correct.'})}\n\n"
        except Exception:
            # Covers requests.HTTPError (non-200) and anything else — the real
            # exception is still in the server log for an admin to diagnose;
            # the user only sees a safe, generic message, never a raw stack trace.
            logging.exception("AI assistant request failed")
            yield f"data: {json.dumps({'error': 'Goby hit an unexpected error. Please try again.'})}\n\n"
        finally:
            # Only release if the shortcut path didn't skip acquiring it —
            # releasing a slot that was never taken would incorrectly let the
            # semaphore exceed its real capacity.
            if shortcut_answer is None:
                _AI_SEMAPHORE.release()

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/ai/history")
@login_required
def ai_history():
    limit = min(int(request.args.get("limit", 50)), 100)
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        # ORDER BY ... ASC LIMIT N (the previous version of this query) grabs
        # the OLDEST N rows, not the most recent N — confirmed real for any
        # user with more than `limit` total turns: reopening the panel would
        # show their very first conversations ever instead of recent ones.
        # Fixed with the standard "most recent N, re-sorted oldest-first for
        # display" pattern — take the latest N by DESC+LIMIT in a subquery,
        # then re-sort that smaller set ASC for chronological display order.
        rows = con.execute("""
            SELECT role, content, created_at FROM (
                SELECT role, content, created_at FROM ai_messages
                WHERE user_id = ? ORDER BY created_at DESC LIMIT ?
            ) ORDER BY created_at ASC
        """, (session["user_id"], limit)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/ai/history", methods=["DELETE"])
@login_required
def clear_ai_history():
    """Lets a user delete their own Ask Goby conversation history on demand —
    scoped to session["user_id"] only, same as the GET above; there is no
    route for clearing another user's history, including for admins."""
    with sqlite3.connect(DB_PATH) as con:
        cur = con.execute("DELETE FROM ai_messages WHERE user_id = ?", (session["user_id"],))
        con.commit()
    log_activity("ai.history_clear", detail=f"rows_deleted={cur.rowcount}")
    return jsonify({"ok": True, "rows_deleted": cur.rowcount})


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
                "SELECT id, username, first_name, last_name, is_admin, is_super_admin, ai_access, created_at "
                "FROM users ORDER BY username"
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
            "is_admin": bool(u["is_admin"]), "is_super_admin": bool(u["is_super_admin"]),
            "ai_access": bool(u["ai_access"]),
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
                # ai_access explicitly 0 here, overriding the column's own
                # DEFAULT 1 — that default exists only so the ALTER TABLE
                # migration doesn't retroactively cut off users who existed
                # before this feature; a brand new user was never using Ask
                # Goby, so there's nothing to preserve, and the super admin
                # must now opt each one in deliberately.
                "INSERT INTO users (username, password_hash, first_name, last_name, is_admin, ai_access) "
                "VALUES (?, ?, ?, ?, ?, 0)",
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
    if _super_admin_protected(user_id):
        return jsonify({"error": "the super admin account can only be modified by itself"}), 403
    data = request.get_json(force=True, silent=True) or {}
    if "ai_access" in data and not session.get("is_super_admin"):
        # Per-user Ask Goby access is deliberately scoped tighter than every
        # other field this route accepts — admin_required (any admin) gates
        # the route itself, but this one field is super-admin-only, same
        # no-exceptions pattern as the AI runtime toggle (PATCH
        # /api/admin/ai-settings) and private-device ownership.
        return jsonify({"error": "super admin privileges required"}), 403
    with sqlite3.connect(DB_PATH) as con:
        target_row = con.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        target_username = target_row[0] if target_row else str(user_id)
        changed = [f for f in ("first_name", "last_name", "is_admin", "group_ids", "ai_access") if f in data]

        if "first_name" in data:
            con.execute("UPDATE users SET first_name = ? WHERE id = ?",
                        ((data.get("first_name") or "").strip() or None, user_id))
        if "last_name" in data:
            con.execute("UPDATE users SET last_name = ? WHERE id = ?",
                        ((data.get("last_name") or "").strip() or None, user_id))

        if "is_admin" in data and not data["is_admin"]:
            # _super_admin_protected() lets the super admin modify THEMSELVES in
            # general (needed for self-service name/password edits), but
            # self-revoking admin status is uniquely dangerous: admin_required
            # (gating the whole Management page + all /api/admin/* routes)
            # checks is_admin, not is_super_admin — so this would immediately
            # lock the super admin out of the UI that could undo it.
            target_super = con.execute(
                "SELECT is_super_admin FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            if target_super and target_super[0]:
                return jsonify({"error": "the super admin account's admin status cannot be revoked"}), 400
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
        if "ai_access" in data:
            con.execute("UPDATE users SET ai_access = ? WHERE id = ?",
                        (1 if data["ai_access"] else 0, user_id))
        con.commit()
    log_activity("user.update", target=target_username, detail=f"fields={','.join(changed)}")
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:user_id>/password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    if _super_admin_protected(user_id):
        return jsonify({"error": "the super admin account can only be modified by itself"}), 403
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
    if _super_admin_protected(user_id):
        return jsonify({"error": "the super admin account can only be modified by itself"}), 403
    with sqlite3.connect(DB_PATH) as con:
        target = con.execute("SELECT is_admin, username, is_super_admin FROM users WHERE id = ?", (user_id,)).fetchone()
        # Not even the super admin can delete themselves — bootstrap_admin()
        # only re-seeds a fresh admin when ZERO admins exist at all, so if any
        # other regular admin remains, deleting "admin" would permanently
        # remove the super-admin role from the system with no auto-recovery.
        if target and target[2]:
            return jsonify({"error": "the super admin account cannot be deleted"}), 400
        if target and target[0]:
            other_admins = con.execute(
                "SELECT COUNT(*) FROM users WHERE is_admin = 1 AND id != ?", (user_id,)
            ).fetchone()[0]
            if other_admins == 0:
                return jsonify({"error": "cannot delete the last admin"}), 400
        con.execute("DELETE FROM user_groups WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM device_users WHERE user_id = ?", (user_id,))
        con.execute("DELETE FROM label_users WHERE user_id = ?", (user_id,))
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


@app.route("/api/admin/devices")
@admin_required
def admin_devices():
    """Currently-PRIVATE devices only — the compact list rendered by default
    on the Management page's Device Access section. Deliberately not "every
    device ever seen": with potentially hundreds of devices and only a
    handful ever made private, loading/rendering the full catalog here
    doesn't scale as a default view. Finding a device to newly mark private
    goes through /api/admin/devices/search instead.

    Restricted the same way as everywhere else: the super admin sees every
    private device; a regular admin only sees ones they own or are
    explicitly granted — being an admin no longer implies visibility into
    every private device."""
    is_super_admin = bool(session.get("is_super_admin"))
    visible_uuids = None if is_super_admin else set(_private_visible_uuids(session["user_id"]))
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""
            SELECT DISTINCT o.uuid, o.name, COALESCE(m.archived, 0) AS archived,
                   m.private_owner_id, u.username AS owner_username,
                   g.id AS group_id, COALESCE(g.name, 'Unassigned') AS group_name
            FROM observations o
            JOIN device_meta m ON m.uuid = o.uuid AND m.private = 1
            LEFT JOIN users u ON u.id = m.private_owner_id
            LEFT JOIN group_codes gc ON gc.code = substr(o.name, 2, 1)
            LEFT JOIN groups g ON g.id = gc.group_id
            ORDER BY o.name
        """).fetchall()
        allowed_by_uuid: dict[str, list] = {}
        for uuid, uid, username in con.execute("""
            SELECT du.uuid, u.id, u.username FROM device_users du JOIN users u ON u.id = du.user_id
        """).fetchall():
            allowed_by_uuid.setdefault(uuid, []).append({"id": uid, "username": username})
    if visible_uuids is not None:
        rows = [r for r in rows if r["uuid"] in visible_uuids]
    return jsonify([{
        "uuid": r["uuid"], "name": r["name"], "archived": bool(r["archived"]),
        "group_id": r["group_id"], "group_name": r["group_name"],
        "owner_username": r["owner_username"],
        "allowed_users": allowed_by_uuid.get(r["uuid"], []),
    } for r in rows])


@app.route("/api/admin/devices/search")
@admin_required
def admin_devices_search():
    """Server-side device lookup for the "Make a device private" modal's
    search-as-you-type — never ships the full device catalog to the browser
    just to let an admin find one device among potentially hundreds.

    A private device the requesting (non-super) admin doesn't own/isn't
    granted is excluded entirely from results, not just flagged — matching
    that they can't see it anywhere else either."""
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify([])
    is_super_admin = bool(session.get("is_super_admin"))
    visible_uuids = None if is_super_admin else set(_private_visible_uuids(session["user_id"]))
    like = f"%{q}%"
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute("""
            SELECT DISTINCT o.uuid, o.name, COALESCE(m.private, 0) AS private,
                   g.id AS group_id, COALESCE(g.name, 'Unassigned') AS group_name
            FROM observations o
            LEFT JOIN device_meta m ON m.uuid = o.uuid
            LEFT JOIN group_codes gc ON gc.code = substr(o.name, 2, 1)
            LEFT JOIN groups g ON g.id = gc.group_id
            WHERE o.name LIKE ? OR o.uuid LIKE ?
            ORDER BY o.name
            LIMIT 20
        """, (like, like)).fetchall()
    if visible_uuids is not None:
        rows = [r for r in rows if not r["private"] or r["uuid"] in visible_uuids]
    return jsonify([{
        "uuid": r["uuid"], "name": r["name"], "private": bool(r["private"]),
        "group_id": r["group_id"], "group_name": r["group_name"],
    } for r in rows])


# Separate from delete_device_permanently()'s DELETE on the same path — this
# is the non-destructive private/allowed-users toggle, admin-only like every
# other device_meta mutation.
@app.route("/api/admin/devices/<uuid>", methods=["PATCH"])
@admin_required
def admin_update_device(uuid):
    data = request.get_json(force=True, silent=True) or {}
    is_super_admin = bool(session.get("is_super_admin"))
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        meta = con.execute(
            "SELECT private, private_owner_id FROM device_meta WHERE uuid = ?", (uuid,)
        ).fetchone()
        currently_private = bool(meta["private"]) if meta else False
        owner_id = meta["private_owner_id"] if meta else None

        # A currently-private device can only be touched (its access edited,
        # or made public) by its owner or the super admin — being "just" an
        # admin no longer grants this. A currently-public device can be
        # privatized by any admin, who becomes its new owner.
        if currently_private and not is_super_admin and owner_id != session["user_id"]:
            return jsonify({"error": "only the admin who made this device private (or the super admin) can change its access"}), 403

        changed = []
        if "private" in data:
            private = 1 if data["private"] else 0
            if private:
                con.execute("""
                    INSERT INTO device_meta (uuid, private, private_owner_id) VALUES (?, 1, ?)
                    ON CONFLICT(uuid) DO UPDATE SET private = 1, private_owner_id = excluded.private_owner_id
                """, (uuid, session["user_id"]))
            else:
                con.execute("""
                    INSERT INTO device_meta (uuid, private) VALUES (?, 0)
                    ON CONFLICT(uuid) DO UPDATE SET private = 0
                """, (uuid,))
            changed.append(f"private={bool(private)}")
        if "user_ids" in data:
            user_ids = data["user_ids"] or []
            con.execute("DELETE FROM device_users WHERE uuid = ?", (uuid,))
            for uid in user_ids:
                con.execute("INSERT OR IGNORE INTO device_users (uuid, user_id) VALUES (?, ?)", (uuid, uid))
            changed.append(f"user_ids={user_ids}")
        con.commit()
    log_activity("device.access_update", target=uuid, detail="; ".join(changed))
    return jsonify({"ok": True})


@app.route("/api/admin/audit-log")
@admin_required
def admin_audit_log():
    limit = min(int(request.args.get("limit", 200)), 1000)
    query = "SELECT id, ts, username, action, target, detail, ip FROM audit_log WHERE 1=1"
    params = []
    if not session.get("is_super_admin"):
        # The super admin's own activity (including login_failed attempts
        # logged under its literal username pre-auth) is visible only to
        # itself — a regular admin sees every other admin's activity but
        # never this. Matched by username against the real users table
        # rather than a hardcoded "admin" literal, same reasoning as every
        # other is_super_admin check in this app.
        query += " AND username NOT IN (SELECT username FROM users WHERE is_super_admin = 1)"
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/version")
@admin_required
def admin_version():
    return jsonify({"app_version": APP_VERSION, "schema_version": SCHEMA_VERSION})


@app.route("/api/admin/active-users")
@admin_required
def admin_active_users():
    """Users considered 'currently logged on' — last_seen_at (touched by
    _touch_last_seen() on every authenticated request on both pages) within
    ACTIVE_USER_WINDOW_MINUTES. This is activity-based, not a real session
    registry — there's no server-side session store to query (sessions are
    plain signed cookies), so "active" here means "made a request recently,"
    not "holds a cookie that hasn't expired yet." A user who closes their
    browser without logging out will simply stop appearing here once they go
    quiet, same as the dashboard's own online/offline feel elsewhere."""
    minutes = int(request.args.get("minutes") or ACTIVE_USER_WINDOW_MINUTES)
    query = """
        SELECT username, is_admin, is_super_admin, last_seen_at
        FROM users
        WHERE last_seen_at >= datetime('now', ?)
    """
    params = [f"-{minutes} minutes"]
    if not session.get("is_super_admin"):
        # The super admin's own active-session presence is visible only to
        # itself — same restriction as the audit log, for the same reason.
        query += " AND is_super_admin = 0"
    query += " ORDER BY last_seen_at DESC"
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/ai-settings")
@admin_required
def admin_get_ai_settings():
    """Super-admin only — not just admin_required, which every other route in
    this block uses, because this specific control was explicitly scoped to
    the super admin account alone, same no-exceptions pattern as the private-
    device override. `configured` (is an LLM endpoint set up at all, via
    LLM_API_BASE_URL) is reported alongside `enabled` (the runtime toggle) so
    the UI can show a meaningful state even when there's nothing to toggle
    yet."""
    if not session.get("is_super_admin"):
        return jsonify({"error": "super admin privileges required"}), 403
    with sqlite3.connect(DB_PATH) as con:
        row = con.execute("SELECT value FROM app_settings WHERE key = 'ai_enabled'").fetchone()
    return jsonify({"configured": _llm_configured(), "enabled": row is None or row[0] == "1"})


@app.route("/api/admin/ai-settings", methods=["PATCH"])
@admin_required
def admin_set_ai_settings():
    if not session.get("is_super_admin"):
        return jsonify({"error": "super admin privileges required"}), 403
    data = request.get_json(force=True, silent=True) or {}
    if "enabled" not in data:
        return jsonify({"error": "enabled is required"}), 400
    enabled = bool(data["enabled"])
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            INSERT INTO app_settings (key, value) VALUES ('ai_enabled', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """, ("1" if enabled else "0",))
        con.commit()
    log_activity("ai.enabled_toggle", detail=f"enabled={enabled}")
    return jsonify({"ok": True, "enabled": enabled})


def _device_backup_payload(uuid: str) -> dict:
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        observations = con.execute("""
            SELECT uuid, name, lat, lon, obs_time, ingest_time, accuracy, confidence, device_id, received_at
            FROM observations WHERE uuid = ? ORDER BY obs_time
        """, (uuid,)).fetchall()
        meta = con.execute(
            "SELECT uuid, archived, archived_at, private FROM device_meta WHERE uuid = ?", (uuid,)
        ).fetchone()
        labels = con.execute("""
            SELECT dl.id, dl.text, dl.private, u.username AS created_by_username, dl.created_at, dl.updated_at
            FROM device_labels dl LEFT JOIN users u ON u.id = dl.created_by
            WHERE dl.uuid = ? ORDER BY dl.created_at
        """, (uuid,)).fetchall()
        allowed_by_label: dict[int, list] = {}
        label_ids = [r["id"] for r in labels]
        if label_ids:
            placeholders = ",".join("?" * len(label_ids))
            for lid, uname in con.execute(f"""
                SELECT lu.label_id, u.username FROM label_users lu
                JOIN users u ON u.id = lu.user_id WHERE lu.label_id IN ({placeholders})
            """, label_ids).fetchall():
                allowed_by_label.setdefault(lid, []).append(uname)
        plan = con.execute("""
            SELECT dest_lat, dest_lon, radius_miles, eta_start, eta_end, created_at, updated_at
            FROM device_plans WHERE uuid = ?
        """, (uuid,)).fetchone()
        plan_history = con.execute("""
            SELECT h.action, h.dest_lat, h.dest_lon, h.radius_miles, h.eta_start, h.eta_end,
                   h.start_date, h.outcome, u.username AS changed_by_username, h.changed_at
            FROM device_plan_history h LEFT JOIN users u ON u.id = h.changed_by
            WHERE h.uuid = ? ORDER BY h.changed_at
        """, (uuid,)).fetchall()
    return {
        "uuid": uuid,
        "backed_up_at": datetime.now(timezone.utc).isoformat(),
        "device_meta": dict(meta) if meta else None,
        "observations": [dict(r) for r in observations],
        "labels": [{
            "text": l["text"], "private": bool(l["private"]), "created_by_username": l["created_by_username"],
            "allowed_usernames": allowed_by_label.get(l["id"], []),
            "created_at": l["created_at"], "updated_at": l["updated_at"],
        } for l in labels],
        "plan": dict(plan) if plan else None,
        "plan_history": [dict(r) for r in plan_history],
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
        con.execute("DELETE FROM device_users WHERE uuid = ?", (uuid,))
        label_ids = [r[0] for r in con.execute("SELECT id FROM device_labels WHERE uuid = ?", (uuid,)).fetchall()]
        if label_ids:
            placeholders = ",".join("?" * len(label_ids))
            con.execute(f"DELETE FROM label_users WHERE label_id IN ({placeholders})", label_ids)
        con.execute("DELETE FROM device_labels WHERE uuid = ?", (uuid,))
        con.execute("DELETE FROM device_plans WHERE uuid = ?", (uuid,))
        con.execute("DELETE FROM device_plan_history WHERE uuid = ?", (uuid,))
        con.commit()
    log_activity("device.delete", target=uuid)
    return jsonify({"uuid": uuid, "deleted": True})


init_db()
bootstrap_admin()
threading.Thread(target=tcp_listener, daemon=True).start()
threading.Thread(target=_audit_log_pruner, daemon=True).start()
threading.Thread(target=_ai_history_pruner, daemon=True).start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=HTTP_PORT, threaded=True)
