# ble.dash

A small Flask dashboard that ingests BLE/location observations over UDP (as CEF-formatted messages) and displays live device tracks on a Leaflet map. Updates are pushed to the browser over Server-Sent Events.

## How it works

- `data/app.py` — Flask app. Runs a background thread listening for UDP packets, decodes them (`data/comlibv3.py`, CEF format), and stores observations in a SQLite database. Serves a REST API (`/api/devices`, `/api/tracks`), an SSE stream (`/stream`), and the map UI (`/`).
- `data/gunicorn_config.py` — Gunicorn config used to serve the app over HTTPS.
- `data/templates/index.html` + `data/static/leaflet/` — the map frontend (Leaflet.js).
- `docker-compose.yml` — runs the app in a `python:3.13-slim` container with the `data/` directory mounted as the app's working directory.

## Prerequisites

- Docker and Docker Compose
- TLS certificate, key, and CA cert for HTTPS (see below) — **not included in this repo**

## Setup

1. Clone the repo:

   ```bash
   git clone https://github.com/j6dtt/ble.dash.git
   cd ble.dash
   ```

2. Add TLS certificates. `gunicorn_config.py` expects these files, which are git-ignored and must be provided yourself:

   ```
   data/certs/ssl.lab.int.crt   # server certificate
   data/certs/ssl.lab.int.key   # private key
   data/certs/lab.int-ca.crt    # CA certificate
   ```

   For local testing you can generate a self-signed cert:

   ```bash
   mkdir -p data/certs
   openssl req -x509 -newkey rsa:2048 -nodes \
     -keyout data/certs/ssl.lab.int.key \
     -out data/certs/ssl.lab.int.crt \
     -days 365 -subj "/CN=localhost"
   cp data/certs/ssl.lab.int.crt data/certs/lab.int-ca.crt
   ```

   If you use different filenames, update the paths in `data/gunicorn_config.py`.

3. (Optional) adjust ports/DB path in `docker-compose.yml`:

   | Variable   | Default (compose) | Description                        |
   |------------|--------------------|-------------------------------------|
   | `UDP_PORT` | `9001`             | UDP port the ingest listener binds  |
   | `HTTP_PORT`| `9043`             | Set for reference; actual bind port is set in `gunicorn_config.py` (`0.0.0.0:9043`) |
   | `DB_PATH`  | `/app/tracks.db`   | Path to the SQLite database file    |

4. Start the service:

   ```bash
   docker compose up -d
   ```

   The container uses host networking, so ports are exposed directly on the host.

5. Open the dashboard at `https://<host>:9043/` (or the port set in `gunicorn_config.py`).

6. Send UDP observations to port `9001` (or your configured `UDP_PORT`) as CEF-formatted messages; devices will appear on the map as data arrives.

## Running without Docker

```bash
cd data
pip install flask gunicorn
export UDP_PORT=9001 HTTP_PORT=9043 DB_PATH=./tracks.db
gunicorn -c gunicorn_config.py app:app
```

## Notes

- The SQLite database (`data/tracks.db*`) and `data/certs/` are git-ignored since they contain runtime/generated and sensitive data — they are created/populated automatically on first run (db) or must be supplied by you (certs).
