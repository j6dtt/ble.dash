bind = "0.0.0.0:9043"
workers = 1          # must stay 1 — the TCP CEF listener thread binds :9001 at
                      # module import time; a 2nd worker process would re-run
                      # that import and fail to bind the same port
worker_class = "gthread"
# Every open dashboard tab holds one thread for its entire /stream (SSE)
# connection lifetime — that thread is never freed while the tab stays open,
# and timeout=0 below means gunicorn never force-frees a stuck one either.
# With the old threads=4, 3-4 simultaneous dashboard tabs consumed the whole
# pool and every other request (logins, API calls, Management actions) hung
# indefinitely with no error logged. 40 gives real headroom — each thread is
# just blocked on a Python Queue.get()/short SQLite call, so this is cheap.
threads = 40
timeout = 0          # disable timeout — required for long-lived SSE connections
certfile = "certs/ssl.lab.int.crt"
keyfile  = "certs/ssl.lab.int.key"
ca_certs = "certs/lab.int-ca.crt"
accesslog = "-"
errorlog = "-"
loglevel = "info"
