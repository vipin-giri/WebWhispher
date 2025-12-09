#!/usr/bin/env python3
"""
WebWhisper – Fully working Flask tool
- Modern UI
- Auto-save scan results to TXT files
- Unique domains stored in SQLite
- Export DB to TXT
Run:
    pip install flask requests
    python webwhisper_app.py
Open:
    http://127.0.0.1:5000
"""

from flask import Flask, request, g, redirect, url_for, render_template_string, send_file, flash
import sqlite3, requests, hashlib, random, time, io, os, datetime
from urllib.parse import quote_plus

# ------------------ CONFIG ------------------
DB_PATH = "webwhisper_domains.db"
CRT_SH_BASE = "https://crt.sh/"
USER_AGENT = "WebWhisper/1.0 (local)"
REQUEST_TIMEOUT = 20
REQUEST_DELAY = 0.7
MAX_FETCH = 1200
DEFAULT_TLDS = ["com", "net", "org"]

app = Flask(__name__)
app.secret_key = os.urandom(24)
_last_results = []

ASCII_BANNER = r"""
 __      __      ___.   __      __.__    .__                             
/  \    /  \ ____\_ |__/  \    /  \  |__ |__| ____________   ___________  
\   \/\/   // __ \| __ \   \/\/   /  |  \|  |/  ___/\__  \_/ __ \_  __ \ 
 \        /\  ___/| \_\ \        /|   Y  \  |\___ \  / __ \\  ___/|  | \/ 
  \__/\  /  \___  >___  /\__/\  / |___|  /__/____  >(____  /\___  >__|    
       \/       \/    \/      \/       \/        \/      \/     \/        
"""

# ------------------ DB ------------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH, check_same_thread=False)
        db.execute("""
            CREATE TABLE IF NOT EXISTS seen_domains (
                id INTEGER PRIMARY KEY,
                domain TEXT UNIQUE,
                fingerprint TEXT UNIQUE,
                first_seen TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()
    return db

@app.teardown_appcontext
def close_db(_):
    db = getattr(g, "_db", None)
    if db: db.close()

def sha(domain): return hashlib.sha256(domain.encode()).hexdigest()

def seen(domain):
    db = get_db()
    fp = sha(domain)
    cur = db.cursor()
    cur.execute("SELECT 1 FROM seen_domains WHERE fingerprint=? LIMIT 1", (fp,))
    return cur.fetchone() is not None

def mark(domain):
    db = get_db()
    fp = sha(domain)
    try:
        db.execute("INSERT INTO seen_domains(domain,fingerprint) VALUES(?,?)", (domain, fp))
        db.commit()
        return True
    except:
        return False

def seen_count():
    cur = get_db().cursor()
    cur.execute("SELECT COUNT(*) FROM seen_domains")
    return cur.fetchone()[0]

def sample_db(n):
    cur = get_db().cursor()
    cur.execute("SELECT domain FROM seen_domains ORDER BY RANDOM() LIMIT ?", (n,))
    return [r[0] for r in cur.fetchall()]

# ------------------ CRT.SH FETCH ------------------
def fetch_tld(tld, limit=MAX_FETCH):
    q = quote_plus(f"%.{tld}")
    url = f"{CRT_SH_BASE}?q={q}&output=json"
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT)
        time.sleep(REQUEST_DELAY)
        data = r.json()
    except:
        return set(), "fetch failed"

    domains = set()
    for i, entry in enumerate(data):
        if i >= limit: break
        nv = entry.get("name_value", "")
        for name in nv.splitlines():
            name = name.strip().lower()
            if name.startswith("*."): name = name[2:]
            if "." not in name: continue
            domains.add(name)

    return domains, None

# ------------------ TEMPLATES ------------------
HTML = """
<!doctype html>
<html>
<head>
<title>WebWhisper</title>
<style>
body{background:#0a0f1c;color:#e6eef8;font-family:Arial;padding:20px;}
.card{background:#11182b;padding:18px;border-radius:8px;margin-bottom:20px;}
input,button,textarea{padding:8px;border-radius:6px;border:1px solid #2a3550;background:#0d1422;color:#e6eef8;}
button{cursor:pointer;background:#3bb9ff;color:#000;font-weight:bold;border:0;}
textarea{width:100%;height:200px;}
.muted{color:#8fa3c8;font-size:13px;}
</style>
</head>
<body>

<div class="card">
<pre>{{ banner }}</pre>
<h2>WebWhisper</h2>
<div class="muted">Unique domain finder (crt.sh). DB size: <b>{{ seen_count }}</b></div>
</div>

<div class="card">
<h3>Run Scan</h3>
<form method="POST" action="/scan">
<label>Count:</label><br>
<input type="number" name="count" value="25"><br><br>

<label>TLDs:</label><br>
<input type="text" name="tlds" value="com,net,org"><br><br>

<label>Max per TLD:</label><br>
<input type="number" name="max_fetch" value="1200"><br><br>

<button type="submit">Run Scan</button>
</form>
</div>

{% if results %}
<div class="card">
<h3>Results ({{ results|length }})</h3>
<textarea readonly>{{ results_text }}</textarea><br><br>

<form method="POST" action="/download_results">
<input type="hidden" name="results_text" value="{{ results_text }}">
<button>Download This Scan (.txt)</button>
</form>
</div>
{% endif %}

<div class="card">
<h3>Actions</h3>
<form method="POST" action="/download_last_results">
<button>Download Last Scan (.txt)</button>
</form>
<br>
<a href="/export_txt"><button>Export DB (.txt)</button></a>
<br><br>
<a href="/sample_page"><button>Sample DB</button></a>
</div>

</body>
</html>
"""

SAMPLE_HTML = """
<!doctype html>
<html>
<head>
<title>Sample DB</title>
<style>
body{background:#0a0f1c;color:#e6eef8;font-family:Arial;padding:20px;}
.card{background:#11182b;padding:18px;border-radius:8px;margin-bottom:20px;}
input,button,textarea{padding:8px;border-radius:6px;border:1px solid #2a3550;background:#0d1422;color:#e6eef8;}
textarea{width:100%;height:200px;}
button{cursor:pointer;background:#3bb9ff;color:#000;font-weight:bold;border:0;}
</style>
</head>
<body>

<div class="card">
<h2>Sample DB</h2>
<form method="POST" action="/sample">
<input type="number" name="count" value="25">
<button>Sample</button>
</form>
</div>

{% if results %}
<div class="card">
<h3>Results</h3>
<textarea readonly>{{ results_text }}</textarea><br><br>

<form method="POST" action="/download_results">
<input type="hidden" name="results_text" value="{{ results_text }}">
<button>Download (.txt)</button>
</form>
</div>
{% endif %}

<a href="/">Back</a>

</body>
</html>
"""

# ------------------ ROUTES ------------------
@app.route("/")
def home():
    return render_template_string(
        HTML, banner=ASCII_BANNER, seen_count=seen_count(), results=None
    )

@app.route("/scan", methods=["POST"])
def scan():
    global _last_results

    count = int(request.form.get("count", 25))
    tlds = [t.strip() for t in request.form.get("tlds", "com,net,org").split(",")]
    max_fetch = int(request.form.get("max_fetch", MAX_FETCH))

    pool = set()
    for t in tlds:
        d, _ = fetch_tld(t, max_fetch)
        pool.update(d)

    pool = list(pool)
    random.shuffle(pool)

    results = []
    for domain in pool:
        if len(results) >= count: break
        if not seen(domain):
            if mark(domain):
                results.append(domain)

    # fallback
    if len(results) < count:
        need = count - len(results)
        results += sample_db(need)

    _last_results = results[:]

    # -------- AUTO-SAVE --------
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{timestamp}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(results))
    # ---------------------------

    return render_template_string(
        HTML,
        banner=ASCII_BANNER,
        seen_count=seen_count(),
        results=results,
        results_text="\n".join(results)
    )

@app.route("/sample_page")
def sample_page():
    return render_template_string(SAMPLE_HTML)

@app.route("/sample", methods=["POST"])
def sample():
    global _last_results
    count = int(request.form.get("count", 25))
    results = sample_db(count)
    _last_results = results[:]
    return render_template_string(
        SAMPLE_HTML,
        results=results,
        results_text="\n".join(results)
    )

@app.route("/download_results", methods=["POST"])
def download_results():
    text = request.form.get("results_text", "")
    bio = io.BytesIO(text.encode())
    return send_file(bio, mimetype="text/plain", as_attachment=True, download_name="scan_results.txt")

@app.route("/download_last_results", methods=["POST"])
def download_last_results():
    text = "\n".join(_last_results)
    bio = io.BytesIO(text.encode())
    return send_file(bio, mimetype="text/plain", as_attachment=True, download_name="last_scan.txt")

@app.route("/export_txt")
def export_txt():
    cur = get_db().cursor()
    cur.execute("SELECT domain FROM seen_domains ORDER BY first_seen")
    rows = cur.fetchall()
    text = "\n".join(r[0] for r in rows)
    bio = io.BytesIO(text.encode())
    return send_file(bio, mimetype="text/plain", as_attachment=True, download_name="webwhisper_db.txt")

# ------------------ RUN ------------------
if __name__ == "__main__":
    print("WebWhisper running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
