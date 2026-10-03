"""CloudDocVault v7 - secure document portal deployed on a public cloud (AWS).

Developed by Satyam Kanojiya.

IaaS  : EC2 instance (created by Elastic Beanstalk)   PaaS : Elastic Beanstalk (Procfile + gunicorn)
DBaaS : RDS PostgreSQL                                Storage : S3 (server-side encrypted)
Security : IAM role, Security Groups, hashed passwords, CSRF, secure headers, login throttling,
           signed + expiring (optionally password-protected) share links, audit log.
"""
import csv
import hashlib
import hmac
import io
import os
import re
import secrets
import socket
import sys
import time
import urllib.request
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, Response, abort, flash, redirect, render_template, request,
                   send_file, session, url_for)
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from db import Database
from storage import get_storage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_VERSION = "7.0"
DEVELOPER = "Satyam Kanojiya"
STARTED_AT = time.time()

MAX_FILE_BYTES = 5 * 1024 * 1024  # per file
CATEGORIES = {
    "Documents": {"pdf", "docx", "txt"},
    "Spreadsheets": {"xlsx", "csv"},
    "Presentations": {"pptx"},
    "Images": {"png", "jpg", "jpeg"},
}
ALLOWED_EXT = set().union(*CATEGORIES.values())
EXT_CATEGORY = {ext: cat for cat, exts in CATEGORIES.items() for ext in exts}
CAT_COLOR = {"Documents": "#2f5bea", "Spreadsheets": "#18a058", "Presentations": "#f59f00", "Images": "#d6336c"}
CAT_ICON = {"Documents": "\U0001F4C4", "Spreadsheets": "\U0001F4CA", "Presentations": "\U0001F4FD", "Images": "\U0001F5BC"}
PREVIEW_MIME = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                "pdf": "application/pdf", "txt": "text/plain"}
# share-link lifetimes: form value -> (seconds, label)
SHARE_CHOICES = {"1h": (3600, "1 hour"), "24h": (86400, "24 hours"), "7d": (604800, "7 days")}
MAX_FAILS, LOCK_SECONDS = 5, 300  # login throttling


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-secret-change-me"),
        MAX_CONTENT_LENGTH=20 * 1024 * 1024,  # whole request; each file is limited to 5 MB below
        QUOTA_BYTES=int(os.environ.get("QUOTA_MB", "25")) * 1024 * 1024,  # per-user storage quota
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
        DATABASE_URL=os.environ.get("DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "docvault.db")),
    )
    if test_config:
        app.config.update(test_config)

    db = Database(app.config["DATABASE_URL"])
    schema = {"ok": False, "error": None}

    def ensure_schema(attempts=1):
        if schema["ok"]:
            return True
        for i in range(attempts):
            try:
                db.init_schema()
                schema["ok"], schema["error"] = True, None
                return True
            except Exception as exc:
                schema["error"] = f"{type(exc).__name__}: {exc}"[:300]
                app.logger.error("Schema init failed: %s", schema["error"])
                if i < attempts - 1:
                    time.sleep(2)
        return False

    ensure_schema(attempts=3)  # never crash the worker at boot; retry per request
    store = app.config.get("STORAGE") or get_storage(BASE_DIR)

    # ------------------------------------------------------------------ helpers
    share_ser = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="docvault-share")
    meta_cache = {}
    fails = {}  # login throttling: key -> (count, first_failure_ts)

    def now_str():
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def log_activity(user_id, action, detail=""):
        """Audit trail. Must never break the request that triggered it."""
        try:
            db.execute("INSERT INTO activity (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)",
                       (user_id, action, str(detail)[:200], now_str()))
        except Exception:
            app.logger.exception("activity log failed")

    def human(n):
        n = float(n or 0)
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024

    app.jinja_env.filters["human"] = human

    def ext_of(name):
        return name.rsplit(".", 1)[-1].lower() if "." in name else ""

    def used_bytes(user_id):
        row = db.one("SELECT COALESCE(SUM(size_bytes), 0) AS used FROM documents WHERE user_id = ?", (user_id,))
        return int(row["used"])  # includes files still in the trash (they still occupy storage)

    def client_ip():
        return (request.headers.get("X-Forwarded-For", request.remote_addr) or "?").split(",")[0].strip()

    def ec2_metadata():
        """Instance details from the EC2 metadata service (IMDSv2). None when not on EC2."""
        if "v" in meta_cache:
            return meta_cache["v"]
        result = None
        try:
            req = urllib.request.Request("http://169.254.169.254/latest/api/token", method="PUT",
                                         headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
            token = urllib.request.urlopen(req, timeout=1).read().decode()

            def get(path):
                r = urllib.request.Request("http://169.254.169.254/latest/meta-data/" + path,
                                           headers={"X-aws-ec2-metadata-token": token})
                return urllib.request.urlopen(r, timeout=1).read().decode()
            result = {"id": get("instance-id"), "type": get("instance-type"),
                      "az": get("placement/availability-zone")}
        except Exception:
            result = None
        meta_cache["v"] = result
        return result

    def share_digest(doc_id, password):
        """Keyed hash: lets us verify a share password without storing it (attacker lacks SECRET_KEY)."""
        return hmac.new(app.config["SECRET_KEY"].encode(), f"share:{doc_id}:{password}".encode(),
                        hashlib.sha256).hexdigest()[:40]

    def csv_safe(value):
        value = str(value)
        return "'" + value if value[:1] in ("=", "+", "-", "@") else value

    # ------------------------------------------------------------ security glue
    def csrf_token():
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_hex(16)
        return session["_csrf"]

    app.jinja_env.globals.update(csrf_token=csrf_token, app_version=APP_VERSION, developer=DEVELOPER)

    @app.before_request
    def make_sure_schema():
        if not schema["ok"] and request.endpoint != "health":
            ensure_schema()

    @app.errorhandler(Exception)
    def unhandled(exc):
        if isinstance(exc, HTTPException):
            return exc
        app.logger.exception("Unhandled error on %s", request.path)
        return f"Internal error ({type(exc).__name__}). Check /health and the server logs.", 500

    @app.before_request
    def csrf_protect():
        if request.method == "POST" and not app.config.get("TESTING_NO_CSRF"):
            sent, expected = request.form.get("_csrf"), session.get("_csrf")
            if not sent or not expected or not secrets.compare_digest(sent, expected):
                abort(400, "Invalid CSRF token")

    @app.after_request
    def secure_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    def current_user():
        uid = session.get("uid")
        return db.one("SELECT id, username, created_at FROM users WHERE id = ?", (uid,)) if uid else None

    def login_required(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not current_user():
                flash("Please log in first.", "error")
                return redirect(url_for("login"))
            return fn(*a, **kw)
        return wrapper

    def own_doc(doc_id, trashed=False):
        cond = "deleted_at IS NOT NULL" if trashed else "deleted_at IS NULL"
        doc = db.one(f"SELECT * FROM documents WHERE id = ? AND user_id = ? AND {cond}",
                     (doc_id, current_user()["id"]))
        if not doc:
            abort(404)
        return doc

    # --------------------------------------------------------------- public pages
    @app.route("/")
    def index():
        return render_template("index.html", user=current_user())

    @app.route("/health")
    def health():
        try:
            ensure_schema()
            db.one("SELECT 1 AS ok")
            return {"status": "ok", "database": "PostgreSQL" if db.is_pg else "SQLite",
                    "storage": store.kind, "schema": schema["ok"], "version": APP_VERSION}, 200
        except Exception as exc:  # pragma: no cover
            return {"status": "error", "database": "PostgreSQL" if db.is_pg else "SQLite",
                    "detail": f"{type(exc).__name__}: {exc}"[:300]}, 500

    def collect_status():
        checks = [{"layer": "PaaS", "service": "AWS Elastic Beanstalk (Python 3.12)", "ok": True, "ms": None,
                   "detail": f"CloudDocVault v{APP_VERSION}, Python {sys.version.split()[0]}, gunicorn behind nginx"}]
        meta = ec2_metadata()
        checks.append({"layer": "IaaS", "ok": True, "ms": None,
                       "service": "Amazon EC2 instance" if meta else "Local machine (no cloud needed)",
                       "detail": (f"{meta['id']} - {meta['type']} - {meta['az']}" if meta
                                  else f"Running on host {socket.gethostname()} - works without AWS")})
        t0 = time.perf_counter()
        try:
            db.one("SELECT 1 AS ok")
            checks.append({"layer": "DBaaS", "service": "Amazon RDS PostgreSQL" if db.is_pg else "SQLite (local file)",
                           "ok": True, "ms": round((time.perf_counter() - t0) * 1000, 1),
                           "detail": "Database connection is healthy"})
        except Exception as exc:
            checks.append({"layer": "DBaaS", "service": "Database", "ok": False, "ms": None,
                           "detail": type(exc).__name__})
        t0 = time.perf_counter()
        try:
            store.ping()
            is_s3 = store.kind == "AWS S3"
            checks.append({"layer": "Storage", "service": "Amazon S3 bucket" if is_s3 else "Local disk", "ok": True,
                           "ms": round((time.perf_counter() - t0) * 1000, 1),
                           "detail": "Bucket reachable, files encrypted at rest (SSE-AES256)" if is_s3
                           else "Upload folder is writable"})
        except Exception as exc:
            checks.append({"layer": "Storage", "service": store.kind, "ok": False, "ms": None,
                           "detail": type(exc).__name__})
        checks.append({"layer": "Security", "service": "IAM role, Security Groups, app-level protection", "ok": True,
                       "ms": None, "detail": "scrypt password hashing, CSRF tokens, secure headers, HttpOnly cookies, "
                                             "login throttling, signed expiring share links, audit log"})
        return checks

    @app.route("/status")
    def status():
        """Live view of the cloud services behind the app (handy for the demo)."""
        checks = collect_status()
        up = int(time.time() - STARTED_AT)
        return render_template("status.html", user=current_user(), checks=checks,
                               all_ok=all(c["ok"] for c in checks), region=os.environ.get("AWS_REGION", "local"),
                               uptime=f"{up // 3600}h {(up % 3600) // 60}m {up % 60}s", now=now_str())

    @app.route("/status.json")
    def status_json():
        checks = collect_status()
        return {"app": "CloudDocVault", "version": APP_VERSION, "developer": DEVELOPER,
                "all_ok": all(c["ok"] for c in checks), "services": checks}

    # ------------------------------------------------------------ auth
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
                flash("Username: 3-30 letters, digits or underscore.", "error")
            elif len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
            elif db.one("SELECT id FROM users WHERE username = ?", (username,)):
                flash("Username already taken.", "error")
            else:
                db.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                           (username, generate_password_hash(password), now_str()))
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
        return render_template("register.html", user=None)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            key = f"{client_ip()}:{username.lower()}"
            count, first = fails.get(key, (0, 0))
            if count >= MAX_FAILS and time.time() - first < LOCK_SECONDS:
                wait = int(LOCK_SECONDS - (time.time() - first)) // 60 + 1
                flash(f"Too many failed attempts. Try again in about {wait} minute(s).", "error")
                return render_template("login.html", user=None)
            if count and time.time() - first >= LOCK_SECONDS:
                fails.pop(key, None)
            row = db.one("SELECT id, password_hash FROM users WHERE username = ?", (username,))
            if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
                fails.pop(key, None)
                session.clear()
                session["uid"] = row["id"]
                log_activity(row["id"], "login", f"Signed in from {client_ip()}")
                return redirect(url_for("dashboard"))
            c, f = fails.get(key, (0, time.time()))
            fails[key] = (c + 1, f)
            if row:
                log_activity(row["id"], "failed login", f"Wrong password from {client_ip()}")
            flash("Invalid username or password.", "error")
        return render_template("login.html", user=None)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("index"))

    # --------------------------------------------------------------- dashboard
    def enrich(doc):
        ext = ext_of(doc["original_name"])
        cat = EXT_CATEGORY.get(ext, "Documents")
        doc.update(ext=ext, cat=cat, icon=CAT_ICON[cat], color=CAT_COLOR[cat],
                   previewable=ext in PREVIEW_MIME, is_image=cat == "Images",
                   starred=bool(doc.get("starred")), downloads=int(doc.get("downloads") or 0))
        return doc

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = current_user()
        q = request.args.get("q", "").strip()
        sort = request.args.get("sort", "new")
        cat = request.args.get("cat", "")
        only_starred = request.args.get("starred") == "1"
        rows = [enrich(d) for d in db.query(
            "SELECT id, original_name, size_bytes, uploaded_at, downloads, starred, deleted_at "
            "FROM documents WHERE user_id = ? ORDER BY id DESC", (user["id"],))]
        active = [d for d in rows if not d["deleted_at"]]
        trash_rows = [d for d in rows if d["deleted_at"]]

        docs = list(active)
        if q:
            docs = [d for d in docs if q.lower() in d["original_name"].lower()]
        if cat in CATEGORIES:
            docs = [d for d in docs if d["cat"] == cat]
        if only_starred:
            docs = [d for d in docs if d["starred"]]
        if sort == "name":
            docs.sort(key=lambda d: d["original_name"].lower())
        elif sort == "size":
            docs.sort(key=lambda d: d["size_bytes"], reverse=True)
        elif sort == "downloads":
            docs.sort(key=lambda d: d["downloads"], reverse=True)
        thumbs = 0
        for d in docs:  # image thumbnails: small images only, and not too many
            d["thumb"] = d["is_image"] and d["size_bytes"] <= 1024 * 1024 and thumbs < 8
            thumbs += 1 if d["thumb"] else 0

        used = used_bytes(user["id"])
        quota = app.config["QUOTA_BYTES"]
        active_bytes = sum(d["size_bytes"] for d in active)

        # donut chart: active storage by file category (stroke-dasharray trick, circumference = 100)
        segments, cum = [], 0.0
        total_for_chart = active_bytes or 1
        for name in CATEGORIES:
            members = [d for d in active if d["cat"] == name]
            b = sum(d["size_bytes"] for d in members)
            pct = round(b * 100 / total_for_chart, 2) if active_bytes else 0
            segments.append({"cat": name, "color": CAT_COLOR[name], "bytes": b, "count": len(members),
                             "pct": pct, "offset": round(25 - cum, 2), "gap": round(100 - pct, 2)})
            cum += pct

        # uploads per day, last 14 days (uses every row, including trashed ones)
        today = datetime.now(timezone.utc).date()
        days = [(today - timedelta(days=i)) for i in range(13, -1, -1)]
        per_day = {}
        for d in rows:
            per_day[d["uploaded_at"][:10]] = per_day.get(d["uploaded_at"][:10], 0) + 1
        peak = max([per_day.get(str(x), 0) for x in days] + [1])
        bars = [{"label": x.strftime("%d/%m"), "n": per_day.get(str(x), 0),
                 "h": round(62 * per_day.get(str(x), 0) / peak), "x": i * 22} for i, x in enumerate(days)]

        shares = db.one("SELECT COUNT(*) AS n FROM activity WHERE user_id = ? AND action = ?",
                        (user["id"], "share"))["n"]
        activity = db.query("SELECT action, detail, created_at FROM activity WHERE user_id = ? "
                            "ORDER BY id DESC LIMIT 8", (user["id"],))
        cat_counts = {name: sum(1 for d in active if d["cat"] == name) for name in CATEGORIES}
        return render_template(
            "dashboard.html", user=user, docs=docs, storage=store.kind,
            database="PostgreSQL (RDS)" if db.is_pg else "SQLite (local)", q=q, sort=sort, cat=cat,
            only_starred=only_starred, used=used, quota=quota, active_bytes=active_bytes,
            percent=min(100, round(used * 100 / quota)) if quota else 0,
            n_files=len(active), n_starred=sum(1 for d in active if d["starred"]),
            n_trash=len(trash_rows), total_downloads=sum(d["downloads"] for d in active),
            shares=int(shares), segments=segments, bars=bars, bar_max=peak, activity=activity,
            share_choices=SHARE_CHOICES, categories=list(CATEGORIES), cat_counts=cat_counts,
            cat_color=CAT_COLOR, cat_icon=CAT_ICON)

    # --------------------------------------------------------------- file actions
    @app.route("/upload", methods=["POST"])
    @login_required
    def upload():
        files = [f for f in request.files.getlist("file") if f and f.filename]
        if not files:
            flash("Choose a file first.", "error")
            return redirect(url_for("dashboard"))
        uid = current_user()["id"]
        used = used_bytes(uid)
        done, problems = 0, []
        for f in files:
            name = secure_filename(f.filename)
            ext = ext_of(name)
            if ext not in ALLOWED_EXT:
                problems.append(f"{f.filename}: file type not allowed")
                continue
            data = f.read()
            if not data:
                problems.append(f"{name}: file is empty")
            elif len(data) > MAX_FILE_BYTES:
                problems.append(f"{name}: larger than 5 MB")
            elif used + len(data) > app.config["QUOTA_BYTES"]:
                problems.append(f"{name}: storage quota ({human(app.config['QUOTA_BYTES'])}) exceeded")
            else:
                key = f"{uuid.uuid4().hex}.{ext}"
                store.save(io.BytesIO(data), key)
                db.execute("INSERT INTO documents (user_id, original_name, stored_key, size_bytes, uploaded_at) "
                           "VALUES (?, ?, ?, ?, ?)",
                           (uid, name, key, len(data), datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")))
                log_activity(uid, "upload", f"{name} ({human(len(data))})")
                used += len(data)
                done += 1
        if done:
            flash(f"{done} file(s) uploaded.", "success")
        for p in problems:
            flash(p, "error")
        return redirect(url_for("dashboard"))

    @app.route("/download/<int:doc_id>")
    @login_required
    def download(doc_id):
        doc = own_doc(doc_id)
        db.execute("UPDATE documents SET downloads = downloads + 1 WHERE id = ?", (doc_id,))
        log_activity(doc["user_id"], "download", doc["original_name"])
        return send_file(store.load(doc["stored_key"]), as_attachment=True, download_name=doc["original_name"])

    @app.route("/preview/<int:doc_id>")
    @login_required
    def preview(doc_id):
        doc = own_doc(doc_id)
        mime = PREVIEW_MIME.get(ext_of(doc["original_name"]))
        if not mime:
            abort(404)
        resp = send_file(store.load(doc["stored_key"]), mimetype=mime, as_attachment=False,
                         download_name=doc["original_name"])
        resp.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'self'; style-src 'unsafe-inline'"
        return resp

    @app.route("/download-all")
    @login_required
    def download_all():
        user = current_user()
        docs = db.query("SELECT original_name, stored_key FROM documents WHERE user_id = ? AND deleted_at IS NULL "
                        "ORDER BY id", (user["id"],))
        if not docs:
            flash("You have no files to export.", "error")
            return redirect(url_for("dashboard"))
        buf, seen = io.BytesIO(), {}
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for d in docs:
                name = d["original_name"]
                if name in seen:
                    seen[name] += 1
                    stem, dot, ext = name.rpartition(".")
                    name = f"{stem} ({seen[name]}){dot}{ext}" if dot else f"{name} ({seen[name]})"
                else:
                    seen[name] = 0
                z.writestr(name, store.load(d["stored_key"]).read())
        buf.seek(0)
        log_activity(user["id"], "export", f"ZIP of {len(docs)} file(s)")
        return send_file(buf, as_attachment=True, download_name=f"clouddocvault-{user['username']}.zip",
                         mimetype="application/zip")

    @app.route("/rename/<int:doc_id>", methods=["POST"])
    @login_required
    def rename(doc_id):
        doc = own_doc(doc_id)
        new = secure_filename(request.form.get("name", "").strip())
        old_ext = ext_of(doc["original_name"])
        if new and ext_of(new) != old_ext:
            new = f"{new.rsplit('.', 1)[0] if '.' in new else new}.{old_ext}"  # keep the real extension
        if not new or new.startswith("."):
            flash("Enter a valid file name.", "error")
        else:
            db.execute("UPDATE documents SET original_name = ? WHERE id = ?", (new[:200], doc_id))
            log_activity(doc["user_id"], "rename", f"{doc['original_name']} -> {new[:200]}")
            flash("File renamed.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/star/<int:doc_id>", methods=["POST"])
    @login_required
    def star(doc_id):
        doc = own_doc(doc_id)
        db.execute("UPDATE documents SET starred = ? WHERE id = ?", (0 if doc["starred"] else 1, doc_id))
        return redirect(url_for("dashboard"))

    @app.route("/delete/<int:doc_id>", methods=["POST"])
    @login_required
    def delete(doc_id):
        doc = own_doc(doc_id)
        db.execute("UPDATE documents SET deleted_at = ? WHERE id = ?", (now_str(), doc_id))
        log_activity(doc["user_id"], "trash", doc["original_name"])
        flash("Moved to trash. You can restore it from the Trash page.", "success")
        return redirect(url_for("dashboard"))

    # ------------------------------------------------------------------- trash
    @app.route("/trash")
    @login_required
    def trash():
        user = current_user()
        docs = [enrich(d) for d in db.query(
            "SELECT id, original_name, size_bytes, uploaded_at, downloads, starred, deleted_at FROM documents "
            "WHERE user_id = ? AND deleted_at IS NOT NULL ORDER BY deleted_at DESC", (user["id"],))]
        return render_template("trash.html", user=user, docs=docs)

    @app.route("/restore/<int:doc_id>", methods=["POST"])
    @login_required
    def restore(doc_id):
        doc = own_doc(doc_id, trashed=True)
        db.execute("UPDATE documents SET deleted_at = NULL WHERE id = ?", (doc_id,))
        log_activity(doc["user_id"], "restore", doc["original_name"])
        flash("File restored.", "success")
        return redirect(url_for("trash"))

    def purge_doc(doc):
        store.delete(doc["stored_key"])
        db.execute("DELETE FROM documents WHERE id = ?", (doc["id"],))

    @app.route("/purge/<int:doc_id>", methods=["POST"])
    @login_required
    def purge(doc_id):
        doc = own_doc(doc_id, trashed=True)
        purge_doc(doc)
        log_activity(doc["user_id"], "delete forever", doc["original_name"])
        flash("File deleted permanently.", "success")
        return redirect(url_for("trash"))

    @app.route("/trash/empty", methods=["POST"])
    @login_required
    def empty_trash():
        uid = current_user()["id"]
        docs = db.query("SELECT id, stored_key FROM documents WHERE user_id = ? AND deleted_at IS NOT NULL", (uid,))
        for d in docs:
            purge_doc(d)
        log_activity(uid, "empty trash", f"{len(docs)} file(s) deleted permanently")
        flash(f"Trash emptied ({len(docs)} file(s)).", "success")
        return redirect(url_for("trash"))

    # ------------------------------------------------------------- share links
    @app.route("/share/<int:doc_id>", methods=["POST"])
    @login_required
    def share(doc_id):
        doc = own_doc(doc_id)
        seconds, label = SHARE_CHOICES.get(request.form.get("expiry", "24h"), SHARE_CHOICES["24h"])
        password = request.form.get("password", "").strip()
        payload = {"d": doc["id"], "t": seconds, "pw": share_digest(doc["id"], password) if password else ""}
        link = url_for("shared_download", token=share_ser.dumps(payload), _external=True)
        log_activity(doc["user_id"], "share", f"{doc['original_name']} (expires in {label}"
                                              f"{', password protected' if password else ''})")
        return render_template("share.html", user=current_user(), doc=doc, link=link, label=label,
                               protected=bool(password))

    def share_payload(token):
        """Return (payload, None) or (None, (message, http_status))."""
        try:
            payload, issued = share_ser.loads(token, max_age=max(s for s, _ in SHARE_CHOICES.values()),
                                              return_timestamp=True)
        except SignatureExpired:
            return None, ("This share link has expired.", 410)
        except BadSignature:
            return None, ("This share link is not valid.", 404)
        if time.time() - issued.timestamp() > payload["t"]:
            return None, ("This share link has expired.", 410)
        return payload, None

    @app.route("/s/<token>", methods=["GET", "POST"])
    def shared_download(token):
        """Public, time-limited download link (no login needed; signed, expiring, optional password)."""
        payload, err = share_payload(token)
        if err:
            return render_template("shared_error.html", user=None, msg=err[0]), err[1]
        doc = db.one("SELECT * FROM documents WHERE id = ? AND deleted_at IS NULL", (payload["d"],))
        if not doc:
            return render_template("shared_error.html", user=None, msg="This file is no longer available."), 404
        if payload.get("pw"):
            if request.method == "GET":
                return render_template("shared_password.html", user=None, doc=doc, token=token, wrong=False)
            if not hmac.compare_digest(share_digest(doc["id"], request.form.get("password", "").strip()),
                                       payload["pw"]):
                time.sleep(0.6)  # slows down guessing
                log_activity(doc["user_id"], "failed share password", doc["original_name"])
                return render_template("shared_password.html", user=None, doc=doc, token=token, wrong=True), 403
        elif request.method == "POST":
            abort(405)
        db.execute("UPDATE documents SET downloads = downloads + 1 WHERE id = ?", (doc["id"],))
        log_activity(doc["user_id"], "shared download", doc["original_name"])
        return send_file(store.load(doc["stored_key"]), as_attachment=True, download_name=doc["original_name"])

    # -------------------------------------------------------- activity + account
    @app.route("/activity")
    @login_required
    def activity_page():
        user = current_user()
        rows = db.query("SELECT action, detail, created_at FROM activity WHERE user_id = ? "
                        "ORDER BY id DESC LIMIT 100", (user["id"],))
        return render_template("activity.html", user=user, rows=rows)

    @app.route("/activity.csv")
    @login_required
    def activity_csv():
        user = current_user()
        rows = db.query("SELECT created_at, action, detail FROM activity WHERE user_id = ? ORDER BY id DESC",
                        (user["id"],))
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["time_utc", "action", "details"])
        for r in rows:
            w.writerow([csv_safe(r["created_at"]), csv_safe(r["action"]), csv_safe(r["detail"])])
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=activity-{user['username']}.csv"})

    @app.route("/account", methods=["GET", "POST"])
    @login_required
    def account():
        user = current_user()
        if request.method == "POST":
            row = db.one("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
            current, new, again = (request.form.get(k, "") for k in ("current", "new", "again"))
            if not check_password_hash(row["password_hash"], current):
                flash("Current password is wrong.", "error")
            elif len(new) < 8:
                flash("New password must be at least 8 characters.", "error")
            elif new != again:
                flash("The two new passwords do not match.", "error")
            else:
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (generate_password_hash(new), user["id"]))
                log_activity(user["id"], "password changed", "Account password updated")
                flash("Password updated.", "success")
                return redirect(url_for("account"))
        stats = db.one("SELECT COUNT(*) AS n, COALESCE(SUM(size_bytes), 0) AS b FROM documents "
                       "WHERE user_id = ? AND deleted_at IS NULL", (user["id"],))
        return render_template("account.html", user=user, n_files=int(stats["n"]), size=int(stats["b"]),
                               used=used_bytes(user["id"]), quota=app.config["QUOTA_BYTES"])

    @app.errorhandler(413)
    def too_large(_):
        flash("Upload too large (max 5 MB per file).", "error")
        return redirect(url_for("dashboard"))

    return app


app = create_app()
application = app  # Elastic Beanstalk looks for "application"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
