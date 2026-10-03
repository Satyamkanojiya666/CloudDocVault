"""End-to-end tests for CloudDocVault (run: python tests/test_app.py). Uses SQLite + a temp folder, no AWS needed."""
import io, os, re, sqlite3, sys, tempfile, time, zipfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as m
from storage import LocalStorage
from db import Database

tmp = tempfile.mkdtemp()
db_url = "sqlite:///" + os.path.join(tmp, "t.db")
old = sqlite3.connect(os.path.join(tmp, "t.db"))
old.executescript("""
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, created_at VARCHAR(64) NOT NULL);
CREATE TABLE documents (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, original_name VARCHAR(255) NOT NULL, stored_key VARCHAR(255) UNIQUE NOT NULL, size_bytes INTEGER NOT NULL, uploaded_at VARCHAR(64) NOT NULL);
INSERT INTO documents (user_id, original_name, stored_key, size_bytes, uploaded_at) VALUES (99, 'legacy.pdf', 'k1', 10, '2026-09-01 10:00');
""")
old.commit(); old.close()
Database(db_url).init_schema()
row = Database(db_url).one("SELECT downloads, starred, deleted_at FROM documents WHERE original_name='legacy.pdf'")
def ok(label, cond): print(("PASS " if cond else "FAIL ") + label); assert cond, label
ok("v6 -> v7 migration adds columns, keeps old rows", row == {"downloads": 0, "starred": 0, "deleted_at": None})
Database(db_url).init_schema(); ok("migration is idempotent (2nd run ok)", True)

app = m.create_app({"DATABASE_URL": db_url, "STORAGE": LocalStorage(os.path.join(tmp, "up")), "QUOTA_BYTES": 40000, "SECRET_KEY": "test-secret"})
c = app.test_client()
def csrf(client, path): return re.search(r'name="_csrf" value="([^"]+)"', client.get(path).get_data(as_text=True)).group(1)
def post(client, path, page="/dashboard", **data): return client.post(path, data={**data, "_csrf": csrf(client, page)})
def table(html): return html.split("Recent activity")[0]

ok("home page renders with developer name", "Satyam Kanojiya" in c.get("/").get_data(as_text=True))
ok("static app.js served", c.get("/static/app.js").status_code == 200)
ok("register", c.post("/register", data={"username": "satyam9", "password": "DocVault123", "_csrf": csrf(c, "/register")}).status_code == 302)
bad = app.test_client(); H = {"X-Forwarded-For": "9.9.9.9"}
for i in range(5): bad.post("/login", data={"username": "satyam9", "password": "wrong", "_csrf": csrf(bad, "/login")}, headers=H)
r = bad.post("/login", data={"username": "satyam9", "password": "DocVault123", "_csrf": csrf(bad, "/login")}, headers=H)
ok("login throttled after 5 failures (even with right password)", "Too many failed attempts" in r.get_data(as_text=True))
ok("throttle is per IP: legit user from another IP unaffected", c.post("/login", data={"username": "satyam9", "password": "DocVault123", "_csrf": csrf(c, "/login")}).status_code == 302)

png = b"\x89PNG\r\n\x1a\n" + b"0" * 300
r = c.post("/upload", data={"file": [(io.BytesIO(b"hello world"), "notes.txt"), (io.BytesIO(png), "pic.png"),
        (io.BytesIO(b"a,b\n1,2"), "data.csv"), (io.BytesIO(b"x"), "evil.exe"), (io.BytesIO(b"p" * 9000), "plan.pdf")],
        "_csrf": csrf(c, "/dashboard")}, content_type="multipart/form-data", follow_redirects=True)
t = r.get_data(as_text=True)
ok("multi-upload accepts 4, rejects .exe", "4 file(s) uploaded" in t and "evil.exe: file type not allowed" in t)
d = c.get("/dashboard").get_data(as_text=True)
ok("dashboard has stats, donut, bar chart, chips", all(x in d for x in ("Welcome back, satyam9", "Storage by file type", "last 14 days", "Favourites", "Images (1)")))
ok("image thumbnail shown for small image", 'class="thumb"' in d)
docs = {x["original_name"]: x["id"] for x in Database(db_url).query("SELECT id, original_name FROM documents WHERE user_id = 1")}

s = table(c.get("/dashboard?cat=Images").get_data(as_text=True)); ok("category filter", "pic.png" in s and "notes.txt" not in s)
post(c, f"/star/{docs['notes.txt']}")
s = table(c.get("/dashboard?starred=1").get_data(as_text=True)); ok("favourites filter", "notes.txt" in s and "pic.png" not in s)
post(c, f"/star/{docs['notes.txt']}"); ok("unstar", "notes.txt" not in table(c.get("/dashboard?starred=1").get_data(as_text=True)))

post(c, f"/rename/{docs['notes.txt']}", name="meeting minutes")
names = [x["original_name"] for x in Database(db_url).query("SELECT original_name FROM documents WHERE user_id = 1")]
ok("rename keeps .txt extension", "meeting_minutes.txt" in names)
post(c, f"/rename/{docs['notes.txt']}", name="../../etc/passwd.exe")
names = [x["original_name"] for x in Database(db_url).query("SELECT original_name FROM documents WHERE user_id = 1")]
ok("rename sanitises path tricks / extension swap", all("/" not in n and not n.endswith(".exe") for n in names))

r = c.get(f"/preview/{docs['pic.png']}"); ok("image preview inline with image/png", r.status_code == 200 and r.mimetype == "image/png")
ok("preview has its own CSP (object-src)", "object-src" in r.headers["Content-Security-Policy"])
ok("no preview for csv (404)", c.get(f"/preview/{docs['data.csv']}").status_code == 404)
c.get(f"/download/{docs['data.csv']}"); c.get(f"/download/{docs['data.csv']}")
s = table(c.get("/dashboard?sort=downloads").get_data(as_text=True)); ok("download counter + sort by most downloaded", s.index("data.csv") < s.index("plan.pdf"))
ok("dashboard CSP header intact", "default-src 'self'" in c.get("/dashboard").headers["Content-Security-Policy"])

r = c.get("/download-all"); z = zipfile.ZipFile(io.BytesIO(r.data))
ok("ZIP export contains all active files", r.status_code == 200 and len(z.namelist()) == 4 and "data.csv" in z.namelist())

r = post(c, f"/share/{docs['plan.pdf']}", expiry="24h"); body = r.get_data(as_text=True)
open_link = re.search(r'value="(http[^"]+/s/[^"]+)"', body).group(1); ok("open share link page + copy button", "copyBtn" in body)
anon = app.test_client(); p1 = "/s/" + open_link.split("/s/")[1]
ok("open link downloads without login", anon.get(p1).data == b"p" * 9000)
r = post(c, f"/share/{docs['pic.png']}", expiry="1h", password="s3cret!"); body = r.get_data(as_text=True)
p2 = "/s/" + re.search(r'value="(http[^"]+/s/[^"]+)"', body).group(1).split("/s/")[1]; ok("protected link says password required", "password" in body.lower())
r = anon.get(p2); ok("protected link shows unlock form (no file leaked)", r.status_code == 200 and b"PNG" not in r.data and "Unlock" in r.get_data(as_text=True))
r = anon.post(p2, data={"password": "nope", "_csrf": csrf(anon, p2)}); ok("wrong password -> 403", r.status_code == 403 and b"PNG" not in r.data)
r = anon.post(p2, data={"password": "s3cret!", "_csrf": csrf(anon, p2)}); ok("right password -> file", r.status_code == 200 and r.data == png)
ok("POST to open link not allowed", anon.post(p1, data={"_csrf": csrf(anon, "/login")}).status_code in (400, 405))
ok("tampered token -> 404", anon.get(p1[:-3] + "zzz").status_code == 404)
short = m.URLSafeTimedSerializer("test-secret", salt="docvault-share").dumps({"d": docs["plan.pdf"], "t": 1, "pw": ""}); time.sleep(2.1)
ok("expired link -> 410", anon.get("/s/" + short).status_code == 410)

post(c, f"/delete/{docs['plan.pdf']}")
ok("trashed file leaves dashboard + shared link dies", "plan.pdf" not in table(c.get("/dashboard").get_data(as_text=True)) and anon.get(p1).status_code == 404)
ok("trash page lists it", "plan.pdf" in c.get("/trash").get_data(as_text=True))
ok("trashed file cannot be downloaded (404)", c.get(f"/download/{docs['plan.pdf']}").status_code == 404)
post(c, f"/restore/{docs['plan.pdf']}", page="/trash"); ok("restore works", "plan.pdf" in table(c.get("/dashboard").get_data(as_text=True)))
post(c, f"/delete/{docs['plan.pdf']}"); post(c, f"/purge/{docs['plan.pdf']}", page="/trash")
ok("purge removes row", Database(db_url).one("SELECT id FROM documents WHERE id = ?", (docs["plan.pdf"],)) is None)
post(c, f"/delete/{docs['pic.png']}"); post(c, "/trash/empty", page="/trash")
ok("empty trash", Database(db_url).one("SELECT id FROM documents WHERE id = ?", (docs["pic.png"],)) is None)

a = c.get("/activity").get_data(as_text=True); ok("activity page lists key actions", all(x in a for x in ("upload", "rename", "share", "trash", "delete forever", "empty trash", "shared download", "failed share password")))
Database(db_url).execute("INSERT INTO activity (user_id, action, detail, created_at) VALUES (1, 'x', '=HYPERLINK(\"evil\")', '2026-01-01 00:00:00')")
r = c.get("/activity.csv"); ok("CSV export + formula injection neutralised", r.mimetype == "text/csv" and "'=HYPERLINK" in r.get_data(as_text=True))

ok("account page", "Member since" in c.get("/account").get_data(as_text=True))
post(c, "/account", page="/account", current="DocVault123", new="NewPass123", again="NewPass123")
c3 = app.test_client(); ok("new password works for login", c3.post("/login", data={"username": "satyam9", "password": "NewPass123", "_csrf": csrf(c3, "/login")}).status_code == 302)

c2 = app.test_client(); c2.post("/register", data={"username": "other01", "password": "DocVault123", "_csrf": csrf(c2, "/register")}); c2.post("/login", data={"username": "other01", "password": "DocVault123", "_csrf": csrf(c2, "/login")})
before = [x["original_name"] for x in Database(db_url).query("SELECT original_name FROM documents WHERE user_id=1")]
ok("other user cannot download my files", c2.get(f"/download/{docs['data.csv']}").status_code == 404)
post(c2, f"/rename/{docs['data.csv']}", name="hack")
ok("other user cannot rename my files", before == [x["original_name"] for x in Database(db_url).query("SELECT original_name FROM documents WHERE user_id=1")])
st = anon.get("/status"); t = st.get_data(as_text=True); ok("status page: layers + latency + architecture svg", st.status_code == 200 and all(x in t for x in ("PaaS", "IaaS", "DBaaS", "Storage", "Security", "Architecture", "Latency")))
j = anon.get("/status.json").get_json(); ok("status.json", j["developer"] == "Satyam Kanojiya" and len(j["services"]) == 5)
ok("health ok + version", anon.get("/health").get_json()["version"] == "7.0")
ok("quota enforced", "quota" in c.post("/upload", data={"file": (io.BytesIO(b"q" * 45000), "huge.pdf"), "_csrf": csrf(c, "/dashboard")}, content_type="multipart/form-data", follow_redirects=True).get_data(as_text=True))
ok("5MB per-file limit", "larger than 5 MB" in c.post("/upload", data={"file": (io.BytesIO(b"q" * (5 * 1024 * 1024 + 1)), "big.pdf"), "_csrf": csrf(c, "/dashboard")}, content_type="multipart/form-data", follow_redirects=True).get_data(as_text=True))
print("\nALL V7 TESTS PASSED")
