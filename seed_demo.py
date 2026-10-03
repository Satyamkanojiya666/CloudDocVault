"""Create a demo account with sample files and activity so the dashboard looks full (no AWS needed).

Usage:   python seed_demo.py        ->   login: demo / Demo@12345
"""
import io
import os
import random
import struct
import uuid
import zlib
from datetime import datetime, timedelta, timezone

from werkzeug.security import generate_password_hash

from db import Database
from storage import get_storage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = Database(os.environ.get("DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "docvault.db")))
STORE = get_storage(BASE_DIR)


def make_png(r, g, b, size=96):
    rows = b"".join(b"\x00" + b"".join(bytes((min(255, r + x), min(255, g + y), b)) for x in range(size))
                    for y in range(size))

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))


def make_pdf(text):
    objs = ["<</Type/Catalog/Pages 2 0 R>>", "<</Type/Pages/Kids[3 0 R]/Count 1>>",
            "<</Type/Page/Parent 2 0 R/MediaBox[0 0 360 160]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>"]
    stream = f"BT /F1 20 Tf 24 80 Td ({text}) Tj ET"
    objs.append(f"<</Length {len(stream)}>>\nstream\n{stream}\nendstream")
    objs.append("<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>")
    out, offsets = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{o}\nendobj\n".encode()
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += "".join(f"{o:010d} 00000 n \n" for o in offsets).encode()
    return out + f"trailer\n<</Size {len(objs) + 1}/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n".encode()


def main():
    DB.init_schema()
    if DB.one("SELECT id FROM users WHERE username = ?", ("demo",)):
        print("Demo user already exists. Login: demo / Demo@12345")
        return
    now = datetime.now(timezone.utc)
    DB.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
               ("demo", generate_password_hash("Demo@12345"), (now - timedelta(days=20)).strftime("%Y-%m-%d %H:%M:%S")))
    uid = DB.one("SELECT id FROM users WHERE username = ?", ("demo",))["id"]
    files = [  # name, bytes, days ago, downloads, starred
        ("cloud-computing-notes.pdf", make_pdf("Cloud computing notes"), 12, 5, 1),
        ("project-report.pdf", make_pdf("CloudDocVault project report"), 9, 8, 1),
        ("syllabus.txt", b"Unit 1: IaaS\nUnit 2: PaaS\nUnit 3: DBaaS\nUnit 4: Storage\nUnit 5: Security\n", 9, 2, 0),
        ("expenses.csv", b"item,amount\nbooks,450\ncloud lab,0\ntravel,120\n", 6, 3, 0),
        ("marks.csv", b"subject,marks\nCloud,92\nAI,88\nDBMS,90\n", 5, 1, 1),
        ("architecture.png", make_png(40, 90, 200), 4, 6, 1),
        ("banner.png", make_png(200, 60, 120), 3, 2, 0),
        ("dashboard-screenshot.png", make_png(30, 150, 90), 1, 4, 0),
        ("viva-questions.txt", b"1. Difference between IaaS, PaaS and SaaS?\n2. What is DBaaS?\n", 0, 1, 0),
    ]
    random.seed(7)
    for name, data, ago, downloads, starred in files:
        when = now - timedelta(days=ago, hours=random.randint(0, 5))
        ext = name.rsplit(".", 1)[1]
        key = f"{uuid.uuid4().hex}.{ext}"
        STORE.save(io.BytesIO(data), key)
        DB.execute("INSERT INTO documents (user_id, original_name, stored_key, size_bytes, uploaded_at, downloads, starred) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?)", (uid, name, key, len(data), when.strftime("%Y-%m-%d %H:%M"), downloads, starred))
        DB.execute("INSERT INTO activity (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)",
                   (uid, "upload", name, when.strftime("%Y-%m-%d %H:%M:%S")))
    for ago, action, detail in [(11, "login", "Signed in"), (8, "share", "project-report.pdf (expires in 24 hours)"),
                                (7, "shared download", "project-report.pdf"), (2, "share", "architecture.png (expires in 1 hour, password protected)"),
                                (0, "login", "Signed in")]:
        DB.execute("INSERT INTO activity (user_id, action, detail, created_at) VALUES (?, ?, ?, ?)",
                   (uid, action, detail, (now - timedelta(days=ago)).strftime("%Y-%m-%d %H:%M:%S")))
    print("Demo data created. Login: demo / Demo@12345")


if __name__ == "__main__":
    main()
