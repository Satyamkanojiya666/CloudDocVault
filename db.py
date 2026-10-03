"""Thin database layer: SQLite locally, PostgreSQL (AWS RDS / any DBaaS) in the cloud."""
import os
import sqlite3


class Database:
    def __init__(self, url=None):
        url = url or ""
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        self.url = url
        self.is_pg = url.startswith("postgresql://")
        self.sqlite_path = url.replace("sqlite:///", "", 1) if url.startswith("sqlite:///") else "docvault.db"

    def connect(self):
        if self.is_pg:
            import psycopg2  # imported lazily so local runs need no driver
            return psycopg2.connect(self.url, connect_timeout=10)
        conn = sqlite3.connect(self.sqlite_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _sql(self, sql):
        return sql.replace("?", "%s") if self.is_pg else sql

    def execute(self, sql, params=()):
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(self._sql(sql), params)
            conn.commit()
        finally:
            conn.close()

    def query(self, sql, params=()):
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(self._sql(sql), params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
        finally:
            conn.close()

    def one(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def init_schema(self):
        pk = "SERIAL PRIMARY KEY" if self.is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
        stmts = [
            f"""CREATE TABLE IF NOT EXISTS users (
            id {pk},
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at VARCHAR(64) NOT NULL)""",
            f"""CREATE TABLE IF NOT EXISTS documents (
            id {pk},
            user_id INTEGER NOT NULL,
            original_name VARCHAR(255) NOT NULL,
            stored_key VARCHAR(255) UNIQUE NOT NULL,
            size_bytes INTEGER NOT NULL,
            uploaded_at VARCHAR(64) NOT NULL,
            downloads INTEGER NOT NULL DEFAULT 0,
            starred INTEGER NOT NULL DEFAULT 0,
            deleted_at VARCHAR(64))""",
            f"""CREATE TABLE IF NOT EXISTS activity (
            id {pk},
            user_id INTEGER NOT NULL,
            action VARCHAR(40) NOT NULL,
            detail VARCHAR(255) NOT NULL,
            created_at VARCHAR(64) NOT NULL)""",
        ]
        conn = self.connect()
        try:
            cur = conn.cursor()
            if self.is_pg:
                # serialise concurrent workers so CREATE TABLE cannot race
                cur.execute("SELECT pg_advisory_xact_lock(727274)")
            for stmt in stmts:
                cur.execute(stmt)
            if self.is_pg:
                # tables created by an older version had VARCHAR(30): widen them
                cur.execute("ALTER TABLE users ALTER COLUMN created_at TYPE VARCHAR(64)")
                cur.execute("ALTER TABLE documents ALTER COLUMN uploaded_at TYPE VARCHAR(64)")
            # columns added in v7 - add them to tables created by older versions
            for col, typ in (("downloads", "INTEGER NOT NULL DEFAULT 0"),
                             ("starred", "INTEGER NOT NULL DEFAULT 0"),
                             ("deleted_at", "VARCHAR(64)")):
                if self.is_pg:
                    cur.execute(f"ALTER TABLE documents ADD COLUMN IF NOT EXISTS {col} {typ}")
                else:
                    try:
                        cur.execute(f"ALTER TABLE documents ADD COLUMN {col} {typ}")
                    except sqlite3.OperationalError:
                        pass  # column already there
            conn.commit()
        finally:
            conn.close()
