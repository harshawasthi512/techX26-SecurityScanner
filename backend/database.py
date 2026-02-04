import aiosqlite
from datetime import datetime
import json

DATABASE_NAME = "scans.db"

async def init_db():
    async with aiosqlite.connect(DATABASE_NAME) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_name TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                include_buckets BOOLEAN DEFAULT 0,
                status TEXT DEFAULT 'pending',
                findings TEXT DEFAULT '{}',
                total_repos INTEGER DEFAULT 0,
                scanned_repos INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Add index for faster queries
        await db.execute("CREATE INDEX IF NOT EXISTS idx_status ON scans(status)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON scans(created_at)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_org_name ON scans(org_name)")
        
        await db.commit()

async def save_scan(org_name: str, scan_type: str, include_buckets: bool):
    async with aiosqlite.connect(DATABASE_NAME) as db:
        cursor = await db.execute(
            "INSERT INTO scans (org_name, scan_type, include_buckets, updated_at) VALUES (?, ?, ?, ?)",
            (org_name, scan_type, 1 if include_buckets else 0, datetime.now().isoformat())
        )
        await db.commit()
        return cursor.lastrowid

async def update_scan_status(scan_id: int, status: str, findings: dict = None, 
                             total_repos: int = 0, scanned_repos: int = 0):
    async with aiosqlite.connect(DATABASE_NAME) as db:
        if findings:
            findings_json = json.dumps(findings)
            await db.execute(
                """UPDATE scans SET status = ?, findings = ?, total_repos = ?, 
                   scanned_repos = ?, updated_at = ? WHERE id = ?""",
                (status, findings_json, total_repos, scanned_repos, datetime.now().isoformat(), scan_id)
            )
        else:
            await db.execute(
                """UPDATE scans SET status = ?, total_repos = ?, scanned_repos = ?, 
                   updated_at = ? WHERE id = ?""",
                (status, total_repos, scanned_repos, datetime.now().isoformat(), scan_id)
            )
        await db.commit()

async def get_scan_history(limit: int = 50):
    async with aiosqlite.connect(DATABASE_NAME) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def get_scan_by_id(scan_id: int):
    async with aiosqlite.connect(DATABASE_NAME) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def delete_scan(scan_id: int):
    async with aiosqlite.connect(DATABASE_NAME) as db:
        await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await db.commit()
        return True

async def delete_all_scans():
    async with aiosqlite.connect(DATABASE_NAME) as db:
        await db.execute("DELETE FROM scans")
        await db.commit()
        return True