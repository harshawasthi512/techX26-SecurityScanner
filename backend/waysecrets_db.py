import aiosqlite
from datetime import datetime
import json
from typing import List, Dict, Optional

DATABASE_NAME = "waysecrets.db"

async def init_waysecrets_db():
    """Initialize the WaySecrets database"""
    async with aiosqlite.connect(DATABASE_NAME) as db:
        # Main scans table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS waysecrets_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                results TEXT DEFAULT '{}',
                stats TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_duration REAL DEFAULT 0
            )
        """)
        
        # Create indexes for faster queries
        await db.execute("CREATE INDEX IF NOT EXISTS idx_ws_domain ON waysecrets_scans(domain)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_ws_status ON waysecrets_scans(status)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_ws_created ON waysecrets_scans(created_at)")
        
        await db.commit()

async def save_waysecrets_scan(domain: str) -> int:
    """Save a new WaySecrets scan"""
    async with aiosqlite.connect(DATABASE_NAME) as db:
        cursor = await db.execute(
            "INSERT INTO waysecrets_scans (domain, updated_at) VALUES (?, ?)",
            (domain, datetime.now().isoformat())
        )
        await db.commit()
        return cursor.lastrowid

async def update_waysecrets_scan(scan_id: int, status: str, results: Dict = None, stats: Dict = None):
    """Update a WaySecrets scan"""
    async with aiosqlite.connect(DATABASE_NAME) as db:
        if results and stats:
            results_json = json.dumps(results)
            stats_json = json.dumps(stats)
            await db.execute(
                """UPDATE waysecrets_scans 
                   SET status = ?, results = ?, stats = ?, updated_at = ?, scan_duration = ? 
                   WHERE id = ?""",
                (status, results_json, stats_json, datetime.now().isoformat(), 
                 stats.get('scan_duration', 0), scan_id)
            )
        else:
            await db.execute(
                "UPDATE waysecrets_scans SET status = ?, updated_at = ? WHERE id = ?",
                (status, datetime.now().isoformat(), scan_id)
            )
        await db.commit()

async def get_waysecrets_scan_history(limit: int = 50) -> List[Dict]:
    """Get WaySecrets scan history"""
    async with aiosqlite.connect(DATABASE_NAME) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            """SELECT id, domain, status, stats, created_at, updated_at, scan_duration 
               FROM waysecrets_scans 
               ORDER BY created_at DESC LIMIT ?""", 
            (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
            scans = []
            for row in rows:
                scan = dict(row)
                # Parse JSON fields
                if scan.get('stats'):
                    try:
                        scan['stats'] = json.loads(scan['stats'])
                    except:
                        scan['stats'] = {}
                scans.append(scan)
            return scans

async def get_waysecrets_scan_by_id(scan_id: int) -> Optional[Dict]:
    """Get a specific WaySecrets scan by ID"""
    async with aiosqlite.connect(DATABASE_NAME) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM waysecrets_scans WHERE id = ?", (scan_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                scan = dict(row)
                # Parse JSON fields
                if scan.get('results'):
                    try:
                        scan['results'] = json.loads(scan['results'])
                    except:
                        scan['results'] = {}
                if scan.get('stats'):
                    try:
                        scan['stats'] = json.loads(scan['stats'])
                    except:
                        scan['stats'] = {}
                return scan
            return None

async def delete_waysecrets_scan(scan_id: int) -> bool:
    """Delete a WaySecrets scan"""
    async with aiosqlite.connect(DATABASE_NAME) as db:
        await db.execute("DELETE FROM waysecrets_scans WHERE id = ?", (scan_id,))
        await db.commit()
        return True

async def delete_all_waysecrets_scans() -> bool:
    """Delete all WaySecrets scans"""
    async with aiosqlite.connect(DATABASE_NAME) as db:
        await db.execute("DELETE FROM waysecrets_scans")
        await db.commit()
        return True

async def get_waysecrets_stats() -> Dict:
    """Get WaySecrets database statistics"""
    async with aiosqlite.connect(DATABASE_NAME) as db:
        db.row_factory = aiosqlite.Row
        
        # Get total scans count
        async with db.execute("SELECT COUNT(*) as total FROM waysecrets_scans") as cursor:
            total_row = await cursor.fetchone()
            total_count = total_row["total"] if total_row else 0
        
        # Get status counts
        status_counts = {}
        async with db.execute("SELECT status, COUNT(*) as count FROM waysecrets_scans GROUP BY status") as cursor:
            async for row in cursor:
                status_counts[row["status"]] = row["count"]
        
        # Get recent scans
        recent_scans = []
        async with db.execute(
            "SELECT domain, status, created_at FROM waysecrets_scans ORDER BY created_at DESC LIMIT 5"
        ) as cursor:
            async for row in cursor:
                recent_scans.append(dict(row))
        
        return {
            "total_scans": total_count,
            "status_counts": status_counts,
            "recent_scans": recent_scans,
            "database": DATABASE_NAME
        }