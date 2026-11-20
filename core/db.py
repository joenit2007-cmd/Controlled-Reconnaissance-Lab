"""
Database module for Controlled Reconnaissance Lab.
Handles SQLite connection, schema migrations, and CRUD operations for scans, findings, reports, and lab progress.
"""
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from core.config import DATABASE_PATH

def get_db_connection() -> sqlite3.Connection:
    """Return a configured SQLite database connection."""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """Initialize database tables and seed baseline lab data."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                profile TEXT DEFAULT 'default',
                status TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                duration REAL DEFAULT 0.0,
                summary TEXT,
                raw_output TEXT,
                parsed_json TEXT
            )
        """)

        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                target TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                remediation TEXT,
                status TEXT DEFAULT 'Open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE SET NULL
            )
        """)

        # Linux Fundamentals Progress table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS linux_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module_key TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                score INTEGER DEFAULT 0,
                completed INTEGER DEFAULT 0,
                notes TEXT,
                updated_at TEXT NOT NULL
            )
        """)

        # Generated Reports table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                report_filename TEXT NOT NULL,
                target TEXT NOT NULL,
                findings_count INTEGER DEFAULT 0,
                generated_at TEXT NOT NULL
            )
        """)

        conn.commit()

    # Seed baseline lab modules & initial sample findings
    seed_initial_data()

def seed_initial_data() -> None:
    """Seed educational modules and sample lab findings clearly marked as sample data."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Seed Linux modules if empty
        cursor.execute("SELECT COUNT(*) as count FROM linux_progress")
        if cursor.fetchone()["count"] == 0:
            modules = [
                ("files_dirs", "Files & Directory Structure (FHS)", 0, 0, "Explored /etc, /proc, /var/log"),
                ("permissions", "Linux Permissions & Special Bits", 0, 0, "Interactive chmod/chown practice"),
                ("users_groups", "User & Group Management", 0, 0, "/etc/passwd, /etc/shadow, sudoers audit"),
                ("processes", "Process Control & Signal Management", 0, 0, "ps, top, kill, signal handlers"),
                ("security_hardening", "Basic Linux Security & Hardening", 0, 0, "SSH, UFW, File Integrity, Logging")
            ]
            now = datetime.now().isoformat()
            cursor.executemany(
                "INSERT INTO linux_progress (module_key, title, score, completed, notes, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                [(m[0], m[1], m[2], m[3], m[4], now) for m in modules]
            )

        # Seed initial sample findings if empty
        cursor.execute("SELECT COUNT(*) as count FROM findings")
        if cursor.fetchone()["count"] == 0:
            now = datetime.now().isoformat()
            sample_findings = [
                (
                    None,
                    "[Sample Lab] Insecure Plaintext Service (FTP Port 21)",
                    "High",
                    "Network Reconnaissance",
                    "127.0.0.1",
                    "A sample lab scan revealed an unencrypted FTP service running on port 21 without TLS/SSL enforcement.",
                    "Port 21/tcp open ftp (vsftpd 3.0.3)",
                    "Disable legacy FTP or enforce FTPS/SFTP over SSH (Port 22). Restrict access to trusted private subnets.",
                    "Open",
                    now,
                    now
                ),
                (
                    None,
                    "[Sample Lab] Missing HTTP Security Headers",
                    "Low",
                    "Web Security",
                    "127.0.0.1",
                    "Web server response is missing defense-in-depth headers: Strict-Transport-Security, Content-Security-Policy, and X-Frame-Options.",
                    "HTTP/1.1 200 OK - Missing HSTS, CSP, X-Frame-Options",
                    "Configure the web application or reverse proxy (Nginx/Apache) to include strict security headers.",
                    "In Progress",
                    now,
                    now
                ),
                (
                    None,
                    "[Sample Lab] World-Writable File in /tmp (Simulated)",
                    "Medium",
                    "Linux Fundamentals",
                    "lab.local",
                    "File permissions check found /tmp/backup.sh configured with octal 777 (rwxrwxrwx), allowing any local user to modify execution logic.",
                    "-rwxrwxrwx 1 root root 420 /tmp/backup.sh",
                    "Restrict ownership and permissions using 'chmod 750 /tmp/backup.sh' and ensure root ownership.",
                    "Open",
                    now,
                    now
                )
            ]
            cursor.executemany("""
                INSERT INTO findings 
                (scan_id, title, severity, category, target, description, evidence, remediation, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, sample_findings)

        conn.commit()

# --- Scan CRUD ---
def save_scan(scan_type: str, target: str, profile: str, status: str,
              start_time: str, end_time: str, duration: float,
              summary: str, raw_output: str, parsed_json: Any) -> int:
    """Insert a scan record and return its ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans 
            (scan_type, target, profile, status, start_time, end_time, duration, summary, raw_output, parsed_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_type, target, profile, status,
            start_time, end_time, duration,
            summary, raw_output,
            json.dumps(parsed_json) if isinstance(parsed_json, (dict, list)) else str(parsed_json)
        ))
        conn.commit()
        return cursor.lastrowid

def get_all_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve recent scans ordered by start_time descending."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        scans = []
        for r in rows:
            d = dict(r)
            try:
                d["parsed_json"] = json.loads(d["parsed_json"]) if d["parsed_json"] else {}
            except Exception:
                pass
            scans.append(d)
        return scans

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Get scan by ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["parsed_json"] = json.loads(d["parsed_json"]) if d["parsed_json"] else {}
        except Exception:
            pass
        return d

def delete_scan_by_id(scan_id: int) -> bool:
    """Delete scan record."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0

# --- Findings CRUD ---
def save_finding(title: str, severity: str, category: str, target: str,
                 description: str, evidence: str, remediation: str,
                 status: str = "Open", scan_id: Optional[int] = None) -> int:
    """Insert a security finding."""
    now = datetime.now().isoformat()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO findings
            (scan_id, title, severity, category, target, description, evidence, remediation, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, title, severity, category, target, description, evidence, remediation, status, now, now))
        conn.commit()
        return cursor.lastrowid

def get_all_findings(severity_filter: Optional[str] = None, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch findings with optional filters."""
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    if severity_filter and severity_filter != "all":
        query += " AND severity = ?"
        params.append(severity_filter)
    if status_filter and status_filter != "all":
        query += " AND status = ?"
        params.append(status_filter)
    query += " ORDER BY id DESC"

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, tuple(params))
        return [dict(r) for r in cursor.fetchall()]

def update_finding(finding_id: int, updates: Dict[str, Any]) -> bool:
    """Update finding fields."""
    allowed_fields = {"title", "severity", "category", "target", "description", "evidence", "remediation", "status"}
    filtered_updates = {k: v for k, v in updates.items() if k in allowed_fields}
    if not filtered_updates:
        return False

    filtered_updates["updated_at"] = datetime.now().isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in filtered_updates.keys())
    values = list(filtered_updates.values()) + [finding_id]

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"UPDATE findings SET {set_clause} WHERE id = ?", tuple(values))
        conn.commit()
        return cursor.rowcount > 0

def delete_finding(finding_id: int) -> bool:
    """Delete finding by ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
        conn.commit()
        return cursor.rowcount > 0

# --- Reports CRUD ---
def save_report_meta(title: str, filename: str, target: str, findings_count: int) -> int:
    """Record a generated report."""
    now = datetime.now().isoformat()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO reports (title, report_filename, target, findings_count, generated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (title, filename, target, findings_count, now))
        conn.commit()
        return cursor.lastrowid

def get_all_reports() -> List[Dict[str, Any]]:
    """Get list of generated reports."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reports ORDER BY id DESC")
        return [dict(r) for r in cursor.fetchall()]

# --- Linux Progress CRUD ---
def get_linux_progress() -> List[Dict[str, Any]]:
    """Get progress records for Linux Fundamentals modules."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM linux_progress ORDER BY id ASC")
        return [dict(r) for r in cursor.fetchall()]

def update_linux_progress(module_key: str, score_delta: int = 10, completed: bool = True) -> bool:
    """Update a specific Linux module progress."""
    now = datetime.now().isoformat()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE linux_progress
            SET score = score + ?, completed = ?, updated_at = ?
            WHERE module_key = ?
        """, (score_delta, 1 if completed else 0, now, module_key))
        conn.commit()
        return cursor.rowcount > 0

# --- Dashboard Stats ---
def get_dashboard_metrics() -> Dict[str, Any]:
    """Calculate aggregated stats for the overview dashboard."""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as total FROM scans")
        total_scans = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as total FROM findings")
        total_findings = cursor.fetchone()["total"]

        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM findings 
            WHERE status != 'Remediated' 
            GROUP BY severity
        """)
        severity_counts = {r["severity"]: r["count"] for r in cursor.fetchall()}

        cursor.execute("""
            SELECT status, COUNT(*) as count 
            FROM findings 
            GROUP BY status
        """)
        status_counts = {r["status"]: r["count"] for r in cursor.fetchall()}

        cursor.execute("SELECT scan_type, COUNT(*) as count FROM scans GROUP BY scan_type")
        scan_type_counts = {r["scan_type"]: r["count"] for r in cursor.fetchall()}

        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "severity_counts": {
                "Critical": severity_counts.get("Critical", 0),
                "High": severity_counts.get("High", 0),
                "Medium": severity_counts.get("Medium", 0),
                "Low": severity_counts.get("Low", 0),
                "Informational": severity_counts.get("Informational", 0),
            },
            "status_counts": status_counts,
            "scan_type_counts": scan_type_counts
        }
