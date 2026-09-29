import sqlite3

DB_PATH = "events.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            sender TEXT,
            subject TEXT,
            risk_score REAL,
            classification TEXT,
            findings TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_record(sender, subject, risk_score, classification, findings):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO analyses (sender, subject, risk_score, classification, findings)
        VALUES (?, ?, ?, ?, ?)
    """,
        (sender, subject, risk_score, classification, "; ".join(findings)),
    )
    conn.commit()
    conn.close()


def get_history(limit=50):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, timestamp, sender, subject, risk_score, classification, findings
        FROM analyses ORDER BY id DESC LIMIT ?
    """,
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows