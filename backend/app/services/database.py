import sqlite3
import os


BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DB_PATH = os.path.join(BASE_DIR, "vulnai.db")


def init_db():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            results TEXT,
            approvals TEXT,
            followup_results TEXT,
            chat_history TEXT
        )
    """)

    conn.commit()
    conn.close()
