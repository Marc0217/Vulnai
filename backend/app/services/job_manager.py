import sqlite3
import json
import uuid


DB_PATH = "vulnai.db"


def init_db():

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            target TEXT,
            status TEXT,
            results TEXT,
            approvals TEXT,
            followup_results TEXT,
            chat_history TEXT,
            ai_analysis TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


def create_job(target):

    job_id = str(uuid.uuid4())

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            job_id,
            target,
            "queued",
            json.dumps({}),
            json.dumps([]),
            json.dumps([]),
            json.dumps([]),
            None
        )
    )

    conn.commit()
    conn.close()

    return job_id


def set_running(job_id):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE jobs SET status = ? WHERE job_id = ?",
        ("running", job_id)
    )

    conn.commit()
    conn.close()


def update_job(job_id, results):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE jobs SET status = ?, results = ? WHERE job_id = ?",
        (
            "completed",
            json.dumps(results),
            job_id
        )
    )

    conn.commit()
    conn.close()


def get_job(job_id):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM jobs WHERE job_id = ?",
        (job_id,)
    )

    row = cursor.fetchone()

    conn.close()

    if not row:
        return None

    return {
        "job_id": row[0],
        "target": row[1],
        "status": row[2],
        "results": json.loads(row[3]),
        "approvals": json.loads(row[4]),
        "followup_results": json.loads(row[5]),
        "chat_history": json.loads(row[6]),
        "ai_analysis": json.loads(row[7]) if row[7] else None
    }


def save_followup(job_id, results):

    job = get_job(job_id)

    followups = job.get("followup_results", [])
    followups.append(results)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE jobs SET followup_results = ? WHERE job_id = ?",
        (
            json.dumps(followups),
            job_id
        )
    )

    conn.commit()
    conn.close()


def save_chat_message(job_id, role, content):

    job = get_job(job_id)

    history = job.get("chat_history", [])

    history.append({
        "role": role,
        "content": content
    })

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE jobs SET chat_history = ? WHERE job_id = ?",
        (
            json.dumps(history),
            job_id
        )
    )

    conn.commit()
    conn.close()


def get_chat_history(job_id):

    job = get_job(job_id)

    if not job:
        return []

    return job.get("chat_history", [])


def save_ai_analysis(job_id, ai_analysis):

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE jobs SET ai_analysis = ? WHERE job_id = ?",
        (
            json.dumps(ai_analysis),
            job_id
        )
    )

    conn.commit()
    conn.close()
