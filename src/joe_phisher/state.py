"""Durable queue and side-effect checkpoints for a single connector instance."""

import fcntl
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path


# Terminal records remain in SQLite for deduplication; none are automatically deleted.
TERMINAL = {"done", "error", "timeout", "blocked", "skipped"}


@contextmanager
def instance_lock(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(str(path) + ".lock", "a") as handle:
        try:
            # The OS releases this advisory lock when the process exits, including after a crash.
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another connector is using this state database") from None
        yield


class State:
    def __init__(self, filename):
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(filename)
        # Commit submission IDs and progress checkpoints durably before further remote work.
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS jobs (message_id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self.db.commit()

    def close(self):
        self.db.close()

    def get(self, message_id):
        row = self.db.execute("SELECT body FROM jobs WHERE message_id=?", (message_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def jobs(self):
        return [json.loads(row[0]) for row in self.db.execute("SELECT body FROM jobs ORDER BY rowid")]

    def save(self, job):
        # Jobs contain IDs, timestamps and result metadata, never EML bytes or signed URLs.
        job["updated"] = time.time()
        with self.db:
            self.db.execute("INSERT INTO jobs(message_id,body) VALUES (?,?) "
                            "ON CONFLICT(message_id) DO UPDATE SET body=excluded.body",
                            (job["message_id"], json.dumps(job)))

    def enqueue(self, message_id, now):
        # Retained terminal rows prevent a later discovery scan from creating the same job.
        if self.get(message_id):
            return False
        self.save({"message_id": message_id, "job_id": uuid.uuid4().hex, "phase": "queued",
                   "created": now, "next_attempt": now, "steps": []})
        return True

    def recover(self):
        for job in self.jobs():
            if job["phase"] == "submitting":
                # A lost response may hide a successful upload. Require reconciliation rather
                # than risk a second submission and another analysis charge.
                job.update(phase="publishing", outcome="blocked",
                           error="Connector stopped during submission; reconcile the submission in Joe Cloud",
                           next_attempt=0)
                self.save(job)
