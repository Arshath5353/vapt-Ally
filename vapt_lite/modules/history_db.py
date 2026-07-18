"""Small SQLite persistence layer; keeps the existing JSON file as a fallback."""
import json
import os
import sqlite3


def initialise(path: str) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, target TEXT NOT NULL, risk_score REAL, risk_level TEXT, payload TEXT NOT NULL)")
        connection.commit()


def load(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with sqlite3.connect(path) as connection:
        rows = connection.execute("SELECT payload FROM scans ORDER BY timestamp ASC").fetchall()
    results = []
    for (payload,) in rows:
        try:
            results.append(json.loads(payload))
        except json.JSONDecodeError:
            continue
    return results


def save(path: str, scan: dict) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT OR REPLACE INTO scans (id, timestamp, target, risk_score, risk_level, payload) VALUES (?, ?, ?, ?, ?, ?)", (scan.get("id"), scan.get("timestamp", ""), scan.get("target", ""), scan.get("risk", {}).get("score", 0), scan.get("risk", {}).get("level", "Unknown"), json.dumps(scan)))
        connection.commit()
