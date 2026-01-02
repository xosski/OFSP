import sqlite3
import threading
from datetime import datetime
from typing import List

class KnowledgeBase:
    def __init__(self, db_path: str = "hades_knowledge.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS web_learnings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            content_type TEXT,
            patterns_found TEXT,
            exploits_found TEXT,
            learned_at TEXT)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role TEXT,
            message TEXT,
            timestamp TEXT,
            context TEXT)''')

        self.conn.commit()

    def store_web_learning(self, url: str, content_type: str, content: str):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''INSERT INTO web_learnings 
                (url, content_type, patterns_found, exploits_found, learned_at)
                VALUES (?, ?, ?, ?, ?)''',
                (url, content_type, content[:500], "", datetime.now().isoformat()))
            self.conn.commit()

    def fetch_recent_learnings(self, limit=1) -> List[str]:
        cursor = self.conn.cursor()
        cursor.execute('SELECT patterns_found FROM web_learnings ORDER BY learned_at DESC LIMIT ?', (limit,))
        return [row[0] for row in cursor.fetchall()]

    def store_chat(self, role: str, message: str, timestamp: str, context: str = ""):
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''INSERT INTO chat_history (role, message, timestamp, context)
                              VALUES (?, ?, ?, ?)''',
                           (role, message, timestamp, context))
            self.conn.commit()

    def get_chat_history(self, limit=50) -> List[dict]:
        cursor = self.conn.cursor()
        cursor.execute('SELECT role, message, timestamp, context FROM chat_history ORDER BY id DESC LIMIT ?', (limit,))
        return [
            {"role": row[0], "message": row[1], "timestamp": row[2], "context": row[3]}
            for row in cursor.fetchall()
        ]