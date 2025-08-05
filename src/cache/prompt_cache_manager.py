import pickle
import sqlite3
from datetime import datetime, timedelta
from collections import deque
from typing import List, Dict, Optional

CACHE_DB = "./src/cache/llm_cache.db"
BAD_RESULTS_DB = "./src/cache/bad_results.db"
PICKLE_FILE = "./src/cache/llm_cache.pkl"
"""
    Manages both SQLite-based prompt-response cache and pickle-based conversation memory.
    Combines:
	•	Pickle: multi-turn structured conversation memory
	•	SQLite: persistent prompt-response cache for LLM

🔍 Features:
	•	.append_message() and .get_conversation() manage a deque buffer
	•	.get_cached_response() and .set_cached_response() avoid redundant LLM calls
	•	.prune_sqlite_cache() clears old entries by age
	•	.search_responses_by_keyword() supports forensic analysis or audit filtering


# === Example Usage ===
if __name__ == "__main__":
    manager = HybridCacheManager()

    # Simulate new conversation turn
    manager.append_message({"role": "user", "content": "What is prompt injection?"})
    manager.save_pickle()

    # Retrieve conversation history
    convo = manager.get_conversation()
    print("Conversation:", convo)

    # Set and get SQLite cached response
    manager.set_cached_response("llama3", "What is prompt injection?", "Prompt injection is ...")
    cached = manager.get_cached_response("llama3", "What is prompt injection?")
    print("Cached Response:", cached)

    # Search for keyword
    matches = manager.search_responses_by_keyword("injection")
    print("Search Matches:", matches)

    # Prune old entries
    manager.prune_sqlite_cache(max_age_days=90)

    # Clear memory cache
    manager.clear_pickle_cache()    
"""


class HybridCacheManager:
    
    def __init__(self, max_history: int = 6):
        self.max_history = max_history
        self.conversation_buffer = self._load_pickle()
        self._init_sqlite()

    # === Pickle Conversation Cache ===

    def _load_pickle(self) -> deque:
        try:
            with open(PICKLE_FILE, "rb") as f:
                return pickle.load(f)
        except Exception:
            return deque(maxlen=self.max_history)

    def save_pickle(self):
        try:
            with open(PICKLE_FILE, "wb") as f:
                pickle.dump(self.conversation_buffer, f)
        except Exception as e:
            print(f"[ERROR] Failed to save conversation pickle: {e}")

    def append_message(self, message: Dict[str, str]):
        self.conversation_buffer.append(message)

    def get_conversation(self) -> List[Dict[str, str]]:
        return list(self.conversation_buffer)

    def clear_pickle_cache(self):
        self.conversation_buffer.clear()
        self.save_pickle()

    # === SQLite Prompt-Response Cache ===

    def _init_sqlite(self):
        self.conn = sqlite3.connect(CACHE_DB)
        self.conn2 = sqlite3.connect(BAD_RESULTS_DB)
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS cache (
                    user_id TEXT,
                    prompt TEXT,
                    response TEXT,
                    created_at TEXT,
                    accessed_at TEXT,
                    PRIMARY KEY (user_id, prompt)
                )
            ''')
            self.conn2.execute('''
                CREATE TABLE IF NOT EXISTS bad_store (
                    user_id TEXT,
                    prompt TEXT,
                    response TEXT,
                    hits_results TEXT,
                    category TEXT,               
                    created_at TEXT,
                    accessed_at TEXT,
                    PRIMARY KEY (user_id, prompt)
                )
            ''')

    def get_cached_response(self, user_id: str, prompt: str) -> Optional[str]:
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT response FROM cache WHERE user_id=? AND prompt=?",
                (user_id, prompt),
            )
            row = cursor.fetchone()
            if row:
                self.conn.execute(
                    "UPDATE cache SET accessed_at=? WHERE user_id=? AND prompt=?",
                    (datetime.now().isoformat(), user_id, prompt),
                )
                return row[0]
        except Exception as e:
            print(f"[ERROR] Cache lookup failed: {e}")
        return None

    def set_cached_response(self, user_id: str, prompt: str, response: str):
        try:
            now = datetime.now().isoformat()
            with self.conn:
                self.conn.execute(
                    '''REPLACE INTO cache (user_id, prompt, response, created_at, accessed_at)
                       VALUES (?, ?, ?, ?, ?)''',
                    (user_id, prompt, response, now, now)
                )
        except Exception as e:
            print(f"[ERROR] Failed to cache response: {e}")

    def prune_sqlite_cache(self, max_age_days: int = 30):
        try:
            threshold = (datetime.now() - timedelta(days=max_age_days)).isoformat()
            with self.conn:
                self.conn.execute(
                    "DELETE FROM cache WHERE created_at < ?",
                    (threshold,)
                )
        except Exception as e:
            print(f"[ERROR] Failed to prune cache: {e}")

    def search_responses_by_keyword(self, keyword: str) -> List[Dict[str, str]]:
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT user_id, prompt, response, created_at FROM cache WHERE response LIKE ?",
                (f"%{keyword}%",)
            )
            return [
                {"user_id": row[0], "prompt": row[1], "response": row[2], "created_at": row[3]}
                for row in cursor.fetchall()
            ]
        except Exception as e:
            print(f"[ERROR] Search failed: {e}")
            return []

