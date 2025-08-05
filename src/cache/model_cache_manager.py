import logging
import sqlite3
from datetime import datetime
from typing import Optional
from pathlib import Path
from ollama import Client

logger = logging.getLogger("CachedLLM")
"""
A minimal SQLite-backed cache for LLM prompt-response pairs.
This cache stores responses from an LLM model, allowing for quick retrieval
of previously generated responses based on the model ID and prompt.

USAGE:
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ############################# it caches the LLM itself
    llm = CachedOllamaLLM(model_id="llama3")
    prompt = "What are the principles of prompt injection defense in LLMs?"
    print(llm.query(prompt))

"""

class SimpleCacheDB:
    def __init__(self, db_path: str | Path = ":memory:"):
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self.conn:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS cache (
                    model_id TEXT,
                    prompt TEXT,
                    response TEXT,
                    created_at TEXT,
                    accessed_at TEXT,
                    PRIMARY KEY (model_id, prompt)
                )
            ''')

    def get(self, model_id: str, prompt: str) -> Optional[str]:
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT response FROM cache WHERE model_id=? AND prompt=?",
                (model_id, prompt),
            )
            row = cursor.fetchone()
            if row:
                self.conn.execute(
                    "UPDATE cache SET accessed_at=? WHERE model_id=? AND prompt=?",
                    (datetime.now().isoformat(), model_id, prompt),
                )
                return row[0]
        except Exception as e:
            logger.error("Error accessing cache: %s", e)
        return None

    def put(self, model_id: str, prompt: str, response: str):
        try:
            now = datetime.now().isoformat()
            with self.conn:
                self.conn.execute(
                    '''REPLACE INTO cache (model_id, prompt, response, created_at, accessed_at)
                       VALUES (?, ?, ?, ?, ?)''',
                    (model_id, prompt, response, now, now)
                )
        except Exception as e:
            logger.error("Error writing to cache: %s", e)

    def clear(self):
        with self.conn:
            self.conn.execute("DELETE FROM cache")


class CachedOllamaLLM:
    """
    Caches responses from an Ollama model for repeated prompts.
    """

    def __init__(self, model_id: str, cache_path: str = "./db/llm_cache.db"):
        self.model_id = model_id
        self.client = Client()
        self.cache = SimpleCacheDB(cache_path)

    def query(self, prompt: str) -> str:
        """
        Query the model with caching. Return cached result if available.
        """
        cached = self.cache.get(self.model_id, prompt)
        if cached:
            logger.info("Cache hit for prompt: %s", prompt[:60])
            return cached

        logger.info("Cache miss. Querying Ollama model.")
        try:
            response = self.client.chat(model=self.model_id, messages=[
                {"role": "user", "content": prompt}
            ])
            content = response.get("message", {}).get("content", "")
            self.cache.put(self.model_id, prompt, content)
            return content
        except Exception as e:
            logger.error("Ollama query failed: %s", e)
            return "[ERROR: Unable to retrieve response from model]"

