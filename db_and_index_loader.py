import os
import sqlite3
from typing import List
import numpy as np
import faiss
import logging
from sentence_transformers import SentenceTransformer
"""
Creates an index DB from files for similarity search
"""
logger = logging.getLogger("EmbeddingIndexer")
logging.basicConfig(level=logging.INFO)

DB_PATH = "./db/malicious_index.faiss"
SRC_PATH = "./kb"

FILES = {
    ["./kb/bad_prompts.parquet", "Bad Prompt"],
    ["./kb/harmful_behaviors.csv", "Harmful Behavior"]
    ["./kb/harmful_strings.csv", "Toxicity"],
    ["./kb/transfer_expriment_behaviors.csv", "Harmful Request"]
}

def read_sentences_from_files(folder_path: str) -> List[str]:
    """
    Read sentences from all .txt files in a given folder.
    Each line is treated as a separate sentence.
    """
    sentences = []
    if not os.path.isdir(folder_path):
        logger.error("Invalid folder path: %s", folder_path)
        return sentences

    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if filename.endswith(".txt"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = [line.strip() for line in f if line.strip()]
                    sentences.extend(lines)
                    logger.info("Loaded %d sentences from %s", len(lines), filename)
            except Exception as e:
                logger.warning("Failed to read %s: %s", filename, e)
    return sentences

def build_index(sentences, model_name="all-MiniLM-L6-v2"):
    try:
        model = SentenceTransformer(model_name)
        texts = [s[1] for s in sentences]
        ids = [s[0] for s in sentences]

        embeddings = model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)

        dim = embeddings.shape[1]
        index = faiss.IndexFlatIP(dim)  # cosine similarity (requires normalized vectors)
        index.add(embeddings)

        faiss.write_index(index, DB_PATH)
        logger.info("FAISS index built and saved to %s", DB_PATH)

        return index, ids
    
    except Exception as e:
                logger.warning("Failed to build index: %s", e)

def main():
    sentences = read_sentences_from_files(SRC_PATH)
    if not sentences:
        logger.warning("No sentences found in DB")
        return

    build_index(sentences)

if __name__ == "__main__":
    main()