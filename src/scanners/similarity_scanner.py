"""
This scan analyzes text using Similarity search to 
identify inappropriate or harmful content.
"""
from src.shared.logger import init_logger
from src.scanners.basescanner import ScanAction, ScanDecision, ScanResult, ScanRiskLevel, ScanStatus, Scanner
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

# Set up logging
logger = init_logger("SimilarityScanner")

INDEX_PATH = "./db/malicious_index.faiss"
MODEL_NAME = "all-MiniLM-L6-v2"
"""
THRESHOLD: Cosine similarity ranges from -1 to 1:
	•	1.0 → exact match
	•	0.9 → very strong similarity
	•	0.75 → fairly similar
	•	≤ 0.5 → weak similarity
"""
THRESHOLD = 0.75  # cosine similarity threshold
TOP_K = 3 # Returns the top most similar entries and their similarity scores.

class SimilarityScanner(Scanner):
    def __init__(self,
        scanner_name: str,
        scan_action: str,
        message: str,
        ingress: bool = False,
        egress: bool = False,
        scan_status: bool = False,
        threshold: float = 1.0,
        block_score: float = 1.0,
        refresh_cache: bool = True):
        super().__init__(
            scanner_name=scanner_name, 
            scan_action=scan_action, 
            message=message,
            ingress=ingress,
            egress=egress,
            scan_status=scan_status,
            threshold=threshold,
            block_score=block_score,
            refresh_cache= refresh_cache)
        try:
            # Load FAISS index
            self.index = faiss.read_index(INDEX_PATH)

            # Load embedding model
            self.model = SentenceTransformer(MODEL_NAME)
            
        except Exception as e:
            print(f"Error loading Index and/or embedding model : {e}")

    
    def scan(self, raw_prompt: str) -> ScanResult:
        #print(f" **** _scan raw_prompt: {raw_prompt}")
        content = self.normalize_prompt(raw_prompt)
        # initialize ScanResult with default values
        # This is the default outcome if no rules are matched
        outcome = None
        try:
            # Generate normalized query embedding
            embedding = self.model.encode([content], normalize_embeddings=True)

            # Perform similarity search
            scores, indices = self.index.search(np.array(embedding), TOP_K)

            # Flatten results
            score_list = scores[0].tolist()
            id_list = indices[0].tolist()

            # Analyze
            matches_above_threshold = [s for s in score_list if s >= THRESHOLD]
            top_score = max(score_list) if score_list else 0.0
            is_similar = len(matches_above_threshold) > 0

            if is_similar:
                outcome = self.get_scan_result_from_score(top_score)
                outcome.score = f"{top_score:.2f}"
                outcome.message += f"imilarityScanner matched {len(matches_above_threshold)} rules"
                outcome.rules_triggered = id_list
                outcome.action = ScanAction(self.scan_action).name


        except Exception as e:
            logger.error("Exception during similarity scan: %s", str(e), exc_info=True)
            return ScanResult(ScanStatus.ERROR.value, ScanDecision.FLAG.value, ScanAction.FLAG.name, "SimilarityScanner: An error ocurred during the scan", "", 0.0, ScanRiskLevel.NONE.name)
            
        return outcome if outcome is not None else ScanResult(
            status=ScanStatus.SUCCESS.value,
            decision=ScanDecision.ALLOW.value,
            action=ScanAction.PASS.name,
            message="SimilarityScanner: No content safety issues found",
            rules_triggered="",
            score=0.0,
            criticallity=ScanRiskLevel.NONE.name
        )
