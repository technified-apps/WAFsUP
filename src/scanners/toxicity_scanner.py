"""
This scan is a content safety check system that analyzes text for inappropriate or harmful content.
"""
from pathlib import Path
import re
from typing import Dict, List
from src.shared.pattern_loader import PatternLoader
from src.shared.logger import init_logger
from src.scanners.basescanner import ScanAction, ScanDecision, ScanResult, ScanRiskLevel, ScanStatus, Scanner

# Set up logging
logger = init_logger("ContentSafetyScanner")

CACHE_FILE = "./src/patterns/harmfull_patterns_cache.pkl"
PATTERN_FILE = "./src/patterns/harmfull_patterns.yaml"
REPORT_FILE = "./reports/report"

severity_weights = {
            'mild': 0.3,
            'moderate': 0.6,
            'severe': 1.0
        }
# these values define the tolerable number of matches per severity
severity_limits = {
    'mild': 3,
    'moderate': 2,
    'severe': 1
}

class ContentSafetyScanner(Scanner):
    def __init__(self,
        scanner_name: str,
        scan_action: str,
        message: str,
        ingress: bool = False,
        egress: bool = False,
        scan_status: bool = False,
        threshold: float = 1.0,
        block_score: float = 1.0,
        refresh_cache: bool = False,
        pii_entities: List = None):
        super().__init__(
            scanner_name=scanner_name, 
            scan_action=scan_action, 
            message=message,
            ingress=ingress,
            egress=egress,
            scan_status=scan_status,
            threshold=threshold,
            block_score=block_score,
            refresh_cache= refresh_cache,
            pii_entities=pii_entities)
        
        try:   
            if Path(PATTERN_FILE).is_file():  
                pattern_loader = PatternLoader(PATTERN_FILE, CACHE_FILE, compile=False)
                # paterns is Dict[str, Pattern]
                self.patterns = pattern_loader.get_patterns()
                #self.resultsbyseverity = {'mild': [], 'moderate': [], 'severe': []}
                self.resultsbyseverity = {'mild': set(), 'moderate': set(), 'severe': set()}
                logger.info(f"Loaded {len(self.patterns)} patterns")
        except FileNotFoundError as fe:
            logger.error(f"Failed to load file {PATTERN_FILE} does not exist.: {fe}")
        except Exception as e:
            logger.error(f"Failed to load patterns: {e}")

    def _scan(self, text: str) -> tuple[float, list]:
        """Analyze text for toxicity by matching against severity-tagged word lists."""
        content = self.normalize_prompt(text)
        triggered_rules = set()
        score =  0
        try:        
            if not self.patterns:
                logger.warning("Scan aborted: no patterns loaded.")
                return 0, []
            
            word_to_severity = {}
            word_to_category = {}
            for category_name, entry in self.patterns.items():
                for severity, words in entry.strings.items():
                    for word in words:
                        key = word.lower()
                        word_to_severity[key] = severity
                        word_to_category[key] = category_name

            if not word_to_severity:
                return 0, []

            pattern = re.compile(r'\b(' + '|'.join(map(re.escape, word_to_severity.keys())) + r')\b', re.IGNORECASE)
            matches = set(pattern.findall(content))

            if not matches:
                return 0, []

            for word in matches:
                severity = word_to_severity[word.lower()]
                self.resultsbyseverity[severity].add(word)
                triggered_rules.add(word_to_category[word.lower()])

            score += (
                len(self.resultsbyseverity['mild']) * severity_weights['mild'] +
                len(self.resultsbyseverity['moderate']) * severity_weights['moderate'] +
                len(self.resultsbyseverity['severe']) * severity_weights['severe']
            )

        except Exception as e:
            logger.error(f"Error in _scan: {e}", exc_info=True)

        return score, list(triggered_rules)

        
    def scan(self, text: str) -> ScanResult:
        """Handle content safety check request and return scan outcome."""
        try:
            outcome = None
            final_score, triggered_rules = self._scan(text)
            hits_summary = [] 

            for severity in self.resultsbyseverity:
                # severyt and words matched - this can be useful for loggin
                #hits_summary.append(f"Severity {severity}: ({', '.join(self.resultsbyseverity.get(severity))})")
                ms = len(self.resultsbyseverity.get(severity))
                if ms >=1:
                    hits_summary.append(f"Severity {severity}: ({ms} matches)")

            hits_str = ' - '.join(hits_summary) if hits_summary else ""
            
            #logger.info(f"###########self.threshold: {self.threshold}")
            if final_score >= 0.5: 
                outcome = self.get_scan_result_from_score(final_score)
                outcome.score = f"{final_score:.2f}"
                outcome.decision = ScanDecision.FLAG.value
                outcome.action = ScanAction.PASS.name
                outcome.rules_triggered = triggered_rules
                outcome.message += f"ContentSafetyScanner: {hits_str}"
                outcome.criticallity=ScanRiskLevel.MEDIUM.name

            if final_score >= self.threshold:
                outcome.decision = ScanDecision.BLOCK.value
                outcome.action = ScanAction(self.scan_action).name
                outcome.criticallity=ScanRiskLevel.CRITICAL.name

        except Exception as e:
            logger.error("Exception during content scan: %s", str(e), exc_info=True)
            return ScanResult(ScanStatus.ERROR.value, ScanDecision.FLAG.value, ScanAction.FLAG.name, "ContentSafetyScanner: An error ocurred during the scan", "", 0.0, ScanRiskLevel.NONE.name)

        return outcome if outcome is not None else ScanResult(
            status=ScanStatus.SUCCESS.value,
            decision=ScanDecision.ALLOW.value,
            action=ScanAction.PASS.name,
            message="ContentSafetyScanner: No content safety issues found",
            rules_triggered="",
            score=0.0,
            criticallity=ScanRiskLevel.NONE.name
        )