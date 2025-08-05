"""
This scan analyzes text to identify PII or sensitive content.
"""

import asyncio
from typing import List, Optional
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from src.shared.logger import init_logger
from src.scanners.basescanner import ScanAction, ScanDecision, ScanRiskLevel, ScanStatus, Scanner, ScanResult

logger = init_logger("PIIScanner")

PresidioResultList = List[RecognizerResult]
ENTITIES_TO_SCANOOOOO = [
    "PERSON",
    "EMAIL_ADDRESS", 
    "SECURITY_ACCESS_CODES",
    "CREDIT_CARD"
    "PASSWORD", 
    "CRYPTO", 
    "IP_ADDRESS", 
    "SEXUAL_PREFERENCE", 
    "RACE", 
    "SWIFT_CODE"]

class PIIScanner(Scanner):
    def __init__(self,
        scanner_name: str,
        scan_action: str,
        message: str,
        ingress: bool = False,
        egress: bool = False,
        scan_status: bool = False,
        threshold: float = 1.0,
        block_score: float = 1.0,
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
            pii_entities=pii_entities)

        try:
            self.entities_to_scan = pii_entities
            logger.info(f"Loading PII entities patterns: {self.entities_to_scan}")
        except Exception as e:
            logger.error(f"Failed to load patterns: {e}")


    #async def scan(self, prompt: str) -> ScanResult:
    def scan(self, prompt: str) -> ScanResult:
        outcome = None

        """analyzer_engine = AnalyzerEngine()
        if not analyzer_engine:
            logger.error("Presidio Analyzer engine not initialized during PII check.")"""

        try:
            """def analyze_sync() -> PresidioResultList:
                logger.debug(
                    f"Running PII analysis (Policy: PII, Threshold: 0.75, Entities: {self.entities_to_scan or 'Default'})"
                )
                return analyzer_engine.analyze(
                    text=prompt,
                    entities=self.entities_to_scan,
                    language="en",
                    #score_threshold=policy.pii_threshold,
                    score_threshold=0.75,
                    return_decision_process=True,
                )

            # results = List[RecognizerResult]
            #final_analyzer_results: PresidioResultList = await asyncio.to_thread(
            final_analyzer_results: PresidioResultList = asyncio.to_thread(
                analyze_sync
            )"""
            final_analyzer_results = None
            if not final_analyzer_results:
                logger.debug(f"No PII found for policy")
            else: 
                logger.debug(f"PII found for policy")
                detected_entity_types = sorted(
                    list(set(res.entity_type for res in final_analyzer_results))
                )
                log_message = (
                    f"PII detected. "
                    f"Types: {detected_entity_types} (Count: {len(final_analyzer_results)})"
                )

                final_score = len(final_analyzer_results)
                outcome = self.get_scan_result_from_score(final_score)
                outcome.score = final_score
                outcome.reason = log_message
                outcome.rules_triggered = ", ".join(
                    res.entity_type for res in final_analyzer_results
                )
                

        except Exception as e:
            logger.error("Exception during PII scan: %s", str(e), exc_info=True)
            return ScanResult(ScanStatus.ERROR.value, ScanDecision.FLAG.value, ScanAction.FLAG.name, "PIIScanner: An error ocurred during the scan", "", 0.0, ScanRiskLevel.NONE.name)
            
        return outcome if outcome is not None else ScanResult(
            status=ScanStatus.SUCCESS.value,
            decision=ScanDecision.ALLOW.value,
            action=ScanAction.PASS.name,
            message="PIIScanner: No content safety issues found",
            rules_triggered="",
            score=0.0,
            criticallity=ScanRiskLevel.NONE.name
        )
                

            
