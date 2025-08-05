from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
import string
from typing import List
import re
import unicodedata

@dataclass
class ScanDecision(Enum): # describes the FINAL decision based on multiple factors
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"

@dataclass
class ScanStatus(Enum): # describes whether the scan was successfully performed or had errors
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"

@dataclass
class ScanAction(Enum): # describes the action to take when a treath was identified
    BLOCK = 0
    OBSERVE = 1
    FLAG = 2
    PASS = 3
    RETRY = 4

    @staticmethod
    def most_severe(actions: List["ScanAction"]) -> "ScanAction":
        return min(actions)  # smaller value = higher severity

@dataclass
class ScanRiskLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @staticmethod
    def max_level(levels):
        return max(levels, key=lambda lvl: lvl.value)
    
@dataclass
class ScanResult:
    status: ScanStatus  # Default to success
    decision: ScanDecision   
    action: int
    message: str
    rules_triggered: str
    score: float
    criticallity: str

    def __repr__(self):
        return (
            f"=== Scan Result ===\n"
            f"Scan status: {self.status}\n"
            f"Score: {self.score}\n"
            f"Decision: {self.decision}\n"
            f"Message: {self.message}\n"
            f"Rules Triggered: {self.rules_triggered or 'NONE'}\n"
            f"Risk Level: {self.criticallity}\n"
            f"Action: {self.action}\n"
        )

class Scanner(ABC):
    def __init__(
        self,
        scanner_name: str,
        scan_action: str,
        message: str,
        ingress: bool = False,
        egress: bool = False,
        scan_status: bool = False,
        threshold: float = 1.0,
        block_score: float = 1.0,
        refresh_cache: bool = False,
        pii_entities: List = None
    ) -> None:
        self.name: str = scanner_name
        self.block_score: float = block_score
        self.scan_action = scan_action
        self.ingress = ingress
        self.egress = egress
        self.message = message
        self.scan_status = scan_status
        self.threshold = threshold
        self.refresh_cache = refresh_cache
        self.pii_entities = pii_entities

    def normalize_prompt(self, text):
        # Normalize unicode characters to compatibility form (e.g., remove accents)
        text = unicodedata.normalize('NFKC', text)

        # Lowercase and remove all punctuation
        text = text.lower()
        text = text.translate(str.maketrans('', '', string.punctuation))

        # Decode percent-encoded characters (e.g., %20)
        text = re.sub(r'%[0-9a-fA-F]{2}', lambda m: bytes.fromhex(m.group()[1:]).decode(errors='ignore'), text)

        # Remove unicode escape sequences
        text = re.sub(r'\\u[0-9a-fA-F]{4}', '', text)
        text = re.sub(r'\\x[0-9a-fA-F]{2}', '', text)
        text = re.sub(r'\\[0-7]{3}', '', text)

        # Remove non-printable and invisible characters
        text = ''.join(c for c in text if c.isprintable())

        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()

        return text

    @abstractmethod
    async def scan(self, message: str) -> ScanResult:
        """
        Scans the message and returns a ScanResult.

        This is the main method that concrete scanner implementations should override.
        Each scanner should implement its full scanning logic within this method,
        including any preprocessing, evaluation, and decision making.

        Args:
            message: The message to scan
            past_trace: Optional trace of previous messages

        Returns:
            ScanResult: The result of the scan, containing a decision, reason, and score
        """
        raise NotImplementedError("[LlamaFirewall] Scan method not implemented")

    def get_scan_result_from_score(self, score: float) -> ScanResult:
        """
        Generate a ScanResult object based on a provided score.
        This utility helps convert raw score outputs into structured decisions.
        """
        thresholds = [
        (20, ScanStatus.FAILED.value, ScanDecision.BLOCK.value, ScanAction.BLOCK.name, "", ScanRiskLevel.CRITICAL.name),
        (10, ScanStatus.FAILED.value, ScanDecision.BLOCK.value, ScanAction.BLOCK.name, "", ScanRiskLevel.HIGH.name),
        (6,  ScanStatus.FAILED.value, ScanDecision.FLAG.value,  ScanAction.FLAG.name,  "", ScanRiskLevel.MEDIUM.name),
        (2,  ScanStatus.FAILED.value, ScanDecision.FLAG.value,  ScanAction.OBSERVE.name,"", ScanRiskLevel.LOW.name),]

        for threshold, status, decision, action, message, risk in thresholds:
            if score >= threshold:
                return ScanResult(
                    status=status,
                    decision=decision,
                    action=action,
                    message=message,
                    rules_triggered="",
                    score=score,
                    criticallity=risk
                )

        return ScanResult(
            status=ScanStatus.SUCCESS.value,
            decision=ScanDecision.ALLOW.value,
            action=ScanAction.PASS.name,
            message="",
            rules_triggered="",
            score=score,
            criticallity=ScanRiskLevel.NONE.name)
    
    def __str__(self) -> str:
        return self.name