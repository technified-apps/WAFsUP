import os
import unicodedata
import magic
import zipfile
import re
from typing import Any, List
from pathlib import Path
from PIL import Image
from PIL.ExifTags import TAGS
from src.shared.pattern_loader import PatternLoader
from src.shared.pattern import Pattern
from src.functions.file_content_parser import SUPPORTED_FILE_TYPES, FileContentParser
from src.scanners.basescanner import ScanAction, ScanDecision, ScanResult, ScanRiskLevel, ScanStatus, Scanner
import re
import logging
from typing import List, Dict
from src.handlers.file_handler import is_file_binary_fn
from src.shared.logger import init_logger

# Set up logging
logger = init_logger("FileUploadScanner")

CACHE_FILE = "./src/patterns/patterns_for_doc_cache.pkl"
PATTERN_FILE = "./src/patterns/patterns_for_doc.yaml"
REPORT_FILE = "./reports/report"

"""
USAGE:
    if __name__ == "__main__":
        directory = "./uploads"
        report = scan_directory(directory)
        print("\n--- Scan Summary ---")
        for entry in report:
            print(entry)

TO DOs:
-- store uploaded file on a sandbox to evaluate 


"""
LLM_TRIGGER_PATTERNS = [
    r"ignore.*instruction", r"simulate.*response", r"act as", r"pretend to be",
    r"<\|system\|>", r"\[system\]", r"unfiltered", r"/JavaScript", r"/JS", r"prompt:.*"
]

SUSPICIOUS_TYPES = [
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-sh",
    "application/x-elf",
    "application/octet-stream",
    "text/x-shellscript",
    "text/x-msdos-batch",
    "application/x-mach-binary",
    "application/x-executable",
    "application/x-dosexec",
    "application/x-pie-executable",
    "application/x-sharedlib",
    "application/vnd.microsoft.portable-executable",
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".sh", ".scr", ".php", ".js", ".bin", ".dll", ".vbs", ".docm", ".xlsm"
]
"""
# Match any characters in the Unicode tag blockThis will catch all 128 “tag” characters, including:
	•	U+E0020 (TAG SPACE)
	•	U+E0061 (TAG LATIN SMALL LETTER A)
	•	…
	•	U+E007F (CANCEL TAG)
"""
TAG_CHAR_PATTERN = re.compile(r'[\U000E0000-\U000E007F]')
"""
# Match any characters in the Unicode
	•	\u200B: Zero-width space
	•	\u200E: LRM / RLM
	•	\u2028, \u2029: Line separators
	•	\u2060–\u2064: Invisible control characters
	•	\uFEFF: BOM (Byte Order Mark)
"""
INVISIBLE_CHAR_PATTERN = re.compile(
    r'[\u200B-\u200F\u2028\u2029\u2060\u2061\u2062\u2063\u2064\uFEFF]'
)
REMOTE_IMG_FILE_PATTERN = r"\!\[.*\]\(https?://([a-z0-9\.]+)/[a-z0-9]+\.(jpg|jpeg|gif|webp|png)\?[a-z]+=(.+)\)"
MAX_FILE_SIZE_MB = 100


class FileUploadScanner(Scanner):
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
            pii_entities=pii_entities)
        
        self.refresh_cache = refresh_cache
        self.patterns = Dict[str, Pattern]
        self.content_parser = FileContentParser()
        try: 
            if Path(PATTERN_FILE).is_file():
                pattern_loader = PatternLoader(PATTERN_FILE, CACHE_FILE, compile=True)
                # paterns is Dict[str, Pattern]
                self.patterns = pattern_loader.get_patterns()
                #self.compiled_strings = load_patterns.get_compiled_patterns()
                logger.info(f"Loaded {len(self.patterns)}")
        except FileNotFoundError as fe:
            logger.error(f"Failed to load file {PATTERN_FILE} does not exist.: {fe}")
        except Exception as e:
            logger.error(f"Failed to load patterns: {e}")
        

    def _regex_match(self, text: str, regex_patterns: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
        """            
        Scan the provided text against all compiled patterns.
        Returns a dictionary where keys are pattern names and values are lists of matched keys.
        """
        matches = {}
        patterns = regex_patterns
        matched_keys = []
        for key, pattern in patterns.items():
            #logger.info(f"name: {key} - pattern: {pattern} ")
            try:
                if pattern['type'] == 'regex' and pattern['pattern'].search(text):
                    matched_keys.append(key)
                elif pattern['type'] == 'hex' and pattern['pattern'] in text.encode(errors='ignore'):
                    matched_keys.append(key)
            except Exception as e:
                logger.warning(f"Error matching pattern '{key}:{pattern['pattern']}': {e}")
        if matched_keys:
            matches[key] = matched_keys

        return matches

    def contains_invisible_unicode(self, text: str) -> bool:
        return bool(TAG_CHAR_PATTERN.search(text) or INVISIBLE_CHAR_PATTERN.search(text))

    def normalize_file_content(self, text: str) -> str:
        """
        Normalize text to NFKC and clean up control/invisible characters (optional).
        """ 
        return unicodedata.normalize("NFKC", text)

    def extract_invisible_characters(self, text: str) -> list:
        """
        Identify characters in the text that match Unicode tag or invisible character ranges.
        """
        return [c for c in text if TAG_CHAR_PATTERN.match(c) or INVISIBLE_CHAR_PATTERN.match(c)]

    def regex_scan(self, content: str)   -> List[dict]: 
        """
        Scans the file content and returns:
        - empty: True if no patterns matched
        - results: List of matched pattern categories
        """  
        results = []
        regex_score = 0

        if self.patterns is None:
            logger.warning("Scan aborted: configuration failed to load.")
            return  # ⛔ Do not proceed
        else:
            # Loop over the regex patterns
            for entry in self.patterns.values():
                regex_strings = entry.strings
                matches = self._regex_match(content, regex_strings)
                matched_keys = [k for k, v in matches.items() if v]

                if matched_keys:
                    # Apply severity scoring: 2 points for regex, 1 for hex
                    regex_score += sum(2 if self.compiled_strings[k]['type'] == 'regex' else 1 for k in matched_keys)
                    results.append({
                        'rule_name': entry.name,
                        'metadata': entry.meta,
                        'matched_keys': matched_keys,
                        'severity_score': regex_score
                    })

        #self.save_scan_results(results, content)
        return results
    
    """
    Image files:
        •	Prompt payloads hidden in EXIF metadata
    """
    def inspect_image_metadata(self, file_path: str, result: dict):
        try:
            img = Image.open(file_path)
            exif_data = img._getexif()
            if exif_data:
                for tag, val in exif_data.items():
                    name = TAGS.get(tag, tag)
                    if isinstance(val, str) and any(re.search(p, val, re.IGNORECASE) for p in LLM_TRIGGER_PATTERNS):
                        result["suspicious"] = True
                        result["reasons"].append(f"Prompt pattern in EXIF metadata: {name}")
                        print(f"inspect metadata ")
        except Exception as e:
            logger.warning(f"EXIF check failed for {file_path}", exc_info=True)

    """
    Filenames:
        •	Pattern matching against malicious prompt strings
    """
    def inspect_filename(self, file_path: str, result: dict):
        name = os.path.basename(file_path).lower()
        for pattern in LLM_TRIGGER_PATTERNS:
            if re.search(pattern, name):
                result["suspicious"] = True
                result["reasons"].append(f"Suspicious filename pattern: {pattern}")

    """
    ZIP archives:
        •	Detection of nested files or zip bombs
    """
    def inspect_zip(self, file_path: str, result: dict):
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                if len(z.namelist()) > 50:
                    result["suspicious"] = True
                    result["reasons"].append("Nested archive or zip bomb suspicion")
        except Exception as e:
            logger.warning(f"ZIP analysis failed for {file_path}", exc_info=True)

    def scan(self, file_path: str) -> dict:
        triggered_rules = None
        final_score = 0.0
        scan_results = []
        outcome = None
        content = None
        
        try: 
            # read content
            content = self.content_parser(file_path)
            #logger.info("Loaded content from file.")           
            if content is None:
                raise ValueError(f"Content load failed: {file_path}")
            
            # Vector checks
            self.inspect_filename(file_path, scan_results)  
            ext = Path(file_path).suffix.lower()   
            if ext in [".jpg", ".jpeg", ".png", "gif", "webp"]: 
                self.inspect_image_metadata(file_path, scan_results)
            elif ext == ".zip":
                self.inspect_zip(file_path, scan_results)
            else:
                parser = SUPPORTED_FILE_TYPES.get(ext)
                if not parser:
                    if is_file_binary_fn(file_path):
                        raise ValueError(f"Unsupported binary file format: {ext}")
                    # fallback to txt file parser (to support script and code files loading)
                else:
                    try:
                        # perform regex scan
                        scan_results = self.regex_scan(content)     
                        logger.debug(f"extract triggered rules from regex check: {scan_results}")       
                        # extract triggered rules
                        if scan_results:
                            for rule in scan_results:
                                triggered_rules.append(rule['rule_name'])
                    except Exception as e:
                        logger.error(f"File Content scan failed: {e}")

                    try:
                        mime_type = magic.from_file(file_path, mime=True)           
                        if mime_type in SUSPICIOUS_TYPES:
                            scan_results.append({
                            'rule_name': "suspicious MIME Type",
                            'suspicious': True,
                            'metadata': "",
                            'matched_keys': "",
                            'severity_score': 10.0,
                            'message': f"Suspicious MIME type: {mime_type}"
                            })
                        logger.debug(f"mime type not suspicious: {mime_type}") 
                    except Exception as e:
                        logger.warning(f"MIME type detection failed for {file_path}", exc_info=True)

                    ext = Path(file_path).suffix.lower()
                    if ext in SUSPICIOUS_EXTENSIONS:
                        scan_results.append({
                            'rule_name': "suspicious Extension Type",
                            'suspicious': True,
                            'metadata': "",
                            'matched_keys': "",
                            'severity_score': 10.0,
                            'message': f"Suspicious extension: {ext}"
                            })
                    
                    logger.debug(f"extension not suspicious: {ext}")

                    size_mb = os.path.getsize(file_path) / (1024 * 1024)
                    if size_mb > MAX_FILE_SIZE_MB:
                        scan_results.append({
                            'rule_name': "Max file size exceed",
                            'suspicious': True,
                            'metadata': "",
                            'matched_keys': "",
                            'severity_score': 10.0,
                            'message': f"File size exceeds limit: {round(size_mb, 2)}"})

                    logger.debug(f"size not exceeded: {size_mb}")
                    if self.contains_invisible_unicode(content):
                        scan_results.append({
                            'rule_name': "invisible prompt injection",
                            'suspicious': True,
                            'metadata': "",
                            'matched_keys': "",
                            'severity_score': 10.0,
                            'message': f"File contains suspicious Unicode tag set"})
                        
                    logger.debug(f"file doesn't contain invisible unicode")

            messages = "File contains suspicious elements:"

            for re in scan_results:
                if re.get('suspicious', True):
                    final_score += re.get('severity_score', 0.0)
                    
                    messages = ', '.join(re['matched_keys'])
                    triggered_rules = ', '.join(re['rule_name'])
            

            if final_score >= self.threshold:
                outcome = self.get_scan_result_from_score(final_score)
                outcome.score = f"{final_score:.2f}"
                outcome.rules_triggered = triggered_rules
                outcome.message = messages
                outcome.action=ScanAction(self.scan_action).name

        except Exception as e:
            logger.error("Exception during File scan: %s", str(e), exc_info=True)
            return ScanResult(ScanStatus.ERROR.value, ScanDecision.FLAG.value, ScanAction.FLAG.name, "SimilarityScanner: An error ocurred during the scan", "", 0.0, ScanRiskLevel.NONE.name)
            
        return outcome if outcome is not None else ScanResult(
            status=ScanStatus.SUCCESS.value,
            decision=ScanDecision.ALLOW.value,
            action=ScanAction.PASS.name,
            message="FileUploadScanner: No issues found on the file",
            rules_triggered="",
            score=0.0,
            criticallity=ScanRiskLevel.NONE.name
        )
