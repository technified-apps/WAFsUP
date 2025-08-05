"""
This scan analyzes text using regExp to identify inappropriate 
or harmful content.
"""

import json
import logging
from typing import Any, List, Dict
from pathlib import Path
from src.shared.pattern import Pattern
from src.shared.pattern_loader import PatternLoader
from src.shared.logger import init_logger
from src.functions.rule_functions import intent_score, invisible_text, obfuscation_score, structure_score, encoding_score, persona_score, cumulative_soft_triggers, token_score
import json
from pathlib import Path
from datetime import datetime
from .basescanner import ScanAction, ScanDecision, ScanResult, ScanRiskLevel, ScanStatus, Scanner

# Set up logging
logger = init_logger("RegexScanner")

CACHE_FILE = "./src/patterns/patterns_cache.pkl"
PATTERN_FILE = "./src/patterns/patterns.yaml"
REPORT_FILE = "./reports/report"

available_functions = {
    'intent_score': intent_score,
    'structure_score': structure_score,
    'encoding_score': encoding_score,
    'persona_score': persona_score,
    'cumulative_soft_triggers': cumulative_soft_triggers,
    'token_score': token_score,
   # 'entropy_score': entropy_score,
    'invisible_text' : invisible_text, 
    'obfuscation_score': obfuscation_score
}

function_weights = {
    'intent_score': 1.5,
    'structure_score': 1.0,
    'encoding_score': 1.0,
    'persona_score': 1.2,
    'cumulative_soft_triggers': 1.0,
    'token_score': 1.0,
 #   'entropy_score': 1.2,
    'obfuscation_score': 1.2
}

class RegexScanner(Scanner):
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

        self.patterns = Dict[str, Pattern]
        self.functions = available_functions

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
    
    def _scan(self, raw_prompt: str)   -> List[dict]: 
        """
        Scans the prompt and returns:
        - empty: True if no patterns matched
        - results: List of matched pattern categories
        """  
        results = []
        func_score = 0
        regex_score = 0

        if self.patterns is None:
            logger.warning("Scan aborted: configuration failed to load.")
            return  # ⛔ Do not proceed
        else:
            #print(f" **** compiled_strings len: {len(self.compiled_strings)}")
            content = self.normalize_prompt(raw_prompt)
            # Loop over the Pattern objects, entry is a Pattern
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

                # apply function scoring
                for fname in entry.functions:
                    if fname in available_functions:
                        fscore = available_functions[fname](content)
                        #logging.info(f"matched {fname} : {fscore}")              
                        weight = function_weights.get(fname, 1.0)

                        if isinstance(fscore, (int, float)):
                            func_score += fscore * float(weight)
                        elif isinstance(fscore, dict) and "score" in fscore:
                            func_score += float(fscore["score"]) * float(weight)
                        else:
                            logger.warning(f"Function '{fname}' returned unsupported type: {type(fscore)}")
                            continue

                        if fscore >= 1:    
                            results.append({
                                'rule_name': fname,
                                'metadata': {'category': "function scan"},
                                'matched_keys': True,
                                'severity_score': func_score
                            })
                  
        #self.save_scan_results(results, content)
        return results
        
    def scan(self, raw_prompt: str) -> ScanResult:
        triggered_rules = []
        scan_results = []
        outcome = None
        try:
            # perform the actiual scan
            scan_results = self._scan(raw_prompt)            
            # extract triggered rules
            if scan_results:
                for rule in scan_results:
                    triggered_rules.append(rule['rule_name'])

                meets_threshold, final_score = self.threat_score(scan_results)
                ## TO DO: add scan levels that will trigger LLM guard even on low score
                if meets_threshold:
                    outcome = self.get_scan_result_from_score(final_score)
                    outcome.score = f"{final_score:.2f}"
                    outcome.message += f"RegexScanner matched {len(scan_results)} rules"
                    outcome.rules_triggered = triggered_rules
                    outcome.action = ScanAction(self.scan_action).name

        except Exception as e:
            logger.error("Exception during regex scan: %s", str(e), exc_info=True)
            return ScanResult(ScanStatus.ERROR.value, ScanDecision.FLAG.value, ScanAction.FLAG.name, "RegexScanner: An error ocurred during the scan", "", 0.0, ScanRiskLevel.NONE.name)
            
        return outcome if outcome is not None else ScanResult(
            status=ScanStatus.SUCCESS.value,
            decision=ScanDecision.ALLOW.value,
            action=ScanAction.PASS.name,
            message="RegexScanner: No content safety issues found",
            rules_triggered="",
            score=0.0,
            criticallity=ScanRiskLevel.NONE.name
        )


    def threat_score(self, scan_results):
        try:
            total = sum(r['severity_score'] for r in scan_results)
            categories = set(r['metadata'].get('category') for r in scan_results)
            bonus = len(categories)
            severity = total + bonus
            
            # Apply rule-specific soft thresholding
            soft_threshold_rules = {'debug_mode_spoofing', 'policy_evasion', 'alignment_breaking'}
            
            meets_threshold = (
                severity >= self.block_score or
                (scan_results[0]['rule_name'] in soft_threshold_rules and severity >= 1) 
            )  
        except Exception as e:
            logger.error("threat_score: %s", str(e))

        return meets_threshold, round(severity, 2)
    
    def save_scan_results(self,results, prompt):
        """
        Saves scan results to a readable file format (JSON or TXT).
        - `results`: list of matched rule dicts
        - `prompt`: the input prompt that was scanned
        - `scanner_name`: optional label for the rule set / scanner
        - `output_dir`: base folder to write results

        Saves scan results into a JSON report file named by date.
        Appends new entries if the file exists, and ensures prompts are tracked.
        """
        Path(REPORT_FILE).mkdir(parents=True, exist_ok=True)
        report_name = "report_"+datetime.now().strftime("%Y-%m-%d") + ".json"
        report_path = Path(REPORT_FILE) / report_name

        # Load existing report if available
        if report_path.exists():
            with open(report_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
        else:
            report_data = {
                "date": datetime.now().strftime("%Y-%m-%d"),
                "entries": []
            }

        # Append new result
        report_data["entries"].append({
            "prompt": prompt,
            "matches": results
        })

        # Write back to file
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)

        print(f"📁 Updated daily scan report: {report_path}")
    
    