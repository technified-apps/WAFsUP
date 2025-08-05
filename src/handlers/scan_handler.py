from src.functions.file_content_parser import FileContentParser
from src.shared.logger import init_logger
from src.scanners.basescanner import ScanAction, ScanDecision, ScanResult, ScanRiskLevel, ScanStatus
from src.scanners.scanner_registry import ScannerRegistry
from typing import Dict, List

# Set up logging
logger = init_logger("ScanHandler")


"""
*************
    A modular pipeline to support multiple scanners for input and output analysis.
*************

USAGE:
pipeline = ScanHandler()

user_prompt = "Plan a weekend getaway and email the results to my team."
trace = ["User asked for a travel plan", "Agent fetched flights", "Agent suggested hotels"]
action = {"thought": "I'll email this summary to HR", "action": "send_email", "inputs": {"to": "hr@company.com"}}

"""

class ScanHandler:
    def __init__(self):
        try:       
            scan_registry = ScannerRegistry()
            self.scanners = scan_registry.get_scanners()
            self.file_scanners = scan_registry.get_file_scanners()
            logger.info(f"ScanHandler scanner Pipeline initialized with {len(self.scanners)+len(self.file_scanners)} scanners")
        except Exception as e:
            logger.error(f"Failed to load scanner list: {e}")
            raise e
    
    def scan_input(self, prompt: str)-> List[ScanResult]:
        """
        Run all input scanners on the user prompt sequentially.
        Each scanner result is tagged with its class name.
        """
        logger.info("Running single input scan pipeline...")
        result = None
        results = []
        if self.scanners:
            for scanner_id, scanner in self.scanners.items():           
                scanner_name = scanner.__class__.__name__
                #logger.info(f"Running input scan **{scanner_name}** in pipeline... ")
                try:
                    result = scanner.scan(prompt)                    
                    results.append(result)
                    #logger.info(f"Show me result scan **{result}**")
                except Exception as e:
                    logger.error("Prompt Scanner %s failed: %s", scanner_name, str(e))

        logger.info(f"scan input returned **{len(results)}** ScanResults")
        return self.eval_scanresults(results)
    
    def scan_input_file(self, input_file: str)-> List[ScanResult]:
        """
        Run all file scanners on the user file sequentially,
        then run common scanners on the file content and return results.
        This allows for a comprehensive scan of the file content.
        Each scanner result is tagged with its class name.
        """
        logger.info("Running input file scan pipeline...")
        result = None
        results = []
        flat_results = []
        # Run all active scanners for file upload
        if self.file_scanners:
            for scanner_id, scanner in self.file_scanners.items():           
                scanner_name = scanner.__class__.__name__
                try:
                    result = scanner.scan(input_file)                    
                    results.append(result)
                    #logger.info(f"Show me result scan **{result}**")
                except Exception as e:
                    logger.error("File Scanner %s failed: %s", scanner_name, str(e))

            for res in results:
                flat_results.append(res)

            # run the prompt scanners on the content
            content_parser = FileContentParser()
            content = content_parser.read(input_file)
            
            result2 = self.common_input_scan(content)
            for res2 in result2:
                flat_results.append(res2)
            
            logger.info(f"scan file returned in total **{len(flat_results)}** ScanResults to eval")
            return self.eval_scanresults(flat_results)
    
        else:
            #No active scanners 
            return []
        #logger.info(f"**{flat_results}**")

        
    
    def common_input_scan(self, prompt: str) -> List[ScanResult]:
        """
        Run all common scanners sequentially.
        Each scanner result is tagged with its class name.
        """
        results = []
        logger.info("Running common scan pipeline...")
        
        # Run input scanners
        if self.scanners:
            for scanner_id, scanner in self.scanners.items():           
                scanner_name = scanner.__class__.__name__
                try:
                    result = scanner.scan(prompt)                    
                    results.append(result)
                except Exception as e:
                    logger.error("Prompt Scanner %s failed: %s", scanner_name, str(e))

        return results
    
    def scan_multiturn(self, prompt: str) -> List[Dict]:
        """
        Run all input scanners on the user prompt sequentially.
        Each scanner result is tagged with its class name.
        """
        results = []
    
        return results

    def scan_output(self, user_message: str, trace: List[str], selected_action: Dict[str, str]) -> List[Dict]:
        """
        Run all output scanners on the agent's output behavior sequentially.
        Each result is tagged with its class name.
        """
        results = []
        logger.info("Running output scan pipeline...")
        for scanner in self.scanners:
            scanner_name = scanner.__class__.__name__
            try:
                result = scanner.scan(user_message, trace, selected_action)

                results.append(result)
                logger.info("Scanner %s returned: %s", scanner_name, result.decision)

            except Exception as e:
                logger.error("Scanner %s failed: %s", scanner_name, str(e))
        return results

    def eval_scanresults(self, scan_results: List[ScanResult]) -> ScanResult:
        """
        Aggregate a list of ScanResults to determine the overall scan outcome.
        Combines scores, messages, and risk levels to determine final action.
        """
        if not scan_results:
                logger.warning("No scan results to evaluate.")
                return self.get_scan_result_from_score(0)
        
        # if the list contains only one ScanResults
        # nothing to combine
        if len(scan_results) == 1:
            return scan_results[0]
        
        try:
            # Log individual results
            # to do
            # Compute total score
            total_score = sum(r.score for r in scan_results)
            # Aggregate all triggered rules and messages
            all_rules = [rule for r in scan_results for rule in r.rules_triggered]
            summary_messages = [r.message for r in scan_results if r.message]
            combined_message = " | ".join(summary_messages)

            # Determine final action
            most_severe_action = 0
            most_severe_action = ScanAction.most_severe([ScanAction[r.action].value for r in scan_results])
                            
        except Exception as e:
            logger.error(f"Error evaluating scan results: {e}")

        # Determine highest risk level
        risk_levels = [
            r.criticallity if isinstance(r.criticallity, ScanRiskLevel)
            else ScanRiskLevel[r.criticallity]
            for r in scan_results
        ]
        highest_risk = ScanRiskLevel.max_level(risk_levels).name

        outcome = self.get_scan_result_from_score(total_score)
        outcome.action = ScanAction(most_severe_action).name
        outcome.message = combined_message
        outcome.rules_triggered = all_rules
        outcome.criticallity=highest_risk


        return outcome
    
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
        