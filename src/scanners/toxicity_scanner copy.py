"""
This scan is a content safety check system that analyzes text for inappropriate or harmful content.
"""

import re
from typing import Dict, List
from src.shared.logger import init_logger
from src.scanners.basescanner import ScanDecision, ScanResult, ScanRiskLevel, ScanStatus, Scanner

# Set up logging
logger = init_logger("ContentSafetyScanner")


class ContentCategories:
    PROFANITY_VULGAR = {
        'mild': [
            "arse", "ass", "damn", "dick", "piss", "pissed", "crap", "hell", "bugger", "bloody", "bollocks", "wuss"
        ],
        'moderate': [
            "bastard", "bitch", "fuck", "fucking", "fuckin", "motherfucker", "shit",
            "asshole", "pussy", "penis", "vagina", "cock", "boobs", "tits", "titties",
            "douchebag", "prick", "whore", "slut", "jackass", "balls", "nuts", "schlong"
        ],
        'severe': [
            "cunt", "dildo", "blowjob", "cum", "ejaculate", "jerk-off", "masturbate",
            "wanker", "shag", "twat", "ballsack", "boner", "muff", "nutsack",
            "sucker", "lick", "licker", "fuckface", "dumbass", "fuckhead",
            "shithead", "shitface", "cumslut", "cumbucket", "semen", "pecker"
        ]
    }

    HATE_SPEECH = {
        'mild': [
            "homo", "jew", "jewish", "muslim", "muslims", "queer", "black", "whitey", "cracker"
        ],
        'moderate': [
            "homophobic", "racist", "anti-semitic", "islamophobe", "homophobe",
            "bigot", "xenophobe", "hate speech", "antisemitism"
        ],
        'severe': [
            "chink", "nigga", "nigger", "coon", "negro", "faggot", "dyke",
            "nazi", "jap", "sandbar", "mongoloid", "furfag", "coont",
            "wetback", "spic", "gook", "kike", "towelhead", "raghead"
        ]
    }

    SEXUAL_EXPLICIT = {
        'mild': [
            "porn", "smut", "erotic", "nudes", "naked", "sexy", "kinky", "innuendo"
        ],
        'moderate': [
            "anal", "clitoris", "clit", "pornography", "orgasm",
            "redtube", "xxx", "hardcore", "fetish", "stripper", "bondage", "lingerie", "dildo"
        ],
        'severe': [
            "buttrape", "anilingus", "cumshot", "rape", "molest",
            "cumdumpster", "cumguzzler", "gangbang", "necrophilia",
            "pedo", "pedophile", "pedophilia", "child predator",
            "loli", "lolicon", "cub", "bestiality", "incest", "rape fantasy"
        ]
    }

    VIOLENCE_HARMFUL = {
        'mild': [
            "die", "shoot", "kill", "stab", "punch", "beat", "slap", "attack", "hurt"
        ],
        'moderate': [
            "bomb", "bombing", "bombed", "shooting",
            "cliff", "bridge", "assault", "murder", "strangle", "torture", "execute", "blow up"
        ],
        'severe': [
            "terrorist", "terrorism",
            "kys", "i want to die", "cut myself", "fuck life",
            "suicide", "hang myself", "self-harm", "slit my wrists", "end it all"
        ]
    }

severity_weights = {
            'mild': 0.3,
            'moderate': 0.6,
            'severe': 1.0
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
        block_score: float = 1.0):
        super().__init__(
            scanner_name=scanner_name, 
            scan_action=scan_action, 
            message=message,
            ingress=ingress,
            egress=egress,
            scan_status=scan_status,
            threshold=threshold,
            block_score=block_score)
        
        
    def calculate_severity_score(self, matches: set, category_levels: dict) -> tuple[float, dict]:
        """Calculate severity score and categorize matched words."""
        severity_weights = {
            'mild': 0.3,
            'moderate': 0.6,
            'severe': 1.0
        }

        results = {
            'mild': [],
            'moderate': [],
            'severe': []
        }

        max_score = 0

        for severity, words in category_levels.items():
            matched = [word for word in words if word in matches]
            if matched:
                results[severity] = matched
                max_score = max(max_score, severity_weights[severity])

        return max_score, results

    def _scan(self, text: str) -> tuple[float, dict]:
        """Check text content against all categories."""
        text = text.lower()
        results = {}
        max_total_score = 0

        for category_name, category_levels in ContentCategories.__dict__.items():
            if category_name.startswith('_'):
                continue

            # Create pattern for all words in this category
            all_words = [word for level in category_levels.values() for word in level]
            pattern = re.compile(r'\b(' + '|'.join(map(re.escape, all_words)) + r')\b', re.IGNORECASE)
            severity_matches = []
            score = 0.0
            matches = set(pattern.findall(text))
            if matches:
                for severity, words in category_levels.items():
                    matched = [word for word in words if word in matches]
                    if matched:
                        results[severity] = matched
                
                
                #severity_matches = self.calculate_severity_score(matches, category_levels)
                max_total_score = self.estimate_toxicity_score(results)

                logger.info(f"***-max_total_score: {max_total_score} - results: {results}")

                results[category_name] = {
                    'score': score,
                    'matches': severity_matches
                }

        return max_total_score, results

    def scan(self, text: str) -> ScanResult:
        outcome = None
        """Handle content safety check request."""
        final_score, results = self._scan(text)
        """
        results = [
            {'score': 0.6, 'matches': {'mild': [], 'moderate': ['shit'], 'severe': []}},
            {'score': 1.0, 'matches': {'mild': [], 'moderate': [], 'severe': ['faggot']}},
            {'score': 0.6, 'matches': {'mild': ['attack'], 'moderate': ['murder', 'execute'], 'severe': []}}]
        results: [
            {'score': 0.6, 'matches': {'mild': [], 'moderate': ['shit'], 'severe': []}}, 
            {'score': 1.0, 'matches': {'mild': [], 'moderate': [], 'severe': ['faggot']}}, 
            {'score': 0.6, 'matches': {'mild': ['attack'], 'moderate': ['murder', 'execute'], 'severe': []}}] 
        """
        try: 
            extracted = []
            sc = 0.0

            for cat, result in results.items():
                cate = cat  
                sc = result['score']
                m = result['matches']
                moderate_hits = 0
                severe_hits = 0
                for severity, words in m.items():
                        for word in words:
                            moderate_hits += 1 if severity == "moderate" else 0
                            severe_hits += 1 if severity == "severe" else 0
                            extracted.append({
                                'category': cate,
                                'score': sc,
                                'word': word,
                                'severity': severity
                            })

            """
            for cat, result in results.items():
                cate = cat       
                logger.info(f"***-category: {cate} - result: {result}")
                for matches in result:
                    sc = result['score']
                    match = result['matches']
                    logger.info(f"***********score: {sc} - matches: {match}")
                    for severity, words in matches.items():
                        for word in words:
                            extracted.append({
                                'score': score,
                                'word': word,
                                'severity': severity
                            })"""

            #logger.info(f"category: {cate} - extracted: {extracted} - score: {sc} - final_score: {final_score}")

            """if details:
                category = ""
                matches = ""
                results = []
                for cat, result in details.items():
                    category += cat +", "
                    #matches += result[cat]["matches"] +", "
                    matches += ", "
                    results.append(result)
                    logger.info(f"result: {result} ")
            
                
                logger.info(f"*********results: {results} ")
                if final_score >= self.block_score:
                    outcome = self.get_scan_result_from_score(final_score)
                    outcome.action = self.scan_action
                    outcome.message += f" - ContentSafetyScanner: Matched {category}: {matches}"
                    outcome.rules_triggeredf = f"{category}: {matches}"
            
            else:
                logger.debug("No content safety issues found")
            """
        except Exception as e:
            outcome = ScanResult(ScanStatus.ERROR.value, ScanDecision.FLAG.value, self.scan_action, "ContentSafetyScanner: An error ocurred during the scan", "", 0.0, ScanRiskLevel.NONE)
            logger.error("scan exception: %s", str(e))

        return outcome if outcome is not None else ScanResult(
            status=ScanStatus.SUCCESS.value,
            decision=ScanDecision.ALLOW.value,
            action=self.scan_action,
            message="ContentSafetyScanner: No content safety issues found",
            rules_triggered="",
            score=0.0,
            criticallity=ScanRiskLevel.NONE
        )
    
    def estimate_toxicity_score(self, matches: Dict[str, List[str]]) -> float:
        """
        Estimate a toxicity score based on severity and word matches.

        Args:
            matches (dict): A dictionary with keys 'mild', 'moderate', 'severe',
                            each containing a list of matched words.

        Returns:
            float: The computed toxicity severity score.

        Raises:
            ValueError: If input format is invalid.
        """
        try:
            if not isinstance(matches, dict):
                raise ValueError("Expected 'matches' to be a dictionary.")

            score = 0.0

            for severity, weight in severity_weights.items():
                words = matches.get(severity, [])
                if not isinstance(words, list):
                    raise ValueError(f"Expected list of words for severity '{severity}', got {type(words).__name__}")
                count = len(words)
                score += count * weight
                logger.debug(f"{severity.capitalize()} matches: {count} × {weight} = {count * weight}")

            logger.info(f"Final computed severity score: {score}")
            return score

        except Exception as e:
            logger.error(f"Error while estimating toxicity score: {e}")
            raise