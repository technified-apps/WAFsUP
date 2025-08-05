from typing import Dict, Union, Any
import re
from dataclasses import dataclass, field
from typing import Dict, List

@dataclass
class PatternMeta:
    description: str
    threat_level: int
    threshold: float
    category: str

@dataclass
class Pattern:
    name: str
    meta: PatternMeta
    strings: Dict[str, Dict[str, Any]]
    functions: List[str]
    def __repr__(self):
        return (
            f"=== Pattern ===\n"
            f"Name: {self.name}\n"
            f"Meta: {self.meta}\n"
            f"Regex: {self.strings}\n"
            f"functions: {self.functions}\n"
        )


class WAFPattern:
    def __init__(self, pattern: Pattern):
        self.pattern = pattern

    def get_name(self) -> str:
        return self.pattern.name

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "description": self.pattern.meta.description,
            "threat_level": self.pattern.meta.threat_level,
            "threshold": self.pattern.meta.threshold,
            "category": self.pattern.meta.category
        }

    def get_functions(self) -> list[str]:
        return self.pattern.functions

    def get_compiled_patterns(self) -> Dict[str, Dict[str, Any]]:
        """
        Uses PatternLoader to compile this pattern’s string rules.
        Returns a dictionary of compiled patterns indexed by string ID.
        """ 
        return self.compiled
    
    # Convert Pattern dataclass to loader-compatible dict format
    def get_pattern(self) -> Dict[str, Dict[str, Union[re.Pattern, bytes]]]:
        """
        Uses PatternLoader to compile this pattern’s string rules.
        Returns a dictionary of compiled patterns indexed by string ID.
        """
        # Convert Pattern dataclass to loader-compatible dict format
        pattern_dict = {
            'name': self.pattern.name,
            'meta': {
                'description': self.pattern.meta.description,
                'threat_level': self.pattern.meta.threat_level,
                'threshold': self.pattern.meta.threshold,
                'category': self.pattern.meta.category
            },
            'strings': self.compiled
        }
        return pattern_dict
    
