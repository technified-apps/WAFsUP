import pickle
import re
import time
import logging
from pathlib import Path
from typing import List, Dict, Any
from src.functions.file_content_parser import FileContentParser

logger = logging.getLogger(__name__)

class PatternLoader:
    def __init__(self, 
                 pattern_file: str,
                 cache_file: str,
                 cache_file: str,
                 cache_ttl: int = 86400,  # 24 hours
                 refresh_cache: bool = False):
        self.pattern_file = pattern_file
        self.cache_file = cache_file
        self.cache_file = Path(cache_file)
        self.cache_ttl = cache_ttl
        self.refresh_cache = refresh_cache
        self.content_parser = FileContentParser()

    def get_compiled_patterns(self) -> List[Dict[str, Any]]:
        if not self.refresh_cache and self._is_cache_valid():
            try:
                with open(self.cache_file, "rb") as f:
                    data = pickle.load(f)
                    logger.info("Loaded compiled patterns from binary cache.")
                    return data['patterns']
            except Exception as e:
                logger.warning(f"Failed to load compiled cache: {e}. Rebuilding.")
                self.cache_file.unlink(missing_ok=True)

        entries = self._load_pattern_source()
        if not entries:
            return []

        compiled_patterns = self._compile_patterns(entries)
        self._cache_compiled_patterns(compiled_patterns)
        return compiled_patterns

    def _is_cache_valid(self) -> bool:
        return self.cache_file.exists() and (time.time() - self.cache_file.stat().st_mtime < self.cache_ttl)

    def _load_pattern_source(self) -> List[Dict[str, Any]]:
        source = self.cache_file if not self.refresh_cache and Path(self.cache_file).exists() else self.pattern_file
        try:
            data = self.content_parser(source)
            logger.info(f"Loaded patterns from {'cache' if source == self.cache_file else 'source'} file.")
            return data.get('patterns', [])
        except Exception as e:
            logger.warning(f"Failed loading from {source}: {e}")
            if source != self.pattern_file:
                try:
                    data = self.content_parser(self.pattern_file)
                    logger.info("Fallback: Loaded patterns from source file.")
                    return data.get('patterns', [])
                except Exception as ex:
                    logger.error(f"Failed fallback pattern load: {ex}")
        return []

    def _compile_patterns(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        compiled_patterns = []
        for entry in entries:
            compiled = {}
            for key, val in entry.get('strings', {}).items():
                try:
                    val = val.strip()
                    if not val:
                        continue
                    if val.startswith("{") and val.endswith("}"):
                        compiled[key] = {'type': 'hex', 'pattern': bytes.fromhex(val.strip("{} "))}
                    elif re.search(r'[\\^$.*+?|()[\]]', val) or val.startswith("(?i"):
                        regex = re.compile(val, re.IGNORECASE)
                        compiled[key] = {'type': 'regex', 'pattern': regex}
                    else:
                        pattern = re.compile(rf'\b{re.escape(val)}\b', re.IGNORECASE)
                        compiled[key] = {'type': 'regex', 'pattern': pattern}
                except Exception as e:
                    logger.warning(f"Invalid pattern '{key}': {e}")
            if compiled:
                compiled_patterns.append(compiled)
        return compiled_patterns

    def _cache_compiled_patterns(self, patterns: List[Dict[str, Any]]):
        try:
            with open(self.cache_file, "wb") as f:
                pickle.dump({'timestamp': time.time(), 'patterns': patterns}, f)
                logger.info("Compiled patterns cached successfully.")
        except Exception as e:
            logger.warning(f"Could not write compiled pattern cache: {e}")

    def _is_testable_regex(self, pattern: re.Pattern) -> bool:
        test_inputs = ["test", "123", "payload", "example"]
        return any(pattern.search(s) for s in test_inputs)

    def test_pattern_match(self, compiled_pattern: Dict[str, Any], test_string: str) -> Dict[str, bool]:
        results = {}
        for key, meta in compiled_pattern.items():
            try:
                if meta['type'] == 'hex':
                    results[key] = meta['pattern'] in test_string.encode(errors='ignore')
                elif meta['type'] == 'regex':
                    results[key] = bool(meta['pattern'].search(test_string))
            except Exception as e:
                logger.warning(f"Error testing pattern {key}: {e}")
                results[key] = False
        return results