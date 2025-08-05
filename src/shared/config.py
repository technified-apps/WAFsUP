LLM_MODEL = "gpt-4"
SIMILARITY_THRESHOLD = 0.6
BLOCKED_PATTERNS = [
    r'ignore\s+previous\s+instructions',
    r'act\s+as',
    r'pretend\s+to\s+be',
    r'reveal\s+system\s+prompt',
    r'unfiltered\s+response',
    r'break\s+character',
    r'developer\s+mode',
]
MAX_REQUESTS_PER_MIN = 10