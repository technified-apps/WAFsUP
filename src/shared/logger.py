from datetime import datetime
import logging
from pathlib import Path

LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DEFAULT_LOG_LEVEL: int = logging.INFO
LOG_PATH: str = "./logs/"
Path(LOG_PATH).mkdir(parents=True, exist_ok=True)
log_name = "log_"+datetime.now().strftime("%Y-%m-%d") + ".txt"
log_path = Path(LOG_PATH) / log_name

def init_logger(name: str = __name__, verbose: bool = False) -> logging.Logger:
    logging.basicConfig(
        level=logging.DEBUG if verbose else DEFAULT_LOG_LEVEL,
        format=LOG_FORMAT,
    )
    return logging.getLogger(name)

def log_event(prompt: str, reason: str):
    with open(log_path, "a") as log:
        log.write(f"[{datetime.now()}] Blocked: {reason} | Prompt: {prompt}\n")

def log(message: str):
    with open(log_path, "a") as log:
        log.write(f"[{datetime.now().strftime("%Y-%m-%d")}] - {message}\n")

