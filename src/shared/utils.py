import re
import string
import uuid
import random

_FIRST_CAP_PATTERN = re.compile("(.)([A-Z][a-z0-9]+)")
_ALL_CAP_PATTERN = re.compile("([a-z0-9])([A-Z])")

def normalize_text(text: str) -> str:
    """Basic normalization: lowercase, strip whitespace, remove punctuation."""
    text = text.lower()
    text = text.strip()
    text = text.translate(str.maketrans("", "", string.punctuation))
    text = re.sub(r"\s+", " ", text).strip()
    return text


def camelcase_to_snakecase(name: str) -> str:
    """Converts a CamelCase string to snake_case.

    Args:
        name (str): The CamelCase string to convert.

    Returns:
        str: The converted snake_case string.
    """
    s1 = _FIRST_CAP_PATTERN.sub(r"\1_\2", name)
    return _ALL_CAP_PATTERN.sub(r"\1_\2", s1).lower()


def snake_to_camelcase(name: str) -> str:
    """Converts a snake_case string to CamelCase.

    Args:
        name (str): The snake_case string to convert.

    Returns:
        str: The converted CamelCase string.
    """
    return "".join(n.capitalize() for n in name.split("_"))

def init_random_seed(seed: int) -> None:
    """Init random generator with seed."""
    global secure_random
    random.seed(seed)
    secure_random = random


def new_uuid() -> str:
    """Helper to generate new UUID v4.

    In testing mode, it will generate a predictable set of UUIDs to help debugging if random seed was set dependent on
    the environment variable DEBUG_MODE.
    """
    random_bits = secure_random.getrandbits(128)
    return str(uuid.UUID(int=random_bits, version=4))


def new_readable_uuid(name: str) -> str:
    """Creates a new uuid with a human readable prefix."""
    return f"({name}){new_uuid()}"


def new_var_uuid() -> str:
    """Creates a new uuid that is compatible with variable names."""
    return new_uuid().replace("-", "_")