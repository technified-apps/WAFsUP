import abc
from src.shared.logger import init_logger

logger = init_logger("BaseLLM")


class BaseLLM(abc.ABC):
    """
    Abstract base class for large language models (LLMs).
    Defines a common interface for querying models.
    """

    def __init__(self, model_id: str, embed: str, **kwargs):
        self.model_id = model_id
        self.params = kwargs
        self.embed = embed

    @abc.abstractmethod
    async def query(self, prompt: str) -> str:
        """
        Run the LLM asynchronously on the given prompt.
        Must be implemented by subclasses.
        """
        pass