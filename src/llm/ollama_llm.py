from src.shared.logger import init_logger
from .basellm import BaseLLM
from ollama import AsyncClient

logger = init_logger("OllamaLLM")

class OllamaLLM(BaseLLM):
    """
    Async wrapper for Ollama-compatible local models using the Ollama client.
    """

    def __init__(self, model_id: str, embed: str, **kwargs):
        super().__init__(model_id=model_id, embed=embed, **kwargs)
        try:           
            self.client = AsyncClient()
        except ImportError as e:
            logger.error("Failed to import Ollama. Try: pip install ollama")
            raise e

    async def query(self, prompt: str) -> str:
        try:
            response = await self.client.chat(
                model=self.model_id,
                messages=[{"role": "user", "content": prompt}],
                **self.params
            )
            return response.get("message", {}).get("content", "[ERROR: No response]")
        except Exception as e:
            logger.error(f"Ollama query failed: {e}")
            return "[ERROR: LLM query failed]"