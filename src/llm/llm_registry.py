
from pathlib import Path
import yaml
from typing import Dict
from src.functions.file_content_parser import FileContentParser
from src.shared.logger import init_logger
from .basellm import BaseLLM
from .ollama_llm import OllamaLLM

# Set up logging
logger = init_logger("LLMRegistry")

LLM_CONFIG_PATH = "./src/shared/llm_conf.yaml"

MODEL_REGISTRY: Dict[str, type] = {
    "ollama": OllamaLLM,
    # "openai": OpenAILLM,
}

class LLMRegistry:
    """
    LLMRouter dynamically instantiates and routes calls to configured LLMs.
    """

    def __init__(self):
        if Path(LLM_CONFIG_PATH).is_file():
            self.config_path = LLM_CONFIG_PATH
            logger.info(f"Loading LLM configuration from {LLM_CONFIG_PATH}")
        else:
            logger.error(f"LLM configuration file not found at {LLM_CONFIG_PATH}. Using default settings.")
            raise FileNotFoundError(f"Configuration file {LLM_CONFIG_PATH} does not exist.")
        
        self.models: Dict[str, BaseLLM] = {}
        self.load_from_yaml()

    def load_from_yaml(self):
        try:
            content_parser = FileContentParser()
            #with open(self.config_path, "r") as f:
                #config = yaml.safe_load(f)
            config = content_parser(self.config_path)

            for route_name, cfg in config.items():
                provider = cfg.get("PROVIDER")
                model_id = cfg.get("MODEL_ID")
                params = cfg.get("PARAMS", {})
                embed = cfg.get("EMBED")

                if provider not in MODEL_REGISTRY:
                    raise ValueError(f"Unknown provider: {provider}")

                self.models[route_name] = MODEL_REGISTRY[provider](model_id=model_id, embed=embed, **params)
        except Exception as e:
            logger.error(f"Failed to load YAML file: {e}")
            return []
    
    async def load_model(self, route: str = "default"):
        if route not in self.models:
            raise ValueError(f"Unknown route: {route}")
        return self.models[route]

