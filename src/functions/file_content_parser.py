import os
from typing import Dict, Type
from src.shared.logger import init_logger
from src.handlers.file_handler import TXTParser, JSONParser, PDFParser, YAMLParser, ParquetParser, PICKLEParser

# Set up logging
logger = init_logger("FileContentParser")

SUPPORTED_FILE_TYPES: Dict[str, Type] = {
    ".txt": TXTParser,
    ".csv": TXTParser,
    ".pdf": PDFParser,
 #   ".docx": DOCXParser,
    ".json": JSONParser,
 #   ".xml": XMLParser,
    ".yaml": YAMLParser,
    ".yml": YAMLParser,
    ".parquet": ParquetParser,
    ".pkl": PICKLEParser,
 #   ".html": HTMLParser,
 #   ".htm": HTMLParser,
 #   ".xhtml": HTMLParser,
 #   ".md": MarkdownParser,
 #   ".markdown": MarkdownParser
}

class FileContentParser:
    def __call__(self, file_path):
        return self.read(file_path)
    
    def read(self, file: str) -> str:
        if not os.path.isfile(file):
            raise FileNotFoundError(f"File not found: {file}")

        _, ext = os.path.splitext(file)
        ext = ext.lower()

        if ext not in SUPPORTED_FILE_TYPES:
            raise ValueError(f"Unsupported file extension: {ext}. Supported types are: {list(SUPPORTED_FILE_TYPES.keys())}")

        parser_class = SUPPORTED_FILE_TYPES[ext]
        parser = parser_class()  # instantiate the parser
        data = parser.read(file)

        return data
    