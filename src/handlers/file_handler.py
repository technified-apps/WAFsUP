from copyreg import pickle
import json
import os
from pathlib import Path
from typing import Dict
import charset_normalizer
#import docx
import markdown
import PyPDF2
import yaml
from bs4 import BeautifulSoup
#from pylatexenc.latex2text import LatexNodes2Text
import mimetypes
from PyPDF2 import PdfReader
import docx2txt
import csv
#import pptx
import pandas as pd
from src.shared.logger import init_logger

# Set up logging
logger = init_logger("FileHandler")

class ParserStrategy:
    def read(self, file_path: str) -> str:
        raise NotImplementedError
    

# Basic text file reading
class TXTParser(ParserStrategy):
    def read(self, file_path: str) -> str:
        try:
            charset_match = charset_normalizer.from_path(file_path).best()
            if not charset_match:
                raise ValueError("Failed to detect encoding")
            logger.debug(f"Reading '{file_path}' with encoding '{charset_match.encoding}'")
            return str(charset_match)
        except Exception as e:
            logger.error(f"Failed to read TXT file '{file_path}': {e}")
            raise


# Reading text from binary file using pdf parser
class PDFParser(ParserStrategy):
    def read(self, file_path: str) -> str:
        try:
            parser = PyPDF2.PdfReader(file_path)
            text = ""
            for page in parser.pages:
                extracted = page.extract_text()
                if extracted:
                    text += extracted
            return text
        except Exception as e:
            logger.error(f"Failed to read PDF file '{file_path}': {e}")
            raise


# Reading as dictionary and returning string format
class JSONParser(ParserStrategy):
    def read(self, file_path: str) -> str:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return str(data)
        except Exception as e:
            logger.error(f"Failed to read JSON file '{file_path}': {e}")
            raise


class XMLParser(ParserStrategy):
    def read(self, file_path: str) -> str:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                soup = BeautifulSoup(f, "xml")
            return soup.get_text()
        except Exception as e:
            logger.error(f"Failed to read XML file '{file_path}': {e}")
            raise


# Reading as dictionary and returning string format
class PICKLEParser(ParserStrategy):
    def read(self, file_path: str) -> str:
        try:
            with open(file_path, "rb") as f:
                data = pickle.load(f)
            return data
        except Exception as e:
            logger.error(f"Failed to read Pickle file '{file_path}': {e}")
            raise


# Reading as dictionary and returning string format
class YAMLParser(ParserStrategy):
    def read(self, file_path: str) -> str:
        #logger.info(f"Loading YAMLParser:*** {file_path}")
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return data
        except Exception as e:
            logger.error(f"Failed to read YAML file '{file_path}': {e}")
            raise


class HTMLParser(ParserStrategy):
    def read(self, file_path: str) -> str:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                soup = BeautifulSoup(f, "html.parser")
            return soup.get_text()
        except Exception as e:
            logger.error(f"Failed to read HTML file '{file_path}': {e}")
            raise


class MarkdownParser(ParserStrategy):
    def read(self, file_path: str) -> str:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                html = markdown.markdown(f.read())
            text = "".join(BeautifulSoup(html, "html.parser").findAll(string=True))
            return text
        except Exception as e:
            logger.error(f"Failed to read Markdown file '{file_path}': {e}")
            raise


class ParquetParser(ParserStrategy):
    def read(self, file_path: str) -> str:
        try:
            df = pd.read_parquet(file_path)
            return df.head(20).to_string(index=False)
        except Exception as e:
            logger.error(f"Failed to read Parquet file '{file_path}': {e}")
            raise

def is_file_binary_fn(file_path: str):
    """Given a file path load all its content and checks if the null bytes is present

    Args:
        file_path (_type_): _description_

    Returns:
        bool: is_binary
    """
    with open(file_path, "rb") as f:
        file_data = f.read()
    if b"\x00" in file_data:
        return True
    return False



"""# Reading text from binary file using docs parser
class DOCXParser(ParserStrategy):
    def read(self, file_path: str) -> str:
        doc_file = docx.Document(file_path)
        text = ""
        for para in doc_file.paragraphs:
            text += para.text
        return text

# Reading text from PowerPoint file using docs parser
class DOCXParser(ParserStrategy):
    def read(self, file_path: str) -> str:
        # Extract text from pptx using python-pptx
        extracted_text = ""
        presentation = pptx.Presentation(file_path)
        for slide in presentation.slides:
            for shape in slide.shapes:
                if shape.has_text_frame:
                    for paragraph in shape.text_frame.paragraphs:
                        for run in paragraph.runs:
                            extracted_text += run.text + " "
                    extracted_text += "\n"
        return extracted_text
"""
