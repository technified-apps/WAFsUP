"""
ScannerRegistry dynamically load and instantiates scanners.
"""
from pathlib import Path
import yaml
from typing import Dict

from src.scanners.upload_scanner import FileUploadScanner
from src.functions.file_content_parser import FileContentParser
from src.shared.logger import init_logger
from src.scanners.toxicity_scanner import ContentSafetyScanner
from src.scanners.pii_scanner import PIIScanner
from src.scanners.basescanner import Scanner
from src.scanners.regex_scanner import RegexScanner

# Set up logging
logger = init_logger("ScannerRegistry")

SCAN_CONFIG_PATH = "./src/shared/scan_conf.yaml"

SCAN_REGISTRY: Dict[int, type] = {
    1: PIIScanner,
    2: RegexScanner,
    3: ContentSafetyScanner,
    #4: FileUploadScanner 
}
FILE_SCAN_REGISTRY: Dict[int, type] = {
    4: FileUploadScanner 
}

class ScannerRegistry:
    def __init__(self):
        if Path(SCAN_CONFIG_PATH).is_file():
            self.config_path = SCAN_CONFIG_PATH
            logger.info(f"Loading SCANNER configuration from {SCAN_CONFIG_PATH}")
        else:
            logger.error(f"SCANNER configuration file not found at {SCAN_CONFIG_PATH}. Using default settings.")
            raise FileNotFoundError(f"Configuration file {SCAN_CONFIG_PATH} does not exist.")
                
        self.scans: Dict[str, Scanner] = {}
        self.file_scanners: Dict[str, Scanner] = {}
        self.load_from_yaml()

    def load_from_yaml(self):
        try:
            content_parser = FileContentParser()
            yamLdata = content_parser.read(self.config_path)
            
            for data in yamLdata['scanners']:
                #logger.info(f"Processing scanner: {data.get("name")} status: {data.get("active")} entities: {data.get("scan_entities")}")
                if data.get("active") == True: # load only if the policiy is active
                    scan_id = data.get("id")
    
                    if scan_id in SCAN_REGISTRY:
                        self.scans[scan_id]= SCAN_REGISTRY[scan_id](
                                                        scanner_name=data.get("name"),
                                                        scan_action=data.get("action"),
                                                        message=data.get("message"),
                                                        ingress = data.get("ingress"),
                                                        egress = data.get("egress"),
                                                        scan_status=data.get("active"),
                                                        threshold= data.get("threshold"),
                                                        block_score= data.get("block_score"),
                                                        pii_entities= data.get("pii_entities"))
                    elif scan_id in FILE_SCAN_REGISTRY:
                        self.file_scanners[scan_id] = FILE_SCAN_REGISTRY[scan_id](
                                                        scanner_name=data.get("name"),
                                                        scan_action=data.get("action"),
                                                        message=data.get("message"),
                                                        ingress = data.get("ingress"),
                                                        egress = data.get("egress"),
                                                        scan_status=data.get("active"),
                                                        threshold= data.get("threshold"),
                                                        block_score= data.get("block_score"),
                                                        pii_entities= data.get("pii_entities"))    
                
                    #logger.info(f"prompt scanners processed= {self.scans}")
                    #logger.info(f"file scanners processed= {self.file_scanners}")

        except Exception as e:
            logger.error(f"Failed to load YAML file: {e}")
            return []
    
    def get_file_scanners(self):
        return self.file_scanners
    
    def get_scanners(self):
        return self.scans


