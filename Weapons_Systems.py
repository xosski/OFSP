from PySide6.QtWidgets import QApplication, QWidget, QMainWindow, QVBoxLayout, QLabel, QPushButton, QTabWidget, QTextEdit, QListWidget, QTreeWidget, QTreeWidgetItem, QProgressBar, QCheckBox, QSlider, QFileDialog
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction
import os, re, math, hashlib, logging, shutil
from pathlib import Path
import ctypes
from typing import List
from YaraRuleManager import YaraRuleManager

class MalwareScanner:
    def __init__(self):
        self.signature_db = set()
        self.quarantine_dir = Path("quarantine")

        self.yara_manager = YaraRuleManager()
        self.logger = self._setup_logging()
        self.dos_header = self.Image_Dos_Header()
        self.yara_manager.combined_rules = self.yara_manager.compile_combined_rules()
        self.executable_found = False

    def _setup_logging(self) -> logging.Logger:
        logging.basicConfig(
            filename='scanner.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        return logging.getLogger('MalwareScanner')

    class Image_Dos_Header(ctypes.Structure):
        _fields_ = [
            ("e_magic", ctypes.c_ushort),
            ("e_cblp", ctypes.c_ushort),
            ("e_cp", ctypes.c_ushort),
            ("e_crlc", ctypes.c_ushort),
            ("e_cparhdr", ctypes.c_ushort),
            ("e_minalloc", ctypes.c_ushort),
            ("e_maxalloc", ctypes.c_ushort),
            ("e_ss", ctypes.c_ushort),
            ("e_sp", ctypes.c_ushort),
            ("e_csum", ctypes.c_ushort),
            ("e_ip", ctypes.c_ushort),
            ("e_cs", ctypes.c_ushort),
            ("e_lfarlc", ctypes.c_ushort),
            ("e_ovno", ctypes.c_ushort),
            ("e_res", ctypes.c_ushort * 4),
            ("e_oemid", ctypes.c_ushort),
            ("e_oeminfo", ctypes.c_ushort),
            ("e_res2", ctypes.c_ushort * 10),
            ("e_lfanew", ctypes.c_long)
        ]

    def load_signatures(self, signature_file=None):
        if signature_file is None:
            logging.warning("No signature file provided, skipping signature loading")
            self.signature_db = set()
            return False

        if not os.path.exists(signature_file):
            logging.warning(f"Signature file not found: {signature_file}")
            self.signature_db = set()
            return False

        with open(signature_file, 'r') as f:
            self.signature_db = set(line.strip() for line in f)
        return True

    def detect_shellcode(self, memory_content, base_address=0):
        shellcode_indicators = {
            'found': False,
            'patterns': [],
            'characteristics': [],
            'risk_level': 0,
            'location': hex(base_address)
        }

        PATTERNS = {
            'egg_hunter': rb'\x66\x81\xca\xff\x0f\x42\x52\x6a\x02',
            'api_hashing': rb'\x74\x0c\x75\x14\xb8[\x00-\xff]{4}',
            'stack_alignment': rb'\x83\xec[\x00-\xff]\x83\xe4\xf0',
            'syscall_stub': rb'\x0f\x34|\x0f\x05|\xcd\x80',
            'null_free': rb'[\x01-\xff]{20,}',
            'function_prolog': rb'\x55\x8b\xec|\x48\x89\x5c',
            'register_setup': rb'\x33\xc0|\x31\xc0|\x48\x31'
        }

        for name, pattern in PATTERNS.items():
            matches = re.finditer(pattern, memory_content)
            for match in matches:
                shellcode_indicators['patterns'].append({
                    'type': name,
                    'offset': match.start(),
                    'bytes': memory_content[match.start():match.start()+16].hex()
                })
                shellcode_indicators['risk_level'] += 1

        characteristics = []

        if b'\xff\x34\x24' in memory_content:
            characteristics.append('position_independent')
            shellcode_indicators['risk_level'] += 2

        entropy = self._calculate_entropy(memory_content)
        if entropy > 7.0:
            characteristics.append('high_entropy')
            shellcode_indicators['risk_level'] += 2

        if len(memory_content) < 4096:
            characteristics.append('small_code_block')
            shellcode_indicators['risk_level'] += 1

        if b'\x89\xe5' in memory_content or b'\x8b\xe5' in memory_content:
            characteristics.append('stack_manipulation')
            shellcode_indicators['risk_level'] += 1

        shellcode_indicators['characteristics'] = characteristics
        shellcode_indicators['found'] = shellcode_indicators['risk_level'] > 2

        return shellcode_indicators

    def _calculate_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x))/len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def calculate_file_hash(self, filepath):
        if not filepath or not os.path.exists(filepath):
            return None

        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logging.debug(f"Hash calculation skipped for {filepath}: {str(e)}")
            return None

    def scan_file(self, filepath: str) -> bool:
        self.compiled_rules = self.yara_manager.compile_combined_rules()
        try:
            matches = self.compiled_rules.match(filepath, timeout=60)
            return matches
        except Exception as e:
            self.logger.error(f"Error scanning file {filepath}: {str(e)}")
            return []

    def scan_directory(self, directory: str) -> List[str]:
        infected_files = []
        for root, _, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                if self.scan_file(full_path):
                    infected_files.append(full_path)
                    logging.warning(f"Malware detected: {full_path}")
        return infected_files

    def quarantine_file(self, filepath: str) -> bool:
        try:
            self.quarantine_dir.mkdir(exist_ok=True)
            filename = Path(filepath).name
            quarantine_path = self.quarantine_dir / f"{filename}.quarantine"
            shutil.move(filepath, quarantine_path)
            logging.info(f"Quarantined {filepath} to {quarantine_path}")
            return True
        except Exception as e:
            logging.error(f"Quarantine failed for {filepath}: {str(e)}")
            return False

    def remove_file(self, filepath: str) -> bool:
        try:
            os.remove(filepath)
            logging.info(f"Removed infected file: {filepath}")
            return True
        except Exception as e:
            logging.error(f"Removal failed for {filepath}: {str(e)}")
            return False
