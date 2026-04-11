"""
Complete OrbitalStationUI - Full functionality from original Unnamed.py
This provides the complete PySide6-based GUI with all scanning, memory analysis,
process monitoring, YARA rule management, and protection features.
"""

import sys
import os
import ctypes
import logging
import traceback
import threading
import time
import importlib
from datetime import datetime
import psutil
from pathlib import Path
import PySide6
# PySide6 imports
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTabWidget, QTextEdit, QFileDialog, QListWidget, QLineEdit, QMessageBox,
    QProgressBar, QTreeWidget, QTreeWidgetItem, QHeaderView, QSplitter, QCheckBox, QSpinBox,
    QGroupBox, QGridLayout, QFrame, QTableWidget, QTableWidgetItem, QComboBox, QInputDialog, QDialog
)

from PySide6.QtGui import QFont, QColor, QTextCharFormat, QTextCursor
from PySide6.QtCore import Qt, QTimer, QThread, Signal

# Import shared constants and backend modules
from shared_constants import *

# Import backend modules with error handling
try:
    import YaraRuleManager
except ImportError:
    YaraRuleManager = None

try:
    import Memory
except ImportError:
    Memory = None

try:
    import Weapons_Systems as weapons
except ImportError:
    weapons = None

try:
    import ShellCodeMagic
except ImportError:
    ShellCodeMagic = None

def _load_hades_ai_module():
    """Load HadesAI, preferring local HAdes workspace when present."""
    hades_workspace = Path(__file__).resolve().parent / "HAdes"
    root_module_path = Path(__file__).resolve().parent

    if hades_workspace.exists():
        hades_path = str(hades_workspace)
        if hades_path not in sys.path:
            sys.path.insert(0, hades_path)
        try:
            return importlib.import_module("HadesAI")
        except Exception:
            # Fall back to root-level module if HAdes import fails
            sys.modules.pop("HadesAI", None)
            if hades_path in sys.path:
                sys.path.remove(hades_path)

    root_path = str(root_module_path)
    if root_path not in sys.path:
        sys.path.insert(0, root_path)

    try:
        return importlib.import_module("HadesAI")
    except Exception:
        return None


HadesAI = _load_hades_ai_module()

def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logging.error(f"Error checking admin status: {str(e)}")
        return False
class ScanWorker(QThread):
    """Worker thread for running scans"""
    progress_updated = Signal(int, str)
    scan_completed = Signal(list)
    detection_found = Signal(dict)
    
    def __init__(self, scan_type, parent_ui):
        super().__init__()
        self.scan_type = scan_type
        self.parent_ui = parent_ui
        self.should_stop = False
        
    def run(self):
        """Run the scan in background"""
        try:
            if self.scan_type == "quick":
                self._run_quick_scan()
            elif self.scan_type == "deep":
                self._run_deep_scan()
        except Exception as e:
            self.progress_updated.emit(0, f"Scan error: {str(e)}")
            
    def stop(self):
        """Stop the scan"""
        self.should_stop = True
        
    def _run_quick_scan(self):
        """Quick scan of running processes"""
        try:
            processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline']))
            total = len(processes)
            
            for i, proc in enumerate(processes):
                if self.should_stop:
                    break
                    
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', 'Unknown')
                    if not proc_name or proc_name.strip() == '':
                        proc_name = 'Unknown'
                    proc_pid = proc_info.get('pid', 0)
                    
                    self.progress_updated.emit(
                        int((i / total) * 100),
                        f"Scanning: {proc_name} (PID: {proc_pid})"
                    )
                    
                    # Simple process analysis
                    if self._analyze_process(proc_info):
                        detection = {
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'type': 'Process',
                            'name': proc_name,
                            'pid': proc_pid,
                            'severity': 'Medium',
                            'description': 'Suspicious process detected'
                        }
                        self.detection_found.emit(detection)
                        
                    # Quick memory check for suspicious processes
                    if proc_name.lower() in ['cmd.exe', 'powershell.exe', 'rundll32.exe']:
                        self._analyze_process_memory(proc_pid)
                        
                    time.sleep(0.01)  # Small delay to prevent UI freezing
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            self.progress_updated.emit(100, "Quick scan completed")
            self.scan_completed.emit([])
            
        except Exception as e:
            self.progress_updated.emit(0, f"Quick scan error: {str(e)}")
            
    def _run_deep_scan(self):
        """Deep scan with memory analysis"""
        try:
            processes = list(psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'memory_info']))
            total = len(processes)
            
            for i, proc in enumerate(processes):
                if self.should_stop:
                    break
                    
                try:
                    proc_info = proc.info
                    proc_name = proc_info.get('name', 'Unknown')
                    if not proc_name or proc_name.strip() == '':
                        proc_name = 'Unknown'
                    proc_pid = proc_info.get('pid', 0)
                    
                    self.progress_updated.emit(
                        int((i / total) * 100),
                        f"Deep scanning: {proc_name} (PID: {proc_pid})"
                    )
                    
                    # Analyze process and memory
                    if self._analyze_process(proc_info):
                        detection = {
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'type': 'Process',
                            'name': proc_name,
                            'pid': proc_pid,
                            'severity': 'High',
                            'description': 'Suspicious process with memory anomalies'
                        }
                        self.detection_found.emit(detection)
                        
                    # Memory analysis if available
                    if self.parent_ui.memory_scanner:
                        self._analyze_process_memory(proc_pid)
                        
                    time.sleep(0.02)  # Slightly longer delay for deep scan
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            self.progress_updated.emit(100, "Deep scan completed")
            self.scan_completed.emit([])
            
        except Exception as e:
            self.progress_updated.emit(0, f"Deep scan error: {str(e)}")
            
    def _analyze_process(self, proc_info):
        """Analyze process for suspicious characteristics"""
        # Simple heuristics for demo
        name = proc_info.get('name', '').lower()
        
        # Suspicious patterns
        suspicious_names = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
        if name in suspicious_names:
            return True
            
        # Check for suspicious paths
        exe_path = proc_info.get('exe', '')
        if exe_path and ('temp' in exe_path.lower() or 'tmp' in exe_path.lower()):
            return True
            
        return False
        
    def _analyze_process_memory(self, pid):
        """Analyze process memory for shellcode"""
        try:
            from Memory import MemoryScanner
            # Use shared memory scanner if available
            if hasattr(self.parent_ui, 'memory_scanner') and self.parent_ui.memory_scanner:
                memory_scanner = self.parent_ui.memory_scanner
            else:
                memory_scanner = MemoryScanner()
            
            # Perform enhanced memory scanning for shellcode
            detections = memory_scanner.scan_process_memory_enhanced(pid)
            
            for detection in detections:
                # Format detection for the UI
                formatted_detection = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'type': f"Shellcode - {detection.get('type', 'Unknown')}",
                    'name': detection.get('process', 'Unknown'),
                    'pid': pid,
                    'severity': 'High',
                    'description': f"Shellcode detected: {detection.get('details', 'No details')}",
                    'address': detection.get('address', 0),
                    'size': detection.get('size', 0),
                    'confidence': detection.get('confidence', 'Unknown'),
                    'risk': detection.get('risk', 'High'),
                    'shellcode': detection.get('shellcode', b''),
                    'patterns': detection.get('patterns', [])
                }
                self.detection_found.emit(formatted_detection)
                
        except Exception as e:
            # Don't emit error for memory analysis failures as they're common
            pass

class FilesystemScanWorker(QThread):
    """Worker thread for filesystem scanning operations"""
    progress_updated = Signal(int, str, int, str)  # progress, current_file, files_scanned, scan_speed
    threat_found = Signal(dict)  # threat_info
    scan_completed = Signal()
    
    def __init__(self, scan_type, paths, parent_ui):
        super().__init__()
        self.scan_type = scan_type
        self.paths = paths
        self.parent_ui = parent_ui
        self.should_stop = False
        self.files_scanned = 0
        self.start_time = None
        
    def stop(self):
        """Stop the scanning process"""
        self.should_stop = True
        
    def run(self):
        """Run the filesystem scan"""
        import os
        import time
        self.start_time = time.time()
        self.files_scanned = 0
        
        try:
            # Get file extensions to scan based on options
            scan_extensions = self._get_scan_extensions()
            
            # Collect all files to scan
            all_files = []
            for path in self.paths:
                if self.should_stop:
                    break
                
                if os.path.isdir(path):
                    for root, dirs, files in os.walk(path):
                        if self.should_stop:
                            break
                        
                        # Skip system directories that may cause issues
                        dirs[:] = [d for d in dirs if not d.startswith('$') and d.lower() not in ['system volume information', 'recycler']]
                        
                        for file in files:
                            if self.should_stop:
                                break
                                
                            file_path = os.path.join(root, file)
                            
                            # Check if file extension should be scanned
                            if scan_extensions is None or any(file.lower().endswith(ext) for ext in scan_extensions):
                                all_files.append(file_path)
            
            total_files = len(all_files)
            
            # Scan each file
            for i, file_path in enumerate(all_files):
                if self.should_stop:
                    break
                
                try:
                    # Update progress
                    progress = int((i / total_files) * 100) if total_files > 0 else 0
                    elapsed_time = time.time() - self.start_time
                    scan_speed = int(self.files_scanned / elapsed_time) if elapsed_time > 0 else 0
                    
                    self.progress_updated.emit(
                        progress,
                        os.path.basename(file_path),
                        self.files_scanned,
                        str(scan_speed)
                    )
                    
                    # Scan the file
                    threat_info = self._scan_file(file_path)
                    if threat_info:
                        self.threat_found.emit(threat_info)
                    
                    self.files_scanned += 1
                    
                    # Small delay to prevent overwhelming the system
                    time.sleep(0.001)
                    
                except Exception as e:
                    # Skip files that cause errors (access denied, etc.)
                    continue
            
            self.scan_completed.emit()
            
        except Exception as e:
            print(f"Filesystem scan error: {e}")
            self.scan_completed.emit()
    
    def _get_scan_extensions(self):
        """Get file extensions to scan based on UI options"""
        extensions = []
        
        if self.parent_ui.scan_all_files.isChecked():
            return None  # Scan all files
        
        if self.parent_ui.scan_executables.isChecked():
            extensions.extend(['.exe', '.dll', '.scr', '.com', '.bat', '.cmd', '.pif'])
        
        if self.parent_ui.scan_scripts.isChecked():
            extensions.extend(['.ps1', '.vbs', '.js', '.wsf', '.wsh', '.py', '.pl'])
        
        if self.parent_ui.scan_documents.isChecked():
            extensions.extend(['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'])
        
        return extensions if extensions else ['.exe', '.dll']  # Default to executables
    
    def _scan_file(self, file_path):
        """Scan a single file for threats with whitelist protection"""
        try:
            # Use YARA rules with whitelist checking if available
            if hasattr(self.parent_ui, 'yara_manager') and self.parent_ui.yara_manager:
                # Use the new whitelist-aware scanning method
                matches = self.parent_ui.yara_manager.scan_with_whitelist_check(file_path)
                if matches:
                    # File matched YARA rules and is not whitelisted - it's a threat
                    match = matches[0]
                    
                    # Extract detailed information if available
                    severity = 'High'
                    detailed_description = f"Matched rule: {match.rule}"
                    
                    if hasattr(match, 'detailed_info'):
                        detailed_info = match.detailed_info
                        severity = detailed_info.get('severity', 'High')
                        techniques = detailed_info.get('technique_indicators', [])
                        pattern_count = len(detailed_info.get('matched_patterns', []))
                        
                        if techniques:
                            detailed_description = f"Techniques: {', '.join(techniques)} | Patterns: {pattern_count}"
                            if detailed_info.get('description'):
                                detailed_description += f" | {detailed_info['description']}"
                    
                    return {
                        'name': match.rule,
                        'path': file_path,
                        'type': 'YARA Detection',
                        'severity': severity,
                        'action': 'Detected',
                        'details': detailed_description,
                        'yara_match': match  # Include the full match object for additional processing
                    }
            
            # Browser deep-clean mode adds browser-specific inspection
            if self.scan_type == 'browser':
                browser_result = self._browser_artifact_analysis(file_path)
                if browser_result:
                    return browser_result

            # Additional heuristic checks if enabled
            if self.parent_ui.heuristic_analysis.isChecked():
                heuristic_result = self._heuristic_analysis(file_path)
                if heuristic_result:
                    return heuristic_result
            
        except Exception as e:
            # Skip files that can't be scanned
            pass
        
        return None

    def _browser_artifact_analysis(self, file_path):
        """Analyze browser artifacts for suspicious extension/cache behavior."""
        lower_path = file_path.lower()
        browser_tokens = ['chrome', 'edge', 'firefox', 'brave', 'opera']
        if not any(token in lower_path for token in browser_tokens):
            return None

        filename = os.path.basename(lower_path)
        ext = os.path.splitext(lower_path)[1]

        # Executables should not normally live under browser profile/cache paths.
        if ext in {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.scr'}:
            return {
                'name': 'Browser Profile Executable Artifact',
                'path': file_path,
                'type': 'Browser Deep Clean',
                'severity': 'High',
                'action': 'Detected',
                'details': 'Executable/script artifact found inside browser profile or cache path'
            }

        inspectable = ext in {'.js', '.mjs', '.json', '.html', '.htm', '.txt'} or filename in {'manifest.json', 'preferences'}
        if not inspectable:
            return None

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(262144).lower()
        except Exception:
            return None

        suspicious_markers = [
            'eval(',
            'new function(',
            'atob(',
            'fromcharcode(',
            'document.cookie',
            'chrome.cookies',
            'webrequestblocking',
            'nativemessaging',
            'proxy',
            'debugger'
        ]
        hits = [marker for marker in suspicious_markers if marker in content]
        if not hits:
            return None

        severity = 'High' if len(hits) >= 3 else 'Medium'
        return {
            'name': 'Suspicious Browser Script/Extension Artifact',
            'path': file_path,
            'type': 'Browser Deep Clean',
            'severity': severity,
            'action': 'Detected',
            'details': f"Suspicious browser markers: {', '.join(hits[:5])}"
        }
    
    def _heuristic_analysis(self, file_path):
        """Perform heuristic analysis on a file"""
        import os
        
        try:
            # Check file size (very large or very small files might be suspicious)
            file_size = os.path.getsize(file_path)
            
            # Check for suspicious file locations
            suspicious_paths = ['temp', 'tmp', 'appdata\\local\\temp', 'windows\\temp']
            file_path_lower = file_path.lower()
            
            for sus_path in suspicious_paths:
                if sus_path in file_path_lower:
                    # File in suspicious location
                    return {
                        'name': 'Suspicious Location',
                        'path': file_path,
                        'type': 'Heuristic',
                        'severity': 'Medium',
                        'action': 'Detected',
                        'details': f"File located in suspicious directory: {sus_path}"
                    }
            
            # Check for executable files with suspicious names
            suspicious_names = ['svchost', 'winlogon', 'explorer', 'system32']
            filename = os.path.basename(file_path).lower()
            
            if any(name in filename for name in suspicious_names) and not file_path_lower.startswith('c:\\windows\\'):
                return {
                    'name': 'Suspicious Name',
                    'path': file_path,
                    'type': 'Heuristic',
                    'severity': 'Medium',
                    'action': 'Detected',
                    'details': f"Executable with system-like name in non-system location"
                }
        
        except Exception as e:
            pass
        
        return None


class BackendInitWorker(QThread):
    """Background worker that performs heavy backend initialization."""
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, initializer):
        super().__init__()
        self._initializer = initializer

    def run(self):
        try:
            state = self._initializer()
            self.completed.emit(state)
        except Exception as e:
            self.failed.emit(str(e))

class OrbitalStationUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Orbital Station: Malware Defense Console")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize GUI variables first (before backend)
        self.scanning = False
        self.monitoring_active = False
        self.total_processes_scanned = 0
        self.threats_found = 0
        self.detections = []
        self.scan_worker = None
        self.auto_quarantine_enabled = True
        self.auto_quarantine_min_severity = 'High'
        self.auto_quarantine_min_confidence = 70
        self.auto_ingested_signatures = set()
        
        # Pre-initialize backend attributes to None
        self.memory_scanner = None
        self.yara_manager = None
        self.rules_loaded = False
        self.compiled_rules = None
        self.shellcode_detector = None
        self.shellcode_tome = None
        self.code_disassembler = None
        self.threat_quarantine = None
        self.malware_scanner = None
        self.backend_init_worker = None
        self.backend_ready = False

        # Initialize a local tome immediately so Ancient Tome tab works on startup,
        # even before async backend initialization finishes.
        if ShellCodeMagic:
            try:
                from ShellCodeMagic import ShellCodeTome
                self.shellcode_tome = ShellCodeTome()
            except Exception:
                self.shellcode_tome = None
        
        # Setup styling and create UI FIRST (so user sees something)
        self._setup_styling()
        self._create_ui()
        
        # Show the window immediately
        self.show()
        QApplication.processEvents()
        
        # Initialize backend asynchronously to avoid freezing UI on startup.
        self._start_backend_initialization()
        
    def _init_backend(self):
        """Initialize all backend components"""
        print("Initializing backend components...")
        
        # Initialize memory scanner FIRST (before YARA manager tries to use it)
        self.memory_scanner = None
        if Memory:
            try:
                self.memory_scanner = Memory.MemoryScanner()
                print("Memory scanner initialized")
            except Exception as e:
                print(f"Memory scanner initialization error: {e}")
                self.memory_scanner = None
        
        # Initialize YARA manager
        if YaraRuleManager:
            try:
                # Use shared YARA manager to avoid recompilation
                if self.memory_scanner and hasattr(self.memory_scanner, 'shared_yara_manager') and self.memory_scanner.shared_yara_manager:
                    self.yara_manager = self.memory_scanner.shared_yara_manager
                else:
                    self.yara_manager = YaraRuleManager.YaraRuleManager()
                # Ensure the rules directory is set before calling methods
                if not hasattr(self.yara_manager, 'rules_dir'):
                    self.yara_manager.rules_dir = Path("yara_rules")
                    os.makedirs(self.yara_manager.rules_dir, exist_ok=True)
                    
                self.yara_manager.create_repo_directories()
                self.yara_manager.fetch_all_rules()
                self.yara_manager.create_missing_rules()
                self.compiled_rules = self.yara_manager.compile_combined_rules()
                self.rules_loaded = self.compiled_rules is not None
                print(f"YARA Manager initialized - Rules loaded: {self.rules_loaded}")
                
                # Share this YARA manager with other components to prevent recompilation
                if Memory and hasattr(Memory, 'MemoryScanner'):
                    try:
                        Memory.MemoryScanner.shared_yara_manager = self.yara_manager
                        print("Shared YaraRuleManager with MemoryScanner")
                    except Exception:
                        pass
                    
                if ShellCodeMagic and hasattr(ShellCodeMagic, 'ShellcodeDetector'):
                    try:
                        ShellCodeMagic.ShellcodeDetector.shared_yara_manager = self.yara_manager
                        print("Shared YaraRuleManager with ShellcodeDetector")
                    except Exception:
                        pass
            except Exception as e:
                print(f"YARA initialization error: {e}")
                self.yara_manager = None
                self.rules_loaded = False
        else:
            self.yara_manager = None
            self.rules_loaded = False
            
        # Initialize shellcode detection components
        if ShellCodeMagic:
            try:
                from ShellCodeMagic import ShellcodeDetector, ShellCodeTome, CodeDisassembler, ThreatQuarantine
                self.shellcode_detector = ShellcodeDetector()
                self.shellcode_tome = ShellCodeTome()
                self.code_disassembler = CodeDisassembler()
                self.threat_quarantine = ThreatQuarantine()
                print("ShellCode Magic components initialized")
            except Exception as e:
                print(f"ShellCode Magic initialization error: {e}")
                self.shellcode_detector = None
                self.shellcode_tome = None
                self.code_disassembler = None
                self.threat_quarantine = None
        else:
            self.shellcode_detector = None
            self.shellcode_tome = None
            self.code_disassembler = None
            self.threat_quarantine = None
            
        # Initialize malware scanner - handle the YaraRuleManager issue
        if weapons:
            try:
                self.malware_scanner = weapons.MalwareScanner()
                print("Malware scanner initialized")
            except Exception as e:
                print(f"Malware scanner initialization error: {e}")
                # Try to initialize without YARA if that's the issue
                self.malware_scanner = None
        else:
            self.malware_scanner = None
            
        # Initialize quarantine directory
        self.quarantine_dir = Path("quarantine")
        self.quarantine_dir.mkdir(exist_ok=True)
        
        # Initialize HadesAI components
        self.hades_kb = None
        self.hades_chat = None
        self.hades_network_monitor = None
        self.hades_cache_scanner = None
        if HadesAI:
            try:
                self.hades_kb = HadesAI.KnowledgeBase()
                self.hades_chat = HadesAI.ChatProcessor(self.hades_kb)
                print("HadesAI components initialized")
            except Exception as e:
                print(f"HadesAI initialization error: {e}")

        # Critical processes that should not be terminated
        self.critical_processes = {
            'explorer.exe', 'svchost.exe', 'lsass.exe',
            'winlogon.exe', 'csrss.exe', 'services.exe',
            'smss.exe', 'wininit.exe', 'System'
        }

    def _collect_backend_state(self):
        """Build backend components in worker thread and return state payload."""
        state = {
            'memory_scanner': None,
            'yara_manager': None,
            'rules_loaded': False,
            'compiled_rules': None,
            'shellcode_detector': None,
            'shellcode_tome': None,
            'code_disassembler': None,
            'threat_quarantine': None,
            'malware_scanner': None,
            'hades_kb': None,
            'hades_chat': None,
            'hades_network_monitor': None,
            'hades_cache_scanner': None,
            'critical_processes': {
                'explorer.exe', 'svchost.exe', 'lsass.exe',
                'winlogon.exe', 'csrss.exe', 'services.exe',
                'smss.exe', 'wininit.exe', 'System'
            }
        }

        if Memory:
            try:
                state['memory_scanner'] = Memory.MemoryScanner()
            except Exception:
                state['memory_scanner'] = None

        if YaraRuleManager:
            try:
                if state['memory_scanner'] and hasattr(state['memory_scanner'], 'shared_yara_manager') and state['memory_scanner'].shared_yara_manager:
                    state['yara_manager'] = state['memory_scanner'].shared_yara_manager
                else:
                    state['yara_manager'] = YaraRuleManager.YaraRuleManager()

                if state['yara_manager']:
                    if not hasattr(state['yara_manager'], 'rules_dir'):
                        state['yara_manager'].rules_dir = Path("yara_rules")
                        os.makedirs(state['yara_manager'].rules_dir, exist_ok=True)

                    state['yara_manager'].create_repo_directories()
                    state['yara_manager'].fetch_all_rules()
                    state['yara_manager'].create_missing_rules()
                    state['compiled_rules'] = state['yara_manager'].compile_combined_rules()
                    state['rules_loaded'] = state['compiled_rules'] is not None

                    if Memory and hasattr(Memory, 'MemoryScanner'):
                        try:
                            Memory.MemoryScanner.shared_yara_manager = state['yara_manager']
                        except Exception:
                            pass

                    if ShellCodeMagic and hasattr(ShellCodeMagic, 'ShellcodeDetector'):
                        try:
                            ShellCodeMagic.ShellcodeDetector.shared_yara_manager = state['yara_manager']
                        except Exception:
                            pass
            except Exception:
                state['yara_manager'] = None
                state['rules_loaded'] = False

        if ShellCodeMagic:
            try:
                from ShellCodeMagic import ShellcodeDetector, ShellCodeTome, CodeDisassembler, ThreatQuarantine
                state['shellcode_detector'] = ShellcodeDetector()
                state['shellcode_tome'] = ShellCodeTome()
                state['code_disassembler'] = CodeDisassembler()
                state['threat_quarantine'] = ThreatQuarantine()
            except Exception:
                pass

        if weapons:
            try:
                state['malware_scanner'] = weapons.MalwareScanner()
            except Exception:
                state['malware_scanner'] = None

        if HadesAI:
            try:
                state['hades_kb'] = HadesAI.KnowledgeBase()
                state['hades_chat'] = HadesAI.ChatProcessor(state['hades_kb'])
            except Exception:
                pass

        return state

    def _start_backend_initialization(self):
        """Run backend initialization in a worker thread to keep UI responsive."""
        self.status_label.setText("Initializing Backend...")
        self.rules_label.setText("Rules: Loading...")
        self.status_message.setText("Loading detection engines in background")

        self.backend_init_worker = BackendInitWorker(self._collect_backend_state)
        self.backend_init_worker.completed.connect(self._on_backend_initialized)
        self.backend_init_worker.failed.connect(self._on_backend_init_failed)
        self.backend_init_worker.start()

    def _on_backend_initialized(self, state):
        """Apply initialized backend state on the UI thread."""
        self.memory_scanner = state.get('memory_scanner')
        self.yara_manager = state.get('yara_manager')
        self.rules_loaded = state.get('rules_loaded', False)
        self.compiled_rules = state.get('compiled_rules')
        self.shellcode_detector = state.get('shellcode_detector')
        self.shellcode_tome = state.get('shellcode_tome')
        self.code_disassembler = state.get('code_disassembler')
        self.threat_quarantine = state.get('threat_quarantine')
        self.malware_scanner = state.get('malware_scanner')
        self.hades_kb = state.get('hades_kb')
        self.hades_chat = state.get('hades_chat')
        self.hades_network_monitor = state.get('hades_network_monitor')
        self.hades_cache_scanner = state.get('hades_cache_scanner')
        self.critical_processes = state.get('critical_processes', set())

        self.quarantine_dir = Path("quarantine")
        self.quarantine_dir.mkdir(exist_ok=True)

        self.backend_ready = True
        self.status_message.setText("Backend initialized")
        self.initial_protection()

        # Refresh Ancient Tome UI with the backend-provided components/data.
        try:
            self._update_tome_wisdom_display()
            self._refresh_tome_tab_if_visible()
        except Exception:
            pass

        self.backend_init_worker = None

    def _on_backend_init_failed(self, error_message):
        """Handle backend initialization failure without freezing the UI."""
        self.backend_ready = False
        self.status_label.setText("Limited Protection")
        self.status_label.setStyleSheet("color: #ffcc00; font-weight: bold; font-size: 14px;")
        self.rules_label.setText("Rules: Failed")
        self.status_message.setText("Backend init failed")
        if hasattr(self, 'log_output'):
            self.log_output.append(f"Backend initialization failed: {error_message}")
        self.backend_init_worker = None

    def closeEvent(self, event):
        """Ensure background workers are stopped before window closes."""
        try:
            if self.scan_worker and self.scan_worker.isRunning():
                self.scan_worker.stop()
                self.scan_worker.wait(3000)
        except Exception:
            pass

        try:
            if self.backend_init_worker and self.backend_init_worker.isRunning():
                self.backend_init_worker.requestInterruption()
                self.backend_init_worker.quit()
                if not self.backend_init_worker.wait(5000):
                    # Last-resort shutdown path to avoid orphaned running thread on app exit.
                    self.backend_init_worker.terminate()
                    self.backend_init_worker.wait(2000)
        except Exception:
            pass

        super().closeEvent(event)

    def _severity_score(self, severity):
        mapping = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return mapping.get(str(severity).lower(), 2)

    def _normalize_confidence(self, value):
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            try:
                return max(0, min(100, int(value)))
            except Exception:
                return 0

        text = str(value).strip().lower().replace('%', '')
        if text in ('high', 'strong'):
            return 85
        if text in ('medium', 'moderate'):
            return 60
        if text in ('low', 'weak'):
            return 30
        try:
            return max(0, min(100, int(float(text))))
        except Exception:
            return 0

    def _resolve_actionable_file_path(self, table, row, path_column=1):
        """Return a valid filesystem path from a table row, or None if not actionable."""
        path_item = table.item(row, path_column)
        if not path_item:
            return None

        file_path = str(path_item.text()).strip()
        if not file_path:
            return None

        file_path_lower = file_path.lower()
        if file_path_lower in ('n/a', 'na'):
            return None
        if file_path_lower.startswith('pid:') or file_path_lower.startswith('memory:'):
            return None

        return file_path

    def _is_scan_results_tab_active(self):
        """Return True when the dedicated Scan Results tab is active."""
        return hasattr(self, 'scan_results_tab') and self.tabs.currentWidget() is self.scan_results_tab

    def _is_filesystem_tab_active(self):
        """Return True when the System Scanner tab is active."""
        return hasattr(self, 'filesystem_tab') and self.tabs.currentWidget() is self.filesystem_tab

    def _is_system_file_protected(self, file_path):
        """Safely check whether a file is protected by policy."""
        try:
            yara_manager = getattr(self, 'yara_manager', None)
            if yara_manager and hasattr(yara_manager, 'is_system_file_protected'):
                return bool(yara_manager.is_system_file_protected(file_path))
        except Exception as e:
            self._append_log(f"⚠️ Protection check failed for {file_path}: {str(e)}")
        return False

    def _append_log(self, message):
        """Append to UI log when available, otherwise fallback to stdout during early startup."""
        if hasattr(self, 'log_output') and self.log_output is not None:
            self.log_output.append(message)
        else:
            try:
                print(message)
            except UnicodeEncodeError:
                safe_message = str(message).encode('ascii', errors='replace').decode('ascii')
                print(safe_message)

    def _should_auto_quarantine(self, detection):
        if not self.auto_quarantine_enabled:
            return False

        # Browser cache findings should be contained immediately when a file artifact exists.
        if detection.get('force_auto_quarantine'):
            return True

        severity_ok = self._severity_score(detection.get('severity', 'Medium')) >= self._severity_score(self.auto_quarantine_min_severity)
        confidence_ok = self._normalize_confidence(detection.get('confidence')) >= self.auto_quarantine_min_confidence
        detection_type = str(detection.get('type', '')).lower()
        is_critical_type = any(token in detection_type for token in ['shellcode', 'injection', 'hollowing', 'rwx'])

        return severity_ok or confidence_ok or is_critical_type

    def _ingest_detection_into_knowledge(self, detection):
        """Persist detection into ShellCode Tome and Hades knowledge base."""
        try:
            signature = "|".join([
                str(detection.get('type', '')),
                str(detection.get('name', detection.get('process', ''))),
                str(detection.get('path', '')),
                str(detection.get('address', '')),
                str(detection.get('description', detection.get('details', '')))
            ])
            detection_sig = hash(signature)
            if detection_sig in self.auto_ingested_signatures:
                return
            self.auto_ingested_signatures.add(detection_sig)

            if hasattr(self, 'shellcode_tome') and self.shellcode_tome:
                category = self._classify_detection_type(str(detection.get('type', 'Unknown'))) if hasattr(self, '_classify_detection_type') else 'unknown_magic'
                tome_entry = {
                    'type': detection.get('type', 'Unknown'),
                    'spell_category': category,
                    'process': detection.get('name', detection.get('process', 'Unknown')),
                    'timestamp': detection.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
                    'confidence': self._normalize_confidence(detection.get('confidence')),
                    'location': detection.get('path', f"Memory: {detection.get('address', 'N/A')}"),
                    'details': detection.get('description', detection.get('details', 'No details provided')),
                    'entropy': detection.get('entropy', 0.0),
                    'disassembly': detection.get('disassembly', ''),
                    'risk': detection.get('severity', detection.get('risk', 'Medium')),
                    'size': detection.get('size', 0),
                    'shellcode': detection.get('shellcode', b''),
                    'patterns': detection.get('patterns', []),
                    'commands': detection.get('commands', []),
                    'findings': detection.get('findings', []),
                    'metadata': detection
                }
                self.shellcode_tome.add_entry(category, tome_entry)
                self._refresh_tome_tab_if_visible()

            if self.hades_kb:
                class _Finding:
                    pass

                finding = _Finding()
                finding.path = str(detection.get('path', detection.get('name', 'N/A')))
                finding.threat_type = str(detection.get('type', 'Unknown'))
                finding.pattern = str(detection.get('description', detection.get('details', 'Detection matched policy')))
                finding.severity = str(detection.get('severity', 'Medium')).upper()
                finding.code_snippet = str(detection.get('code', detection.get('code_snippet', '')))
                finding.browser = str(detection.get('browser', 'OFSP'))
                finding.context = str(detection.get('details', detection.get('description', '')))

                self.hades_kb.store_threat_finding(finding)
                self.hades_kb.store_learned_exploit(
                    source_url=str(detection.get('path', 'ofsp://local-detection')),
                    exploit_type=str(detection.get('type', 'Unknown')),
                    code=str(detection.get('code', detection.get('code_snippet', detection.get('description', '')))),
                    description=str(detection.get('description', detection.get('details', 'Auto-ingested from OFSP detection pipeline')))
                )
        except Exception as e:
            if hasattr(self, 'log_output'):
                self.log_output.append(f"⚠️ Knowledge ingestion warning: {str(e)}")

    def _refresh_tome_tab_if_visible(self):
        """Refresh Ancient Tome table only when the tab is active."""
        try:
            if not hasattr(self, 'tabs') or not hasattr(self, 'shellcode_table'):
                return

            current_tab = self.tabs.currentWidget()
            for i in range(self.tabs.count()):
                if self.tabs.tabText(i) == "🧙‍♂️ Ancient Tome" and self.tabs.widget(i) is current_tab:
                    self._browse_ancient_tome()
                    break
        except Exception as e:
            if hasattr(self, 'log_output'):
                self.log_output.append(f"⚠️ Tome refresh warning: {str(e)}")

    def _attempt_auto_quarantine(self, detection):
        """Automatically quarantine high-risk detections when safe to do so."""
        if not self._should_auto_quarantine(detection):
            return

        file_path = detection.get('path')
        if not file_path or str(file_path).strip() in ('', 'N/A'):
            return

        file_path = str(file_path)
        if not os.path.exists(file_path):
            return

        try:
            if self.yara_manager and hasattr(self.yara_manager, 'is_system_file_protected'):
                if self.yara_manager.is_system_file_protected(file_path):
                    self._append_log(f"🛡️ Auto-quarantine skipped protected file: {file_path}")
                    return
        except Exception:
            pass

        if self._quarantine_file(file_path):
            detection['status'] = 'Auto-Quarantined'
            self._append_log(f"🔒 Auto-quarantined detection artifact: {file_path}")
        
    def _setup_styling(self):
        """Setup the dark cyberpunk styling"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0a0a0a;
                color: #00ffcc;
            }
            QLabel {
                color: #c0c0c0;
                font-size: 12px;
            }
            QPushButton {
                background-color: #1a1a1a;
                color: #00ffcc;
                border: 1px solid #00ffcc;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #00ffcc;
                color: #000;
            }
            QPushButton:pressed {
                background-color: #008b8b;
            }
            QPushButton:disabled {
                background-color: #2a2a2a;
                color: #666;
                border-color: #666;
            }
            QLineEdit {
                background-color: #111;
                color: #0f0;
                border: 1px solid #444;
                padding: 6px;
                border-radius: 3px;
            }
            QTextEdit {
                background-color: #050505;
                color: #0f0;
                border: 1px solid #333;
                font-family: 'Consolas', monospace;
            }
            QTabWidget::pane {
                border: 1px solid #333;
                background-color: #111;
            }
            QTabBar::tab {
                background: #1a1a1a;
                color: #00ffcc;
                padding: 8px 16px;
                margin: 2px;
                border-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #2a2a2a;
                font-weight: bold;
            }
            QProgressBar {
                border: 1px solid #444;
                border-radius: 5px;
                text-align: center;
                color: #00ffcc;
                background-color: #1a1a1a;
            }
            QProgressBar::chunk {
                background-color: #00ffcc;
                border-radius: 4px;
            }
            QTreeWidget, QTableWidget {
                background-color: #0a0a0a;
                color: #c0c0c0;
                border: 1px solid #444;
                alternate-background-color: #1a1a1a;
                gridline-color: #333;
            }
            QTreeWidget::item:selected, QTableWidget::item:selected {
                background-color: #00ffcc;
                color: #000;
            }
            QHeaderView::section {
                background-color: #2a2a2a;
                color: #00ffcc;
                padding: 6px;
                border: 1px solid #444;
                font-weight: bold;
            }
            QGroupBox {
                color: #00ffcc;
                border: 1px solid #444;
                border-radius: 4px;
                margin: 5px 0px;
                padding-top: 10px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)

        font = QFont("Consolas", 10)
        self.setFont(font)
        
    def _create_ui(self):
        """Create the complete user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Status bar
        self._create_status_bar(main_layout)
        
        # Control panel
        self._create_control_panel(main_layout)
        
        # Tab widget for main content
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create all tabs with full functionality
        self._create_scanner_tab()
        self._create_filesystem_tab()
        self._create_memory_tab()
        self._create_shellcode_detection_tab()
        self._create_process_tab()
        self._create_detections_tab()
        self._create_scan_results_tab()
        self._create_scan_status_tab()
        self._create_yara_tab()
        self._create_quarantine_tab()
        self._create_logs_tab()
        self._create_hades_ai_tab()
        self._create_donation_tab()
    
    def _create_hades_ai_tab(self):
        """Create HadesAI integration tab for AI-powered threat analysis"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Header
        header_frame = QGroupBox("🔥 HadesAI - Self-Learning Threat Intelligence")
        header_frame.setStyleSheet("""
            QGroupBox {
                font-size: 16px;
                font-weight: bold;
                color: #ff6600;
                border: 2px solid #ff6600;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
            }
        """)
        header_layout = QHBoxLayout(header_frame)
        
        # Status indicators
        self.hades_status_label = QLabel("Status: " + ("🟢 Active" if HadesAI else "🔴 Not Available"))
        self.hades_status_label.setStyleSheet("color: #00ff88; font-size: 14px;")
        header_layout.addWidget(self.hades_status_label)
        
        self.hades_patterns_label = QLabel("Patterns: 0")
        header_layout.addWidget(self.hades_patterns_label)
        
        self.hades_exploits_label = QLabel("Learned Exploits: 0")
        header_layout.addWidget(self.hades_exploits_label)
        
        header_layout.addStretch()
        
        # Refresh stats button
        refresh_btn = QPushButton("🔄 Refresh Stats")
        refresh_btn.clicked.connect(self._refresh_hades_stats)
        header_layout.addWidget(refresh_btn)
        
        layout.addWidget(header_frame)
        
        # Main content splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side - Chat interface
        chat_widget = QWidget()
        chat_layout = QVBoxLayout(chat_widget)
        
        chat_label = QLabel("💬 AI Chat - Ask HADES anything about security")
        chat_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #ff6600;")
        chat_layout.addWidget(chat_label)
        
        self.hades_chat_output = QTextEdit()
        self.hades_chat_output.setReadOnly(True)
        self.hades_chat_output.setPlaceholderText("Chat with HADES AI...\n\nTry:\n• 'help' - Show commands\n• 'scan https://example.com' - Scan a target\n• 'show findings' - View threat findings\n• 'scan browser cache' - Scan cached files")
        self.hades_chat_output.setStyleSheet("background-color: #0d0d0d; color: #00ff88; font-family: Consolas;")
        chat_layout.addWidget(self.hades_chat_output)
        
        # Chat input
        input_layout = QHBoxLayout()
        self.hades_chat_input = QLineEdit()
        self.hades_chat_input.setPlaceholderText("Type a command or question...")
        self.hades_chat_input.returnPressed.connect(self._send_hades_chat)
        self.hades_chat_input.setStyleSheet("padding: 8px; font-size: 14px;")
        input_layout.addWidget(self.hades_chat_input)
        
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self._send_hades_chat)
        send_btn.setStyleSheet("background-color: #ff6600; color: white; font-weight: bold; padding: 8px 20px;")
        input_layout.addWidget(send_btn)
        
        chat_layout.addLayout(input_layout)
        
        splitter.addWidget(chat_widget)
        
        # Right side - Actions and findings
        actions_widget = QWidget()
        actions_layout = QVBoxLayout(actions_widget)
        
        # Quick actions
        actions_frame = QGroupBox("⚡ Quick Actions")
        actions_grid = QGridLayout(actions_frame)
        
        cache_scan_btn = QPushButton("🔍 Scan Browser Cache")
        cache_scan_btn.clicked.connect(self._hades_scan_cache)
        actions_grid.addWidget(cache_scan_btn, 0, 0)
        
        network_mon_btn = QPushButton("🌐 Start Network Monitor")
        network_mon_btn.clicked.connect(self._hades_start_network_monitor)
        actions_grid.addWidget(network_mon_btn, 0, 1)
        
        show_exploits_btn = QPushButton("📚 Show Learned Exploits")
        show_exploits_btn.clicked.connect(self._hades_show_exploits)
        actions_grid.addWidget(show_exploits_btn, 1, 0)
        
        show_findings_btn = QPushButton("🎯 Show Threat Findings")
        show_findings_btn.clicked.connect(self._hades_show_findings)
        actions_grid.addWidget(show_findings_btn, 1, 1)
        
        actions_layout.addWidget(actions_frame)
        
        # Recent findings table
        findings_label = QLabel("📋 Recent Threat Findings")
        findings_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        actions_layout.addWidget(findings_label)
        
        self.hades_findings_table = QTableWidget()
        self.hades_findings_table.setColumnCount(5)
        self.hades_findings_table.setHorizontalHeaderLabels(["Type", "Path", "Severity", "Browser", "Detected"])
        self.hades_findings_table.horizontalHeader().setStretchLastSection(True)
        self.hades_findings_table.setAlternatingRowColors(True)
        actions_layout.addWidget(self.hades_findings_table)
        
        splitter.addWidget(actions_widget)
        splitter.setSizes([500, 400])
        
        layout.addWidget(splitter)
        
        self.tabs.addTab(widget, "🔥 HadesAI")
        
        # Initial stats refresh
        if HadesAI:
            QTimer.singleShot(1000, self._refresh_hades_stats)
    
    def _send_hades_chat(self):
        """Send a message to HadesAI chat"""
        message = self.hades_chat_input.text().strip()
        if not message:
            return
            
        self.hades_chat_input.clear()
        self.hades_chat_output.append(f"<b style='color: #00ffcc;'>You:</b> {message}")
        
        if not self.hades_chat:
            self.hades_chat_output.append("<b style='color: #ff4444;'>HADES:</b> I'm not available. Please check if HadesAI module is properly installed.")
            return
        
        try:
            result = self.hades_chat.process(message)
            response = result.get('response', 'No response')
            self.hades_chat_output.append(f"<b style='color: #ff6600;'>HADES:</b> {response}")
            
            # Handle any actions
            action = result.get('action')
            if action:
                self._handle_hades_action(action)
                
        except Exception as e:
            self.hades_chat_output.append(f"<b style='color: #ff4444;'>Error:</b> {str(e)}")
    
    def _handle_hades_action(self, action):
        """Handle HadesAI action commands"""
        action_type = action.get('type')
        target = action.get('target')
        
        if action_type == 'cache_scan':
            self._hades_scan_cache()
        elif action_type in ['full_scan', 'vuln_scan', 'port_scan']:
            self.hades_chat_output.append(f"<i style='color: #888;'>Starting {action_type} on {target}...</i>")
            # Future: implement actual scanning
    
    def _hades_scan_cache(self):
        """Start browser cache scan"""
        if not HadesAI:
            QMessageBox.warning(self, "Error", "HadesAI module not available")
            return
            
        self.hades_chat_output.append("<i style='color: #888;'>Starting browser cache scan...</i>")
        
        try:
            self.hades_cache_scanner = HadesAI.BrowserScanner(self.hades_kb)
            self.hades_cache_scanner.progress.connect(lambda p: self._hades_cache_progress(p, "Scanning..."))
            self.hades_cache_scanner.status.connect(lambda s: self.hades_chat_output.append(f"<i style='color: #888;'>{s}</i>"))
            self.hades_cache_scanner.finding_detected.connect(self._hades_finding_detected)
            self.hades_cache_scanner.finished_scan.connect(self._hades_cache_complete)
            self.hades_cache_scanner.start()
        except Exception as e:
            self.hades_chat_output.append(f"<b style='color: #ff4444;'>Error:</b> {str(e)}")
    
    def _hades_cache_progress(self, progress, message):
        """Update cache scan progress"""
        self.hades_chat_output.append(f"<i style='color: #888;'>[{progress}%] {message}</i>")
    
    def _hades_finding_detected(self, finding):
        """Handle a detected finding from HadesAI"""
        # Add to findings table
        row = self.hades_findings_table.rowCount()
        self.hades_findings_table.insertRow(row)
        
        items = [
            QTableWidgetItem(finding.get('type', 'Unknown')),
            QTableWidgetItem(finding.get('path', '')[:50]),
            QTableWidgetItem(finding.get('severity', 'Medium')),
            QTableWidgetItem(finding.get('browser', 'Unknown')),
            QTableWidgetItem(datetime.now().strftime("%H:%M:%S"))
        ]
        
        for col, item in enumerate(items):
            severity = finding.get('severity', 'Medium').upper()
            if severity == 'HIGH':
                item.setBackground(QColor('#ff4444'))
            elif severity == 'MEDIUM':
                item.setBackground(QColor('#ffaa44'))
            self.hades_findings_table.setItem(row, col, item)
        
        # Also add to main OFSP detections
        detection = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': f"HadesAI Cache: {finding.get('type', 'Unknown')}",
            'name': finding.get('path', 'Unknown')[:30],
            'pid': 'N/A',
            'severity': finding.get('severity', 'Medium'),
            'description': finding.get('code', finding.get('pattern', ''))[:300],
            'details': finding.get('context', finding.get('pattern', 'Hades cache finding')),
            'path': finding.get('path', 'N/A'),
            'browser': finding.get('browser', 'Unknown'),
            'code': finding.get('code', ''),
            'patterns': [finding.get('pattern')] if finding.get('pattern') else [],
            'confidence': finding.get('confidence', 'medium'),
            'findings': [finding],
            'force_auto_quarantine': True
        }
        self._add_detection(detection)
        
        self.hades_chat_output.append(f"<b style='color: #ff6600;'>🎯 Finding:</b> {finding.get('type')} in {finding.get('path', '')[:40]}")
    
    def _hades_cache_complete(self, stats):
        """Handle cache scan completion"""
        self.hades_chat_output.append(f"<b style='color: #00ff88;'>✅ Cache scan complete!</b>")
        self.hades_chat_output.append(f"Files scanned: {stats.get('total_files', 0)}")
        self.hades_chat_output.append(f"Threats found: {stats.get('threats', 0)}")
        self._refresh_hades_stats()
        self._refresh_tome_tab_if_visible()
    
    def _hades_start_network_monitor(self):
        """Start network monitoring"""
        if not HadesAI:
            QMessageBox.warning(self, "Error", "HadesAI module not available")
            return
        
        try:
            if self.hades_network_monitor and self.hades_network_monitor.isRunning():
                self.hades_network_monitor.stop()
                self.hades_chat_output.append("<b style='color: #ffaa00;'>Network monitor stopped</b>")
            else:
                self.hades_network_monitor = HadesAI.NetworkMonitor()
                self.hades_network_monitor.connection_detected.connect(
                    lambda c: self.hades_chat_output.append(f"<i style='color: #888;'>Connection: {c.get('remote_ip', 'Unknown')}:{c.get('remote_port', 0)}</i>")
                )
                self.hades_network_monitor.threat_detected.connect(self._hades_finding_detected)
                self.hades_network_monitor.start()
                self.hades_chat_output.append("<b style='color: #00ff88;'>🌐 Network monitor started</b>")
        except Exception as e:
            self.hades_chat_output.append(f"<b style='color: #ff4444;'>Error:</b> {str(e)}")
    
    def _hades_show_exploits(self):
        """Show learned exploits"""
        if not self.hades_kb:
            self.hades_chat_output.append("<b style='color: #ff4444;'>Knowledge base not available</b>")
            return
        
        exploits = self.hades_kb.get_learned_exploits(10)
        if exploits:
            self.hades_chat_output.append("<b style='color: #ff6600;'>📚 Learned Exploits:</b>")
            for exp in exploits:
                self.hades_chat_output.append(f"• {exp.get('exploit_type', 'Unknown')} - {exp.get('description', 'No description')[:50]}")
        else:
            self.hades_chat_output.append("<i>No exploits learned yet. Scan some targets to learn!</i>")
    
    def _hades_show_findings(self):
        """Show threat findings"""
        if not self.hades_kb:
            self.hades_chat_output.append("<b style='color: #ff4444;'>Knowledge base not available</b>")
            return
        
        findings = self.hades_kb.get_threat_findings(10)
        if findings:
            self.hades_chat_output.append("<b style='color: #ff6600;'>🎯 Recent Threat Findings:</b>")
            for f in findings:
                self.hades_chat_output.append(f"• [{f.get('severity', 'Medium')}] {f.get('threat_type', 'Unknown')} - {f.get('path', '')[:40]}")
        else:
            self.hades_chat_output.append("<i>No findings yet. Start a scan!</i>")
    
    def _refresh_hades_stats(self):
        """Refresh HadesAI statistics"""
        if not self.hades_kb:
            return
        
        try:
            patterns = self.hades_kb.get_patterns()
            exploits = self.hades_kb.get_learned_exploits(1000)
            
            self.hades_patterns_label.setText(f"Patterns: {len(patterns)}")
            self.hades_exploits_label.setText(f"Learned Exploits: {len(exploits)}")
        except Exception as e:
            print(f"Error refreshing HADES stats: {e}")
        
    def _create_donation_tab(self):
        """Create donation/support tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignCenter)
        
        # Spacer at top
        layout.addStretch()
        
        # Main donation frame
        donation_frame = QGroupBox("Support Orbital Station Development")
        donation_frame.setStyleSheet("""
            QGroupBox {
                font-size: 18px;
                font-weight: bold;
                color: #00ff88;
                border: 2px solid #00ff88;
                border-radius: 10px;
                margin-top: 20px;
                padding: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 20px;
                padding: 0 10px;
            }
        """)
        donation_layout = QVBoxLayout(donation_frame)
        donation_layout.setSpacing(20)
        
        # Thank you message
        thanks_label = QLabel("Thank you for using Orbital Station!")
        thanks_label.setStyleSheet("font-size: 16px; color: #ffffff; font-weight: bold;")
        thanks_label.setAlignment(Qt.AlignCenter)
        donation_layout.addWidget(thanks_label)
        
        # Description
        desc_label = QLabel(
            "Your support helps us continue developing and improving\n"
            "Orbital Station's malware detection capabilities.\n\n"
            "Every contribution makes a difference!"
        )
        desc_label.setStyleSheet("font-size: 14px; color: #cccccc;")
        desc_label.setAlignment(Qt.AlignCenter)
        donation_layout.addWidget(desc_label)
        
        # Donation button
        donate_btn = QPushButton("💖 Support the Project")
        donate_btn.setStyleSheet("""
            QPushButton {
                background-color: #6772e5;
                color: white;
                font-size: 18px;
                font-weight: bold;
                padding: 15px 40px;
                border-radius: 8px;
                border: none;
            }
            QPushButton:hover {
                background-color: #7b85e8;
            }
            QPushButton:pressed {
                background-color: #5469d4;
            }
        """)
        donate_btn.setCursor(Qt.PointingHandCursor)
        donate_btn.clicked.connect(self._open_donation_link)
        donation_layout.addWidget(donate_btn, alignment=Qt.AlignCenter)
        
        # Link info
        link_label = QLabel("Secure payment via Stripe")
        link_label.setStyleSheet("font-size: 12px; color: #888888;")
        link_label.setAlignment(Qt.AlignCenter)
        donation_layout.addWidget(link_label)
        
        layout.addWidget(donation_frame)
        
        # Spacer at bottom
        layout.addStretch()
        
        self.tabs.addTab(widget, "💖 Support")
    
    def _open_donation_link(self):
        """Open the donation link in the default browser"""
        import webbrowser
        webbrowser.open("https://buy.stripe.com/28EbJ1f7ceo3ckyeES5kk00")
        if hasattr(self, 'log_output'):
            self.log_output.append("💖 Thank you for considering a donation!")
        
    def _create_status_bar(self, parent_layout):
        """Create status bar with system information"""
        status_frame = QWidget()
        status_layout = QHBoxLayout(status_frame)
        
        # Protection status
        self.status_label = QLabel("Initializing...")
        self.status_label.setStyleSheet("color: #ffcc00; font-weight: bold; font-size: 14px;")
        status_layout.addWidget(QLabel("Status:"))
        status_layout.addWidget(self.status_label)
        
        # Progress bar
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        self.scan_progress.setMinimum(0)
        self.scan_progress.setMaximum(100)
        status_layout.addWidget(self.scan_progress)
        
        # Status message
        self.status_message = QLabel("")
        status_layout.addWidget(self.status_message)
        
        # Counters
        self.processes_label = QLabel("Processes: 0")
        self.threats_label = QLabel("Threats: 0")
        self.rules_label = QLabel("Rules: Loading...")
        
        status_layout.addStretch()
        status_layout.addWidget(self.processes_label)
        status_layout.addWidget(self.threats_label)
        status_layout.addWidget(self.rules_label)
        
        parent_layout.addWidget(status_frame)
        
    def _create_control_panel(self, parent_layout):
        """Create the main control panel"""
        control_frame = QWidget()
        control_layout = QHBoxLayout(control_frame)
        
        # Scan controls group
        scan_group = QGroupBox("Scan Controls")
        scan_layout = QHBoxLayout(scan_group)
        
        self.quick_scan_btn = QPushButton("Quick Scan")
        self.deep_scan_btn = QPushButton("Deep Scan")
        self.stop_scan_btn = QPushButton("Stop Scan")
        self.stop_scan_btn.setEnabled(False)
        
        self.quick_scan_btn.clicked.connect(self.start_quick_scan)
        self.deep_scan_btn.clicked.connect(self.start_deep_scan)
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        
        scan_layout.addWidget(self.quick_scan_btn)
        scan_layout.addWidget(self.deep_scan_btn)
        scan_layout.addWidget(self.stop_scan_btn)
        
        # Protection controls group
        protection_group = QGroupBox("Protection Controls")
        protection_layout = QHBoxLayout(protection_group)
        
        self.enable_protection_btn = QPushButton("Enable Protection")
        self.disable_protection_btn = QPushButton("Disable Protection")
        self.quarantine_btn = QPushButton("Quarantine Selected")
        self.restore_btn = QPushButton("Restore Selected")
        
        self.enable_protection_btn.clicked.connect(self.enable_protection)
        self.disable_protection_btn.clicked.connect(self.disable_protection)
        self.quarantine_btn.clicked.connect(self.quarantine_selected)
        self.restore_btn.clicked.connect(self.restore_selected)

        self.delete_btn = QPushButton("Delete Selected")
        self.delete_btn.clicked.connect(self.delete_selected)
        
        protection_layout.addWidget(self.enable_protection_btn)
        protection_layout.addWidget(self.disable_protection_btn)
        protection_layout.addWidget(self.quarantine_btn)
        protection_layout.addWidget(self.delete_btn)
        protection_layout.addWidget(self.restore_btn)
        
        control_layout.addWidget(scan_group)
        control_layout.addWidget(protection_group)
        
        parent_layout.addWidget(control_frame)
        
    def _create_scanner_tab(self):
        """Create file scanner tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # File selection
        file_frame = QGroupBox("File Scanner")
        file_layout = QHBoxLayout(file_frame)
        
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Select file to scan...")
        
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self._browse_file)
        
        scan_file_btn = QPushButton("Scan File")
        scan_file_btn.clicked.connect(self._scan_file)
        
        file_layout.addWidget(QLabel("File:"))
        file_layout.addWidget(self.file_path_input)
        file_layout.addWidget(browse_btn)
        file_layout.addWidget(scan_file_btn)
        
        layout.addWidget(file_frame)
        
        # Results
        self.scan_results = QTextEdit()
        self.scan_results.setPlaceholderText("Scan results will appear here...")
        layout.addWidget(self.scan_results)
        
        self.tabs.addTab(widget, "File Scanner")
        
    def _create_filesystem_tab(self):
        """Create comprehensive filesystem scanner tab like commercial antivirus"""
        widget = QWidget()
        self.filesystem_tab = widget
        layout = QVBoxLayout(widget)
        
        # === SCAN CONFIGURATION ===
        config_group = QGroupBox("🖥️ System Scan Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Drive selection
        drive_frame = QGroupBox("Select Drives to Scan")
        drive_layout = QVBoxLayout(drive_frame)
        
        import string
        import os
        
        # Get available drives
        self.drive_checkboxes = {}
        drives_row = QHBoxLayout()
        
        for drive_letter in string.ascii_uppercase:
            drive_path = f"{drive_letter}:\\"
            if os.path.exists(drive_path):
                checkbox = QPushButton(f"Drive {drive_letter}:")
                checkbox.setCheckable(True)
                checkbox.setStyleSheet("""
                    QPushButton {
                        text-align: left;
                        padding: 8px;
                        border: 2px solid #555;
                        border-radius: 4px;
                        background: #2a2a2a;
                        color: white;
                    }
                    QPushButton:checked {
                        background: #0078d4;
                        border-color: #106ebe;
                    }
                """)
                self.drive_checkboxes[drive_letter] = checkbox
                drives_row.addWidget(checkbox)
                if len(self.drive_checkboxes) % 4 == 0:
                    drive_layout.addLayout(drives_row)
                    drives_row = QHBoxLayout()
        
        if drives_row.count() > 0:
            drive_layout.addLayout(drives_row)
            
        # Quick drive selection buttons
        quick_select_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All Drives")
        select_all_btn.clicked.connect(self._select_all_drives)
        select_system_btn = QPushButton("Select System Drive (C:)")
        select_system_btn.clicked.connect(self._select_system_drive)
        clear_drives_btn = QPushButton("Clear Selection")
        clear_drives_btn.clicked.connect(self._clear_drive_selection)
        
        quick_select_layout.addWidget(select_all_btn)
        quick_select_layout.addWidget(select_system_btn)
        quick_select_layout.addWidget(clear_drives_btn)
        quick_select_layout.addStretch()
        
        drive_layout.addLayout(quick_select_layout)
        config_layout.addWidget(drive_frame)
        
        # Scan options
        options_frame = QGroupBox("Scan Options")
        options_layout = QVBoxLayout(options_frame)
        
        # File type filters
        filter_layout = QHBoxLayout()
        self.scan_executables = QPushButton("Scan Executables (.exe, .dll, .scr)")
        self.scan_executables.setCheckable(True)
        self.scan_executables.setChecked(True)
        
        self.scan_scripts = QPushButton("Scan Scripts (.bat, .ps1, .vbs)")
        self.scan_scripts.setCheckable(True)
        self.scan_scripts.setChecked(True)
        
        self.scan_documents = QPushButton("Scan Documents (.pdf, .doc, .xls)")
        self.scan_documents.setCheckable(True)
        
        self.scan_all_files = QPushButton("Scan All File Types")
        self.scan_all_files.setCheckable(True)
        
        for btn in [self.scan_executables, self.scan_scripts, self.scan_documents, self.scan_all_files]:
            btn.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 6px;
                    border: 1px solid #555;
                    border-radius: 3px;
                    background: #2a2a2a;
                    color: white;
                }
                QPushButton:checked {
                    background: #0078d4;
                    border-color: #106ebe;
                }
            """)
        
        filter_layout.addWidget(self.scan_executables)
        filter_layout.addWidget(self.scan_scripts)
        filter_layout.addWidget(self.scan_documents)
        filter_layout.addWidget(self.scan_all_files)
        options_layout.addLayout(filter_layout)
        
        # Advanced options
        advanced_layout = QHBoxLayout()
        self.deep_scan_archives = QPushButton("Deep Scan Archives (.zip, .rar)")
        self.deep_scan_archives.setCheckable(True)
        
        self.scan_network_drives = QPushButton("Include Network Drives")
        self.scan_network_drives.setCheckable(True)
        
        self.heuristic_analysis = QPushButton("Heuristic Analysis")
        self.heuristic_analysis.setCheckable(True)
        self.heuristic_analysis.setChecked(True)
        
        self.scan_browser_artifacts = QPushButton("Scan Browser Artifacts")
        self.scan_browser_artifacts.setCheckable(True)
        self.scan_browser_artifacts.setChecked(True)

        for btn in [self.deep_scan_archives, self.scan_network_drives, self.heuristic_analysis, self.scan_browser_artifacts]:
            btn.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 6px;
                    border: 1px solid #555;
                    border-radius: 3px;
                    background: #2a2a2a;
                    color: white;
                }
                QPushButton:checked {
                    background: #0078d4;
                    border-color: #106ebe;
                }
            """)
        
        advanced_layout.addWidget(self.deep_scan_archives)
        advanced_layout.addWidget(self.scan_network_drives)
        advanced_layout.addWidget(self.heuristic_analysis)
        advanced_layout.addWidget(self.scan_browser_artifacts)
        advanced_layout.addStretch()
        options_layout.addLayout(advanced_layout)
        
        config_layout.addWidget(options_frame)
        layout.addWidget(config_group)
        
        # === SCAN CONTROLS ===
        controls_group = QGroupBox("🚀 Scan Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        self.fs_quick_scan_btn = QPushButton("⚡ Quick Scan")
        self.fs_quick_scan_btn.setStyleSheet("""
            QPushButton {
                background: #28a745;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #218838;
            }
        """)
        self.fs_quick_scan_btn.clicked.connect(self._start_filesystem_quick_scan)
        
        self.fs_full_scan_btn = QPushButton("🔍 Full System Scan")
        self.fs_full_scan_btn.setStyleSheet("""
            QPushButton {
                background: #17a2b8;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #138496;
            }
        """)
        self.fs_full_scan_btn.clicked.connect(self._start_filesystem_full_scan)
        
        self.fs_custom_scan_btn = QPushButton("⚙️ Custom Scan")
        self.fs_custom_scan_btn.setStyleSheet("""
            QPushButton {
                background: #6f42c1;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #5a32a3;
            }
        """)
        self.fs_custom_scan_btn.clicked.connect(self._start_filesystem_custom_scan)

        self.fs_browser_scan_btn = QPushButton("Browser Deep Clean Scan")
        self.fs_browser_scan_btn.setStyleSheet("""
            QPushButton {
                background: #5a3f99;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #4b3380;
            }
        """)
        self.fs_browser_scan_btn.clicked.connect(self._start_browser_deep_clean_scan)
        
        self.fs_stop_scan_btn = QPushButton("⏹️ Stop Scan")
        self.fs_stop_scan_btn.setStyleSheet("""
            QPushButton {
                background: #dc3545;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background: #c82333;
            }
        """)
        self.fs_stop_scan_btn.clicked.connect(self._stop_filesystem_scan)
        self.fs_stop_scan_btn.setEnabled(False)
        
        controls_layout.addWidget(self.fs_quick_scan_btn)
        controls_layout.addWidget(self.fs_full_scan_btn)
        controls_layout.addWidget(self.fs_custom_scan_btn)
        controls_layout.addWidget(self.fs_browser_scan_btn)
        controls_layout.addWidget(self.fs_stop_scan_btn)
        controls_layout.addStretch()
        layout.addWidget(controls_group)
        
        # === SCAN PROGRESS ===
        progress_group = QGroupBox("📊 Scan Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        # Progress information
        info_layout = QHBoxLayout()
        self.fs_current_file_label = QLabel("Ready to scan...")
        self.fs_files_scanned_label = QLabel("Files Scanned: 0")
        self.fs_threats_found_label = QLabel("Threats Found: 0")
        self.fs_scan_speed_label = QLabel("Speed: 0 files/sec")
        
        info_layout.addWidget(self.fs_current_file_label)
        info_layout.addStretch()
        info_layout.addWidget(self.fs_files_scanned_label)
        info_layout.addWidget(self.fs_threats_found_label)
        info_layout.addWidget(self.fs_scan_speed_label)
        progress_layout.addLayout(info_layout)
        
        # Progress bar
        self.fs_progress_bar = QProgressBar()
        self.fs_progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #555;
                border-radius: 5px;
                text-align: center;
                background: #2a2a2a;
                color: white;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0,
                                          stop: 0 #28a745, stop: 1 #20c997);
                border-radius: 3px;
            }
        """)
        progress_layout.addWidget(self.fs_progress_bar)
        
        layout.addWidget(progress_group)
        
        # === SCAN RESULTS ===
        results_group = QGroupBox("🦠 Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        self.fs_results_table = QTableWidget()
        self.fs_results_table.setColumnCount(6)
        self.fs_results_table.setHorizontalHeaderLabels([
            "Threat Name", "File Path", "Threat Type", "Severity", "Action", "Details"
        ])
        self.fs_results_table.setAlternatingRowColors(True)
        self.fs_results_table.setSelectionBehavior(QTableWidget.SelectRows)
        results_layout.addWidget(self.fs_results_table)
        
        # Results actions
        results_actions_layout = QHBoxLayout()
        quarantine_selected_btn = QPushButton("🔒 Quarantine Selected")
        quarantine_selected_btn.clicked.connect(self._quarantine_selected_files)
        
        delete_selected_btn = QPushButton("🗑️ Delete Selected")
        delete_selected_btn.clicked.connect(self._delete_selected_files)
        
        export_results_btn = QPushButton("📄 Export Results")
        export_results_btn.clicked.connect(self._export_scan_results)
        
        clear_results_btn = QPushButton("🧹 Clear Results")
        clear_results_btn.clicked.connect(self._clear_scan_results)
        
        results_actions_layout.addWidget(quarantine_selected_btn)
        results_actions_layout.addWidget(delete_selected_btn)
        results_actions_layout.addWidget(export_results_btn)
        results_actions_layout.addWidget(clear_results_btn)
        results_actions_layout.addStretch()
        results_layout.addLayout(results_actions_layout)
        
        layout.addWidget(results_group)
        
        # Initialize filesystem scan state
        self.fs_scanning = False
        self.fs_scan_worker = None
        self.fs_files_scanned = 0
        self.fs_threats_found = 0
        
        self.tabs.addTab(widget, "🖥️ System Scanner")
        
    def _create_memory_tab(self):
        """Create memory analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Process selection
        process_frame = QGroupBox("Memory Analysis")
        process_layout = QHBoxLayout(process_frame)
        
        self.pid_input = QLineEdit()
        self.pid_input.setPlaceholderText("Enter Process ID...")
        
        analyze_btn = QPushButton("Analyze Memory")
        analyze_btn.clicked.connect(self._analyze_memory)
        
        dump_btn = QPushButton("Dump Memory")
        dump_btn.clicked.connect(self._dump_memory)
        
        scan_all_btn = QPushButton("Scan All Processes")
        scan_all_btn.clicked.connect(self._scan_all_processes)
        scan_all_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        
        process_layout.addWidget(QLabel("PID:"))
        process_layout.addWidget(self.pid_input)
        process_layout.addWidget(analyze_btn)
        process_layout.addWidget(dump_btn)
        process_layout.addWidget(scan_all_btn)
        
        layout.addWidget(process_frame)
        
        # Memory regions table
        self.memory_table = QTableWidget()
        self.memory_table.setColumnCount(5)
        self.memory_table.setHorizontalHeaderLabels(["Address", "Size", "Protection", "Type", "Status"])
        self.memory_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.memory_table)
        
        # Memory analysis output
        self.memory_output = QTextEdit()
        self.memory_output.setPlaceholderText("Memory analysis results will appear here...")
        layout.addWidget(self.memory_output)
        
        self.tabs.addTab(widget, "Memory Analysis")
        
    def _create_shellcode_detection_tab(self):
        """🧙‍♂️ Create the Ancient Shellcode Tome - A mystical interface to browse learned spells"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # === TOME HEADER WITH WISDOM STATISTICS ===
        header_frame = QGroupBox("🧙‍♂️ The Ancient Shellcode Tome - Keeper of Dark Magic Knowledge")
        header_layout = QVBoxLayout(header_frame)
        
        # Tome wisdom display
        wisdom_layout = QHBoxLayout()
        
        self.tome_power_label = QLabel("Tome Power Level: Loading...")
        self.tome_power_label.setStyleSheet("color: #FFD700; font-weight: bold; font-size: 14px;")
        
        self.tome_spells_label = QLabel("Spells Learned: Loading...")
        self.tome_categories_label = QLabel("Categories Discovered: Loading...")
        self.tome_velocity_label = QLabel("Learning Velocity: Loading...")
        
        wisdom_layout.addWidget(self.tome_power_label)
        wisdom_layout.addWidget(self.tome_spells_label)
        wisdom_layout.addWidget(self.tome_categories_label)
        wisdom_layout.addWidget(self.tome_velocity_label)
        wisdom_layout.addStretch()
        
        header_layout.addLayout(wisdom_layout)
        layout.addWidget(header_frame)
        
        # === MAGICAL SCANNING CONTROLS ===
        control_frame = QGroupBox("🔮 Arcane Detection & Learning Spells")
        control_layout = QVBoxLayout(control_frame)
        
        # Primary scan spells
        scan_row = QHBoxLayout()
        
        scan_memory_btn = QPushButton("🧠 Scan Memory Realms")
        scan_memory_btn.clicked.connect(self._scan_memory_for_shellcode)
        scan_memory_btn.setStyleSheet("""
            QPushButton { 
                background-color: #8B008B; 
                color: white; 
                font-weight: bold; 
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background-color: #9932CC; }
        """)
        
        scan_process_btn = QPushButton("⚔️ Scan Process Soul")
        scan_process_btn.clicked.connect(self._scan_process_for_shellcode)
        scan_process_btn.setStyleSheet("""
            QPushButton { 
                background-color: #DC143C; 
                color: white; 
                font-weight: bold; 
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background-color: #FF1493; }
        """)
        
        deep_scan_btn = QPushButton("🌌 Deep Mystical Scan")
        deep_scan_btn.clicked.connect(self._deep_shellcode_scan)
        deep_scan_btn.setStyleSheet("""
            QPushButton { 
                background-color: #191970; 
                color: white; 
                font-weight: bold; 
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background-color: #4169E1; }
        """)
        
        scan_row.addWidget(scan_memory_btn)
        scan_row.addWidget(scan_process_btn)
        scan_row.addWidget(deep_scan_btn)
        
        # Tome management spells
        tome_row = QHBoxLayout()
        
        browse_tome_btn = QPushButton("📚 Browse Ancient Spells")
        browse_tome_btn.clicked.connect(self._browse_ancient_tome)
        browse_tome_btn.setStyleSheet("""
            QPushButton { 
                background-color: #2F4F4F; 
                color: white; 
                font-weight: bold; 
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background-color: #708090; }
        """)
        
        search_tome_btn = QPushButton("🔍 Search Tome")
        search_tome_btn.clicked.connect(self._search_tome)
        search_tome_btn.setStyleSheet("""
            QPushButton { 
                background-color: #556B2F; 
                color: white; 
                font-weight: bold; 
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background-color: #9ACD32; }
        """)
        
        stats_btn = QPushButton("📊 Tome Statistics")
        stats_btn.clicked.connect(self._show_tome_statistics)
        stats_btn.setStyleSheet("""
            QPushButton { 
                background-color: #B8860B; 
                color: white; 
                font-weight: bold; 
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover { background-color: #DAA520; }
        """)
        
        clear_results_btn = QPushButton("🧹 Clear Results")
        clear_results_btn.clicked.connect(self._clear_shellcode_results)
        
        tome_row.addWidget(browse_tome_btn)
        tome_row.addWidget(search_tome_btn)
        tome_row.addWidget(stats_btn)
        tome_row.addWidget(clear_results_btn)
        
        # Detection sensitivity and filters
        settings_row = QHBoxLayout()
        
        sensitivity_label = QLabel("🎯 Detection Sensitivity:")
        self.shellcode_sensitivity = QComboBox()
        self.shellcode_sensitivity.addItems(["Low", "Medium", "High", "Paranoid", "Wizard"])
        self.shellcode_sensitivity.setCurrentText("Medium")
        
        category_label = QLabel("📜 Spell Category:")
        self.spell_category_filter = QComboBox()
        self.spell_category_filter.addItems([
            "All Spells", "🪄 API Hashing", "🥚 Egg Hunters", "💉 Process Injection",
            "⚗️ XOR Encoding", "📚 Stack Strings", "🏛️ PEB Access", "🪞 Reflective Loading",
            "⛓️ ROP Chains", "🐚 Pure Shellcode", "🔥 RWX Memory", "⚡ WX Memory",
            "🌊 CFG Bypass", "👻 Process Hollowing", "🌫️ Suspicious Memory",
            "📋 Unsigned Modules", "🗝️ Suspicious Registry", "👑 Suspicious Cmdline",
            "🎯 YARA Matches", "🌟 Unknown Magic"
        ])
        
        settings_row.addWidget(sensitivity_label)
        settings_row.addWidget(self.shellcode_sensitivity)
        settings_row.addWidget(category_label)
        settings_row.addWidget(self.spell_category_filter)
        settings_row.addStretch()
        
        control_layout.addLayout(scan_row)
        control_layout.addLayout(tome_row)
        control_layout.addLayout(settings_row)
        layout.addWidget(control_frame)
        
        # === SPELL RESULTS TABLE ===
        results_frame = QGroupBox("📋 Detected Spells & Ancient Knowledge")
        results_layout = QVBoxLayout(results_frame)
        
        self.shellcode_table = QTableWidget()
        self.shellcode_table.setColumnCount(9)
        self.shellcode_table.setHorizontalHeaderLabels([
            "🕐 Discovered", "🏷️ Spell Name", "⚔️ Process", "📍 Memory Realm", 
            "🎯 Confidence", "⚡ Power", "📏 Size", "🔄 Encounters", "🛡️ Actions"
        ])
        
        # Enhanced table styling
        self.shellcode_table.setAlternatingRowColors(True)
        self.shellcode_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.shellcode_table.setSortingEnabled(True)
        header = self.shellcode_table.horizontalHeader()
        header.setStretchLastSection(True)
        
        # Custom styling for mystical appearance
        self.shellcode_table.setStyleSheet("""
            QTableWidget {
                background-color: #1a1a2e;
                color: #eee;
                gridline-color: #16213e;
                border: 1px solid #16213e;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #16213e;
            }
            QTableWidget::item:selected {
                background-color: #0f3460;
                color: #fff;
            }
            QHeaderView::section {
                background-color: #16213e;
                color: #eee;
                padding: 8px;
                border: 1px solid #0e1b3c;
                font-weight: bold;
            }
        """)
        
        results_layout.addWidget(self.shellcode_table)
        layout.addWidget(results_frame)
        
        # === SPELL ANALYSIS GRIMOIRE ===
        details_frame = QGroupBox("📖 Spell Analysis Grimoire")
        details_layout = QVBoxLayout(details_frame)
        
        # Create mystical tabs for different spell views
        self.shellcode_details_tabs = QTabWidget()
        self.shellcode_details_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #16213e;
                background-color: #1a1a2e;
            }
            QTabBar::tab {
                background-color: #16213e;
                color: #eee;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0f3460;
                color: #fff;
            }
        """)
        
        # 🔮 Raw Magic view
        self.shellcode_hex_view = QTextEdit()
        self.shellcode_hex_view.setFont(QFont("Courier New", 10))
        self.shellcode_hex_view.setPlaceholderText("Select a spell to reveal its raw magical essence...")
        self.shellcode_hex_view.setStyleSheet("background-color: #0d1117; color: #c9d1d9;")
        self.shellcode_details_tabs.addTab(self.shellcode_hex_view, "🔮 Raw Magic")
        
        # ⚔️ Spell Incantation view
        self.shellcode_disasm_view = QTextEdit()
        self.shellcode_disasm_view.setFont(QFont("Courier New", 10))
        self.shellcode_disasm_view.setPlaceholderText("Select a spell to see its mystical incantations...")
        self.shellcode_disasm_view.setStyleSheet("background-color: #0d1117; color: #58a6ff;")
        self.shellcode_details_tabs.addTab(self.shellcode_disasm_view, "⚔️ Incantations")
        
        # 🌟 Pattern Runes view
        self.shellcode_patterns_view = QTextEdit()
        self.shellcode_patterns_view.setPlaceholderText("Select a spell to analyze its magical patterns and runes...")
        self.shellcode_patterns_view.setStyleSheet("background-color: #0d1117; color: #79c0ff;")
        self.shellcode_details_tabs.addTab(self.shellcode_patterns_view, "🌟 Pattern Runes")
        
        # 📜 Ancient Scroll view
        self.shellcode_metadata_view = QTextEdit()
        self.shellcode_metadata_view.setPlaceholderText("Select a spell to read its ancient scroll metadata...")
        self.shellcode_metadata_view.setStyleSheet("background-color: #0d1117; color: #ffa657;")
        self.shellcode_details_tabs.addTab(self.shellcode_metadata_view, "📜 Ancient Scroll")
        
        # 🔍 Spell History view (new)
        self.spell_history_view = QTextEdit()
        self.spell_history_view.setPlaceholderText("Select a spell to view its discovery history and encounters...")
        self.spell_history_view.setStyleSheet("background-color: #0d1117; color: #f85149;")
        self.shellcode_details_tabs.addTab(self.spell_history_view, "🔍 Spell History")
        
        details_layout.addWidget(self.shellcode_details_tabs)
        layout.addWidget(details_frame)
        
        # Connect mystical events
        self.shellcode_table.itemSelectionChanged.connect(self._update_shellcode_details)
        self.spell_category_filter.currentTextChanged.connect(self._filter_spells_by_category)
        
        # Initialize tome wisdom display
        self._update_tome_wisdom_display()
        self._browse_ancient_tome()

        self.tabs.addTab(widget, "🧙‍♂️ Ancient Tome")
        
    def _create_process_tab(self):
        """Create process monitoring tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Process controls
        control_frame = QGroupBox("Process Controls")
        control_layout = QHBoxLayout(control_frame)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh_processes)
        
        terminate_btn = QPushButton("Terminate Process")
        terminate_btn.clicked.connect(self._terminate_process)
        
        suspend_btn = QPushButton("Suspend Process")
        suspend_btn.clicked.connect(self._suspend_process)
        
        control_layout.addWidget(refresh_btn)
        control_layout.addWidget(terminate_btn)
        control_layout.addWidget(suspend_btn)
        control_layout.addStretch()
        
        layout.addWidget(control_frame)
        
        # Process tree
        self.process_tree = QTreeWidget()
        self.process_tree.setHeaderLabels(["PID", "Name", "CPU %", "Memory", "Status", "Path"])
        self.process_tree.setAlternatingRowColors(True)
        layout.addWidget(self.process_tree)
        
        # Auto-refresh processes - less aggressive to prevent freezing
        self.process_timer = QTimer()
        self.process_timer.timeout.connect(self._smart_refresh_processes)
        self.process_timer.start(15000)  # Refresh every 15 seconds instead of 5
        
        self.tabs.addTab(widget, "Process Monitor")
        
    def _create_detections_tab(self):
        """Create detections/alerts tab"""
        widget = QWidget()
        self.detections_tab = widget
        layout = QVBoxLayout(widget)

        # Detection controls
        control_frame = QGroupBox("Detection Management")
        control_layout = QHBoxLayout(control_frame)

        self.detections_quarantine_btn = QPushButton("Quarantine Selected")
        self.detections_quarantine_btn.setEnabled(False)
        self.detections_quarantine_btn.clicked.connect(self._quarantine_selected_detections)

        self.detections_delete_btn = QPushButton("Delete Selected")
        self.detections_delete_btn.setEnabled(False)
        self.detections_delete_btn.clicked.connect(self._delete_selected_detections)

        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self._clear_detections)

        export_btn = QPushButton("Export Detections")
        export_btn.clicked.connect(self._export_detections)

        control_layout.addWidget(self.detections_quarantine_btn)
        control_layout.addWidget(self.detections_delete_btn)
        control_layout.addWidget(clear_btn)
        control_layout.addWidget(export_btn)
        control_layout.addStretch()
        
        layout.addWidget(control_frame)
        
        # Detections table
        self.detections_table = QTableWidget()
        self.detections_table.setColumnCount(6)
        self.detections_table.setHorizontalHeaderLabels(["Timestamp", "Type", "Name", "PID", "Severity", "Description"])
        self.detections_table.horizontalHeader().setStretchLastSection(True)
        self.detections_table.setAlternatingRowColors(True)
        self.detections_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.detections_table)
        
        # Detection detail pane
        detail_frame = QGroupBox("Detection Details")
        detail_layout = QVBoxLayout(detail_frame)
        self.detection_details_text = QTextEdit()
        self.detection_details_text.setReadOnly(True)
        self.detection_details_text.setMaximumHeight(220)
        self.detection_details_text.setPlaceholderText("Select a detection to view full context and recommended response.")
        detail_layout.addWidget(self.detection_details_text)
        layout.addWidget(detail_frame)

        self.detections_table.itemSelectionChanged.connect(self._update_detection_details)
        self.detections_table.itemSelectionChanged.connect(self._update_detection_action_buttons)

        self.tabs.addTab(widget, "Detections")

    def _update_detection_action_buttons(self):
        """Enable detection action buttons only when selected rows have valid file paths."""
        if not hasattr(self, 'detections_table'):
            return

        has_actionable_selection = False
        selected_rows = sorted({item.row() for item in self.detections_table.selectedItems()})
        for row in selected_rows:
            if row < 0 or row >= len(self.detections):
                continue
            detection = self.detections[row]
            file_path = str(detection.get('path', '')).strip()
            if file_path and file_path.lower() not in ('n/a', 'na') and os.path.exists(file_path):
                has_actionable_selection = True
                break

        if hasattr(self, 'detections_quarantine_btn'):
            self.detections_quarantine_btn.setEnabled(has_actionable_selection)
        if hasattr(self, 'detections_delete_btn'):
            self.detections_delete_btn.setEnabled(has_actionable_selection)

    def _get_detection_recommendation(self, detection):
        """Return a practical recommendation based on detection context."""
        detection_type = str(detection.get('type', '')).lower()
        severity = str(detection.get('severity', 'Medium')).lower()
        path_text = str(detection.get('path', '')).lower()

        if 'shellcode' in detection_type or 'injection' in detection_type:
            return "Quarantine related file/artifact, isolate process tree, and capture memory snapshot for forensic triage."
        if 'yara' in detection_type:
            return "Review matched rule details and signature family, then quarantine file if path is not trusted/whitelisted."
        if 'memory' in detection_type:
            return "Re-scan process with elevated privileges, verify module map, and terminate process if confidence remains high."
        if 'heuristic' in detection_type:
            return "Validate file provenance, hash reputation, and execution chain before quarantine/deletion decision."
        if 'hadesai' in detection_type:
            return "Open Hades findings for correlated evidence and apply the suggested mitigation workflow for this threat class."
        if any(s in path_text for s in ['temp', 'appdata', 'downloads']):
            return "Treat as potentially staged payload; quarantine first, then inspect parent process and startup persistence."
        if severity == 'high':
            return "Prioritize immediate containment: isolate, quarantine, and investigate related processes and network activity."
        return "Collect additional telemetry (hash, signer, parent process, command line) and monitor for recurrence."

    def _format_detection_details(self, detection):
        """Build a thorough, human-readable detail view for a detection."""
        timestamp = detection.get('timestamp', 'Unknown')
        detection_type = detection.get('type', 'Unknown')
        name = detection.get('name', 'Unknown')
        pid = detection.get('pid', 'N/A')
        severity = detection.get('severity', 'Medium')
        description = detection.get('description', detection.get('details', 'No description provided.'))
        path = detection.get('path', 'N/A')
        confidence = detection.get('confidence', 'N/A')
        risk = detection.get('risk', severity)
        address = detection.get('address', 'N/A')
        size = detection.get('size', 'N/A')
        patterns = detection.get('patterns', [])
        browser = detection.get('browser', '')
        code_snippet = detection.get('code', detection.get('code_snippet', ''))
        yara_rule = detection.get('rule', detection.get('yara_rule', ''))

        if isinstance(address, int):
            address = f"0x{address:08x}"

        pattern_text = ', '.join(map(str, patterns[:6])) if patterns else 'None captured'
        if len(patterns) > 6:
            pattern_text += f" (+{len(patterns) - 6} more)"

        lines = [
            f"Timestamp: {timestamp}",
            f"Type: {detection_type}",
            f"Name/Target: {name}",
            f"PID: {pid}",
            f"Severity: {severity}",
            f"Risk Rating: {risk}",
            f"Confidence: {confidence}",
            f"Path: {path}",
            f"Memory Address: {address}",
            f"Artifact Size: {size}",
            f"YARA Rule: {yara_rule or 'N/A'}",
            f"Browser Context: {browser or 'N/A'}",
            "",
            "Why This Was Flagged:",
            f"{description}",
            "",
            "Observed Indicators:",
            f"{pattern_text}",
        ]

        if code_snippet:
            lines.extend(["", "Relevant Snippet:", str(code_snippet)[:600]])

        lines.extend([
            "",
            "Recommended Action:",
            self._get_detection_recommendation(detection),
        ])

        return "\n".join(lines)

    def _update_detection_details(self):
        """Update detection detail panel based on current selection."""
        if not hasattr(self, 'detection_details_text'):
            return

        current_row = self.detections_table.currentRow()
        if current_row < 0 or current_row >= len(self.detections):
            self.detection_details_text.setText("Select a detection to view full context and response guidance.")
            return

        detection = self.detections[current_row]
        self.detection_details_text.setText(self._format_detection_details(detection))

    def _quarantine_selected_detections(self):
        """Quarantine file-backed detections directly from the detections tab."""
        selected_rows = sorted({item.row() for item in self.detections_table.selectedItems()})
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select detections to quarantine.")
            return

        quarantined = 0
        skipped = 0
        for row in selected_rows:
            if row < 0 or row >= len(self.detections):
                continue

            detection = self.detections[row]
            file_path = str(detection.get('path', '')).strip()
            if not file_path or file_path.lower() in ('n/a', 'na') or not os.path.exists(file_path):
                skipped += 1
                continue

            if self._is_system_file_protected(file_path):
                skipped += 1
                continue

            if self._quarantine_file(file_path):
                detection['status'] = 'Quarantined'
                quarantined += 1

        self._update_detection_action_buttons()
        QMessageBox.information(self, "Detections Quarantined", f"Quarantined {quarantined} detections. Skipped {skipped}.")

    def _delete_selected_detections(self):
        """Delete file-backed detections directly from the detections tab."""
        selected_rows = sorted({item.row() for item in self.detections_table.selectedItems()})
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select detections to delete.")
            return

        confirm = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Permanently delete files for {len(selected_rows)} selected detections?\n\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if confirm != QMessageBox.Yes:
            return

        deleted = 0
        skipped = 0
        for row in selected_rows:
            if row < 0 or row >= len(self.detections):
                continue

            detection = self.detections[row]
            file_path = str(detection.get('path', '')).strip()
            if not file_path or file_path.lower() in ('n/a', 'na') or not os.path.exists(file_path):
                skipped += 1
                continue

            if self._is_system_file_protected(file_path):
                skipped += 1
                continue

            try:
                os.remove(file_path)
                detection['status'] = 'Deleted'
                deleted += 1
            except Exception:
                skipped += 1

        self._update_detection_action_buttons()
        QMessageBox.information(self, "Detections Deleted", f"Deleted {deleted} detection files. Skipped {skipped}.")
        
    def _create_scan_results_tab(self):
        """Create dedicated scan results tab with enhanced visibility"""
        widget = QWidget()
        self.scan_results_tab = widget
        layout = QVBoxLayout(widget)
        
        # Results summary frame
        summary_frame = QGroupBox("Scan Summary")
        summary_layout = QHBoxLayout(summary_frame)
        
        self.sr_files_scanned_label = QLabel("Files Scanned: 0")
        self.sr_threats_found_label = QLabel("Threats Found: 0")
        self.sr_last_scan_label = QLabel("Last Scan: Never")
        self.sr_scan_type_label = QLabel("Scan Type: None")
        
        summary_layout.addWidget(self.sr_files_scanned_label)
        summary_layout.addWidget(self.sr_threats_found_label)
        summary_layout.addWidget(self.sr_last_scan_label)
        summary_layout.addWidget(self.sr_scan_type_label)
        summary_layout.addStretch()
        
        layout.addWidget(summary_frame)
        
        # Results management controls
        control_frame = QGroupBox("Results Management")
        control_layout = QHBoxLayout(control_frame)
        
        quarantine_selected_btn = QPushButton("Quarantine Selected")
        quarantine_selected_btn.clicked.connect(self._quarantine_selected_results)
        quarantine_selected_btn.setStyleSheet("QPushButton { background-color: #ff6600; color: white; font-weight: bold; }")
        
        delete_selected_btn = QPushButton("Delete Selected")
        delete_selected_btn.clicked.connect(self._delete_selected_results)
        delete_selected_btn.setStyleSheet("QPushButton { background-color: #cc0000; color: white; font-weight: bold; }")
        
        whitelist_selected_btn = QPushButton("Whitelist Selected")
        whitelist_selected_btn.clicked.connect(self._whitelist_selected_results)
        whitelist_selected_btn.setStyleSheet("QPushButton { background-color: #00aa00; color: white; font-weight: bold; }")
        
        export_results_btn = QPushButton("Export Results")
        export_results_btn.clicked.connect(self._export_scan_results)
        
        clear_results_btn = QPushButton("Clear Results")
        clear_results_btn.clicked.connect(self._clear_scan_results)
        
        control_layout.addWidget(quarantine_selected_btn)
        control_layout.addWidget(delete_selected_btn)  
        control_layout.addWidget(whitelist_selected_btn)
        control_layout.addWidget(export_results_btn)
        control_layout.addWidget(clear_results_btn)
        control_layout.addStretch()
        
        layout.addWidget(control_frame)
        
        # Enhanced results table with more space
        self.scan_results_table = QTableWidget()
        self.scan_results_table.setColumnCount(7)
        self.scan_results_table.setHorizontalHeaderLabels([
            "Threat Name", "File Path", "Type", "Severity", "Action", "Details", "Status"
        ])
        self.scan_results_table.horizontalHeader().setStretchLastSection(True)
        self.scan_results_table.setAlternatingRowColors(True)
        self.scan_results_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Set column widths for better visibility
        self.scan_results_table.setColumnWidth(0, 200)  # Threat Name
        self.scan_results_table.setColumnWidth(1, 400)  # File Path
        self.scan_results_table.setColumnWidth(2, 120)  # Type
        self.scan_results_table.setColumnWidth(3, 80)   # Severity
        self.scan_results_table.setColumnWidth(4, 100)  # Action
        self.scan_results_table.setColumnWidth(6, 100)  # Status
        
        layout.addWidget(self.scan_results_table)
        
        # Threat details area
        details_frame = QGroupBox("Threat Details")
        details_layout = QVBoxLayout(details_frame)
        
        self.threat_details_text = QTextEdit()
        self.threat_details_text.setMaximumHeight(150)
        self.threat_details_text.setPlaceholderText("Select a threat above to view detailed information...")
        details_layout.addWidget(self.threat_details_text)
        
        layout.addWidget(details_frame)
        
        # Connect selection change to details update
        self.scan_results_table.itemSelectionChanged.connect(self._update_threat_details)
        
        self.tabs.addTab(widget, "📊 Scan Results")
        
    def _create_yara_tab(self):
        """Create YARA rules management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # YARA controls
        control_frame = QGroupBox("YARA Rules Management")
        control_layout = QHBoxLayout(control_frame)
        
        compile_btn = QPushButton("Compile Rules")
        compile_btn.clicked.connect(self._compile_yara)
        
        reload_btn = QPushButton("Reload Rules")
        reload_btn.clicked.connect(self._reload_yara)
        
        test_btn = QPushButton("Test Rules")
        test_btn.clicked.connect(self._test_yara)
        
        control_layout.addWidget(compile_btn)
        control_layout.addWidget(reload_btn)
        control_layout.addWidget(test_btn)
        control_layout.addStretch()
        
        layout.addWidget(control_frame)
        
        # Rules output
        self.yara_output = QTextEdit()
        self.yara_output.setPlaceholderText("YARA rules information will appear here...")
        layout.addWidget(self.yara_output)
        
        self.tabs.addTab(widget, "YARA Rules")
        
    def _create_quarantine_tab(self):
        """Create quarantine management tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Quarantine controls
        control_frame = QGroupBox("Quarantine Management")
        control_layout = QHBoxLayout(control_frame)
        
        refresh_q_btn = QPushButton("Refresh")
        refresh_q_btn.clicked.connect(self._refresh_quarantine)
        
        restore_q_btn = QPushButton("Restore Selected")
        restore_q_btn.clicked.connect(self._restore_quarantined)
        
        delete_q_btn = QPushButton("Delete Permanently")
        delete_q_btn.clicked.connect(self._delete_quarantined)
        
        control_layout.addWidget(refresh_q_btn)
        control_layout.addWidget(restore_q_btn)
        control_layout.addWidget(delete_q_btn)
        control_layout.addStretch()
        
        layout.addWidget(control_frame)
        
        # Quarantined items
        self.quarantine_table = QTableWidget()
        self.quarantine_table.setColumnCount(4)
        self.quarantine_table.setHorizontalHeaderLabels(["Filename", "Original Path", "Date Quarantined", "Threat Type"])
        self.quarantine_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.quarantine_table)
        
        self.tabs.addTab(widget, "Quarantine")
        
    def _create_logs_tab(self):
        """Create logs and debug information tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Log controls
        control_frame = QGroupBox("Log Management")
        control_layout = QHBoxLayout(control_frame)
        
        clear_logs_btn = QPushButton("Clear Logs")
        clear_logs_btn.clicked.connect(self._clear_logs)
        
        save_logs_btn = QPushButton("Save Logs")
        save_logs_btn.clicked.connect(self._save_logs)
        
        control_layout.addWidget(clear_logs_btn)
        control_layout.addWidget(save_logs_btn)
        control_layout.addStretch()
        
        layout.addWidget(control_frame)
        
        # Log output
        self.log_output = QTextEdit()
        self.log_output.setPlaceholderText("Application logs will appear here...")
        layout.addWidget(self.log_output)
        
        self.tabs.addTab(widget, "Logs")
        
    def _create_scan_status_tab(self):
        """Create scan status and live detection monitoring tab"""
        widget = QWidget()
        self.live_scans_tab = widget
        layout = QVBoxLayout(widget)
        
        # Scan controls frame
        controls_frame = QGroupBox("🔍 Active Scans")
        controls_layout = QVBoxLayout(controls_frame)
        
        # Scan status display
        self.scan_status_text = QTextEdit()
        self.scan_status_text.setMaximumHeight(150)
        self.scan_status_text.setReadOnly(True)
        self.scan_status_text.append("💤 No active scans")
        controls_layout.addWidget(self.scan_status_text)
        
        # Quick control buttons
        buttons_layout = QHBoxLayout()
        
        self.start_memory_scan_btn = QPushButton("🧠 Start Memory Scan")
        self.start_memory_scan_btn.clicked.connect(self._scan_memory_for_shellcode)
        buttons_layout.addWidget(self.start_memory_scan_btn)
        
        self.start_process_scan_btn = QPushButton("🔍 Scan Process")
        self.start_process_scan_btn.clicked.connect(self._scan_process_for_shellcode)
        buttons_layout.addWidget(self.start_process_scan_btn)
        
        self.start_deep_scan_btn = QPushButton("🔬 Deep Scan")
        self.start_deep_scan_btn.clicked.connect(self._deep_shellcode_scan)
        buttons_layout.addWidget(self.start_deep_scan_btn)
        
        self.clear_detections_btn = QPushButton("🧹 Clear")
        self.clear_detections_btn.clicked.connect(self._clear_live_scan_results)
        buttons_layout.addWidget(self.clear_detections_btn)
        
        controls_layout.addLayout(buttons_layout)
        layout.addWidget(controls_frame)
        
        # Live detections frame
        detections_frame = QGroupBox("📊 Live Detection Results")
        detections_layout = QVBoxLayout(detections_frame)
        
        # Detection table
        self.live_detections_table = QTableWidget(0, 7)
        self.live_detections_table.setHorizontalHeaderLabels([
            "Timestamp", "Type", "Process", "Address", "Confidence", "Risk", "Size"
        ])
        self.live_detections_table.horizontalHeader().setStretchLastSection(True)
        self.live_detections_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.live_detections_table.itemSelectionChanged.connect(self._update_live_detection_details)
        detections_layout.addWidget(self.live_detections_table)
        
        # Detection details
        details_frame = QGroupBox("🔍 Detection Details")
        details_layout = QVBoxLayout(details_frame)
        
        self.live_detection_details = QTextEdit()
        self.live_detection_details.setMaximumHeight(200)
        self.live_detection_details.setReadOnly(True)
        self.live_detection_details.setText("Select a detection to view details")
        details_layout.addWidget(self.live_detection_details)
        
        detections_layout.addWidget(details_frame)
        layout.addWidget(detections_frame)
        
        self.tabs.addTab(widget, "📊 Live Scans")
        
    def _clear_live_scan_results(self):
        """Clear live scan results and status text."""
        self.live_detections_table.setRowCount(0)
        self.scan_status_text.clear()
        self.scan_status_text.append("💤 Results cleared")
        self.live_detection_details.setText("Select a detection to view details")
        
    def _update_live_detection_details(self):
        """Update live detection details when selection changes"""
        try:
            current_row = self.live_detections_table.currentRow()
            if current_row < 0:
                return
                
            timestamp_item = self.live_detections_table.item(current_row, 0)
            if not timestamp_item:
                return
                
            # Get detection data stored in UserRole
            detection = timestamp_item.data(Qt.UserRole) if hasattr(timestamp_item, 'data') else None
            if not detection:
                self.live_detection_details.setText("No detailed information available")
                return
            
            # Format detection details
            details = f"🔍 Detection Details:\n\n"
            details += f"Type: {detection.get('type', 'Unknown')}\n"
            details += f"Process: {detection.get('process', 'Unknown')}\n"
            address = detection.get('address', 'N/A')
            if isinstance(address, int):
                address_text = f"0x{address:08x}"
            else:
                address_text = str(address)

            details += f"Address: {address_text}\n"
            details += f"Size: {detection.get('size', 0)} bytes\n"
            details += f"Confidence: {detection.get('confidence', 'Unknown')}\n"
            details += f"Risk Level: {detection.get('risk', 'Unknown')}\n"
            
            if detection.get('details'):
                details += f"\nDetails: {detection.get('details')}\n"
                
            if detection.get('patterns'):
                details += f"\nPatterns Detected: {len(detection.get('patterns', []))}\n"
                
            self.live_detection_details.setText(details)
            
        except Exception as e:
            self.live_detection_details.setText(f"Error loading details: {str(e)}")
            
    def _add_live_detection(self, detection):
        """Add detection to live scan results table"""
        try:
            # Update scan status
            process_name = detection.get('process') or detection.get('name', 'Unknown')
            detection_type = detection.get('type', 'Unknown')
            self.scan_status_text.append(f"🎯 Detection: {detection_type} in {process_name}")
            
            # Add to live detections table
            current_row = self.live_detections_table.rowCount()
            self.live_detections_table.insertRow(current_row)
            
            timestamp = detection.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            process = detection.get('process') or detection.get('name', 'Unknown')
            address = detection.get('address', detection.get('location', detection.get('path', 'N/A')))
            confidence = detection.get('confidence', detection.get('severity', 'Unknown'))
            risk = detection.get('risk', detection.get('severity', 'Medium'))
            size = detection.get('size', 0)
            
            items = [
                QTableWidgetItem(timestamp),
                QTableWidgetItem(detection_type),
                QTableWidgetItem(process),
                QTableWidgetItem(f"0x{address:08x}" if isinstance(address, int) else str(address)),
                QTableWidgetItem(str(confidence)),
                QTableWidgetItem(str(risk)),
                QTableWidgetItem(f"{size} bytes")
            ]
            
            for col, item in enumerate(items):
                self.live_detections_table.setItem(current_row, col, item)
                
            # Color coding by risk level
            if str(risk).lower() == 'high':
                color = QColor('#ff4444')
            elif str(risk).lower() == 'medium':
                color = QColor('#ffaa44')
            else:
                color = QColor('#44ff44')
            items[5].setBackground(color)
            
            # Store detection data for detailed view
            items[0].setData(Qt.UserRole, detection)
            
            # Auto-scroll to new detection
            self.live_detections_table.scrollToBottom()
            
        except Exception as e:
            self.scan_status_text.append(f"❌ Error adding live detection: {str(e)}")
        
    # === SCAN METHODS ===
    
    def start_quick_scan(self):
        """Start a quick scan"""
        if self.scanning:
            return
            
        self.scanning = True
        self._update_scan_ui_start()
        
        # Update live scan status
        if hasattr(self, 'scan_status_text'):
            self.scan_status_text.append("🚀 Starting quick scan...")
            
        self.scan_worker = ScanWorker("quick", self)
        self.scan_worker.progress_updated.connect(self._update_scan_progress)
        self.scan_worker.detection_found.connect(self._add_detection)
        self.scan_worker.scan_completed.connect(self._scan_completed)
        self.scan_worker.start()
        
    def start_deep_scan(self):
        """Start a deep scan"""
        if self.scanning:
            return
            
        self.scanning = True
        self._update_scan_ui_start()
        
        # Update live scan status
        if hasattr(self, 'scan_status_text'):
            self.scan_status_text.append("🔬 Starting deep scan with memory analysis...")
            
        self.scan_worker = ScanWorker("deep", self)
        self.scan_worker.progress_updated.connect(self._update_scan_progress)
        self.scan_worker.detection_found.connect(self._add_detection)
        self.scan_worker.scan_completed.connect(self._scan_completed)
        self.scan_worker.start()
        
    def stop_scan(self):
        """Stop the current scan"""
        if self.scan_worker:
            self.scan_worker.stop()
            self.scan_worker.wait()
            
        self.scanning = False
        self._update_scan_ui_end()
        
    def _update_scan_ui_start(self):
        """Update UI when scan starts"""
        self.quick_scan_btn.setEnabled(False)
        self.deep_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        
    def _update_scan_ui_end(self):
        """Update UI when scan ends"""
        self.quick_scan_btn.setEnabled(True)
        self.deep_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.scan_progress.setVisible(False)
        self.status_message.setText("Scan completed")
        
    def _update_scan_progress(self, progress, message):
        """Update scan progress"""
        self.scan_progress.setValue(progress)
        self.status_message.setText(message)
        
        # Also update live scan status if available
        if hasattr(self, 'scan_status_text'):
            self.scan_status_text.append(f"📊 {message} ({progress}%)")
        
    def _scan_completed(self, results):
        """Handle scan completion"""
        self.scanning = False
        self._update_scan_ui_end()
        
        # Update live scan status if available
        if hasattr(self, 'scan_status_text'):
            self.scan_status_text.append(f"✅ Scan completed! {len(self.detections)} total detections found")
            
        # Update scan summary if available
        if hasattr(self, 'summary_stats_label'):
            self.summary_stats_label.setText(
                f"📊 Files Scanned: {getattr(self, 'files_scanned', 0)} | "
                f"Threats Found: {self.threats_found} | "
                f"Clean Files: {getattr(self, 'files_scanned', 0) - self.threats_found}"
            )
        
        # Refresh process list after scan
        self._smart_refresh_processes()
        
    def _add_detection(self, detection):
        """Add a new detection to all relevant tables and logs"""
        # Normalize legacy detection payloads to unified structure
        if 'type' not in detection and 'threat' in detection:
            detection['type'] = detection.get('threat', 'Detection')
        if 'name' not in detection:
            detection['name'] = detection.get('process', detection.get('path', 'Unknown'))
        if 'description' not in detection:
            detection['description'] = detection.get('details', 'Detection event captured')
        if 'path' not in detection and 'file_path' in detection:
            detection['path'] = detection.get('file_path')

        self.detections.append(detection)
        self.threats_found += 1
        self.threats_label.setText(f"Threats: {self.threats_found}")
        
        # Log the detection
        if hasattr(self, 'log_output'):
            severity = detection.get('severity', 'Medium')
            icon = "🔴" if severity == 'High' else "🟡" if severity == 'Medium' else "🟢"
            self.log_output.append(f"{icon} Detection: {detection.get('type', 'Unknown')} - {detection.get('name', 'Unknown')} (PID: {detection.get('pid', 'N/A')})")
        
        # Add to detections table
        row = self.detections_table.rowCount()
        self.detections_table.insertRow(row)
        
        items = [
            detection.get('timestamp', ''),
            detection.get('type', ''),
            detection.get('name', ''),
            str(detection.get('pid', '')),
            detection.get('severity', ''),
            detection.get('description', '')
        ]
        
        for col, item in enumerate(items):
            table_item = QTableWidgetItem(str(item))
            # Color code by severity
            severity = detection.get('severity', 'Medium')
            if severity == 'High':
                table_item.setBackground(QColor('#ff4444'))
            elif severity == 'Medium':
                table_item.setBackground(QColor('#ffaa44'))
            self.detections_table.setItem(row, col, table_item)
        
        # Also add to scan results table if available
        if hasattr(self, 'scan_results_table'):
            self._add_to_scan_results(detection)
            
        # Also add to live scan tab if available
        if hasattr(self, 'live_detections_table'):
            self._add_live_detection(detection)
            
        # Add to shellcode detection tab if it's a shellcode/memory detection
        detection_type = str(detection.get('type', '')).lower()
        if 'shellcode' in detection_type or 'memory' in detection_type or 'injection' in detection_type:
            self._add_shellcode_detection(detection)

        # Persist detection intelligence into Tome + Hades DB
        self._ingest_detection_into_knowledge(detection)

        # Auto-quarantine risky detections with valid file artifacts
        self._attempt_auto_quarantine(detection)

        # Refresh details panel with newest detection context
        if hasattr(self, 'detection_details_text') and self.detections:
            self.detection_details_text.setText(self._format_detection_details(detection))

        if hasattr(self, 'detections_table'):
            self._update_detection_action_buttons()
            
    # === FILE SCANNER METHODS ===
    
    def _browse_file(self):
        """Browse for file to scan"""
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan", "", "All Files (*)")
        if file_path:
            self.file_path_input.setText(file_path)
            
    def _scan_file(self):
        """Scan selected file"""
        file_path = self.file_path_input.text().strip()
        if not file_path:
            QMessageBox.warning(self, "Error", "Please select a file to scan")
            return
            
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", "Selected file does not exist")
            return
            
        try:
            self.scan_results.clear()
            self.scan_results.append(f"Scanning file: {file_path}\n")
            
            # Use malware scanner if available
            if self.malware_scanner:
                try:
                    results = self.malware_scanner.scan_file(file_path)
                    if results:
                        self.scan_results.append(f"THREAT DETECTED: {results}")
                        # Add to detections
                        detection = {
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'type': 'File',
                            'name': os.path.basename(file_path),
                            'pid': '',
                            'severity': 'High',
                            'description': f'Malware detected in file: {file_path}'
                        }
                        self._add_detection(detection)
                    else:
                        self.scan_results.append("File is clean")
                except Exception as e:
                    self.scan_results.append(f"Scan error: {str(e)}")
            else:
                self.scan_results.append("Malware scanner not available")
                
        except Exception as e:
            QMessageBox.critical(self, "Scan Error", f"Error scanning file: {str(e)}")
            
    # === MEMORY ANALYSIS METHODS ===
    
    def _analyze_memory(self):
        """Analyze process memory with enhanced shellcode detection"""
        pid_text = self.pid_input.text().strip()
        if not pid_text:
            QMessageBox.warning(self, "Error", "Please enter a Process ID")
            return
            
        try:
            pid = int(pid_text)
            if pid <= 0:
                QMessageBox.warning(self, "Error", "Please enter a valid positive Process ID")
                return
                
            self.memory_output.clear()
            self.memory_output.append(f"🔍 Analyzing memory for PID {pid}...\n")
            
            if self.memory_scanner:
                self.memory_output.append("Memory scanner is available - performing enhanced analysis...")
                try:
                    import psutil
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                    self.memory_output.append(f"Process found: {proc_name} (PID: {pid})")
                    
                    # Basic memory info
                    memory_info = proc.memory_info()
                    self.memory_output.append(f"📊 Memory usage: {memory_info.rss // (1024*1024)} MB")
                    self.memory_output.append(f"📊 Virtual memory: {memory_info.vms // (1024*1024)} MB")
                    
                    try:
                        exe_path = proc.exe()
                        self.memory_output.append(f"📂 Executable: {exe_path}")
                        self.memory_output.append(f"📊 Status: {proc.status()}")
                    except psutil.AccessDenied:
                        self.memory_output.append("⚠️ Limited access (some info requires admin)")
                    
                    # Enhanced memory scan with shellcode detection
                    self.memory_output.append("\n🔬 Starting enhanced shellcode detection...")
                    try:
                        detections = self.memory_scanner.scan_process_memory_enhanced(pid)
                        
                        if detections:
                            self.memory_output.append(f"\n⚠️ Found {len(detections)} suspicious patterns:\n")
                            for detection in detections:
                                self.memory_output.append(f"  🎯 {detection.get('type', 'Unknown')}")
                                self.memory_output.append(f"     Address: 0x{detection.get('address', 0):08x}")
                                self.memory_output.append(f"     Confidence: {detection.get('confidence', 0)}%")
                                self.memory_output.append(f"     Risk: {detection.get('risk', 'Unknown')}")
                                self.memory_output.append(f"     Size: {detection.get('size', 0)} bytes")
                                self.memory_output.append("")
                                
                                # Add to detections system
                                detection['name'] = proc_name
                                detection['pid'] = pid
                                detection['severity'] = detection.get('risk', 'Medium')
                                detection['description'] = detection.get('details', f"Shellcode detected at 0x{detection.get('address', 0):08x}")
                                self._add_detection(detection)
                        else:
                            self.memory_output.append("\n✅ No suspicious shellcode patterns detected")
                            
                    except Exception as scan_error:
                        self.memory_output.append(f"⚠️ Enhanced scan error: {str(scan_error)}")
                    
                    self.memory_output.append("\n✅ Memory analysis completed.")
                    
                except psutil.NoSuchProcess:
                    self.memory_output.append(f"❌ Process with PID {pid} not found")
                except Exception as e:
                    self.memory_output.append(f"❌ Error during memory analysis: {str(e)}")
            else:
                self.memory_output.append("❌ Memory scanner not available")
                
        except ValueError:
            QMessageBox.warning(self, "Error", "Please enter a valid numeric Process ID")
        except Exception as e:
            QMessageBox.critical(self, "Analysis Error", f"Error analyzing memory: {str(e)}")
            
    def _dump_memory(self):
        """Dump process memory"""
        pid_text = self.pid_input.text().strip()
        if not pid_text:
            QMessageBox.warning(self, "Error", "Please enter a Process ID")
            return
            
        try:
            pid = int(pid_text)
            self.memory_output.append(f"Memory dump for PID {pid} would be saved to file...")
            
        except ValueError:
            QMessageBox.warning(self, "Error", "Please enter a valid numeric Process ID")
    
    def _scan_all_processes(self):
        """Scan all running processes for suspicious activity"""
        if not self.memory_scanner:
            QMessageBox.warning(self, "Error", "Memory scanner is not available")
            return
            
        self.memory_output.clear()
        self.memory_output.append("Starting scan of all running processes...\n")
        
        try:
            import psutil
            processes = list(psutil.process_iter(['pid', 'name', 'exe', 'memory_info']))
            total_processes = len(processes)
            scanned_count = 0
            threats_found = 0
            
            self.memory_output.append(f"Found {total_processes} running processes\n")
            
            for proc in processes:
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    name = proc_info['name'] or 'Unknown'
                    
                    # Skip system critical processes to avoid issues
                    if name.lower() in ['system', 'registry', 'csrss.exe', 'wininit.exe']:
                        continue
                    
                    scanned_count += 1
                    self.memory_output.append(f"Scanning: {name} (PID: {pid})")
                    
                    # Basic suspicious behavior checks
                    suspicious_score = 0
                    warnings = []
                    
                    # Check if process executable path exists
                    exe_path = proc_info.get('exe')
                    if not exe_path or exe_path == '':
                        suspicious_score += 2
                        warnings.append("No executable path")
                    
                    # Check memory usage patterns
                    memory_info = proc_info.get('memory_info')
                    if memory_info and hasattr(memory_info, 'rss'):
                        memory_mb = memory_info.rss // (1024*1024)
                        if memory_mb > 1000:  # Very high memory usage
                            suspicious_score += 1
                            warnings.append(f"High memory usage: {memory_mb}MB")
                    
                    # Check for suspicious process names
                    suspicious_names = ['svchost', 'winlogon', 'explorer']
                    if any(sus_name in name.lower() for sus_name in suspicious_names):
                        if exe_path and not exe_path.startswith('C:\\Windows\\'):
                            suspicious_score += 3
                            warnings.append("Suspicious process name in non-system location")
                    
                    # Check for processes running from temp directories
                    if exe_path:
                        temp_paths = ['temp', 'tmp', 'appdata\\local\\temp']
                        if any(temp_path in exe_path.lower() for temp_path in temp_paths):
                            suspicious_score += 2
                            warnings.append("Running from temporary directory")
                    
                    # Report if suspicious
                    if suspicious_score >= 3:
                        threats_found += 1
                        self.memory_output.append(f"  ⚠️  SUSPICIOUS: {name} (PID: {pid}) - Score: {suspicious_score}")
                        for warning in warnings:
                            self.memory_output.append(f"    - {warning}")
                        self.memory_output.append("")
                        
                        # Add to detections pane with correct field names
                        detection_data = {
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'type': 'Memory Scan',
                            'name': name,
                            'pid': pid,
                            'severity': 'Medium' if suspicious_score < 5 else 'High',
                            'description': '; '.join(warnings),
                            'process': name,
                            'address': 0,
                            'size': memory_info.rss if memory_info else 0,
                            'confidence': min(suspicious_score * 20, 100),
                            'risk': 'Medium' if suspicious_score < 5 else 'High'
                        }
                        self._add_detection(detection_data)
                    else:
                        self.memory_output.append(f"  ✓  Clean: {name}")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
                    continue
            
            self.memory_output.append(f"\nScan completed!")
            self.memory_output.append(f"Processes scanned: {scanned_count}")
            self.memory_output.append(f"Threats found: {threats_found}")
            
            if threats_found > 0:
                QMessageBox.warning(self, "Threats Found", 
                                  f"Found {threats_found} suspicious processes. Check the Memory Analysis tab for details.")
            else:
                QMessageBox.information(self, "Scan Complete", "No suspicious processes detected.")
                
        except Exception as e:
            self.memory_output.append(f"Error during process scan: {str(e)}")
            QMessageBox.critical(self, "Scan Error", f"Error scanning processes: {str(e)}")
            
    # === PROCESS MONITORING METHODS ===
    
    def _refresh_processes(self):
        """Refresh the process list"""
        self.process_tree.clear()
        self.total_processes_scanned = 0
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status', 'exe']):
                try:
                    proc_info = proc.info
                    self.total_processes_scanned += 1
                    
                    # Create tree item
                    memory_mb = 0
                    try:
                        pmem = proc_info.get('memory_info')
                        if pmem and hasattr(pmem, 'rss'):
                            memory_mb = pmem.rss // (1024*1024)
                    except (AttributeError, TypeError):
                        memory_mb = 0
                        
                    item = QTreeWidgetItem([
                        str(proc_info['pid']),
                        proc_info['name'] or 'Unknown',
                        f"{proc_info.get('cpu_percent', 0):.1f}%",
                        f"{memory_mb} MB",
                        proc_info.get('status', 'Unknown'),
                        proc_info.get('exe', '') or 'Unknown'
                    ])
                    
                    # Color code suspicious processes
                    if proc_info['name'] and proc_info['name'].lower() in ['cmd.exe', 'powershell.exe']:
                        item.setForeground(0, QColor('#ff6666'))
                        
                    self.process_tree.addTopLevelItem(item)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            self.processes_label.setText(f"Processes: {self.total_processes_scanned}")
            
        except Exception as e:
            self.log_output.append(f"Error refreshing processes: {str(e)}")
            
    def _smart_refresh_processes(self):
        """Smart refresh that preserves selection and only updates changes"""
        # Store current selection
        current_item = self.process_tree.currentItem()
        selected_pid = None
        if current_item:
            selected_pid = current_item.text(0)
        
        # Get current process count for quick comparison
        old_count = self.process_tree.topLevelItemCount()
        
        try:
            # Quick check - only do full refresh if process count changed significantly
            current_processes = list(psutil.process_iter(['pid']))
            new_count = len(current_processes)
            
            # If count is similar, skip refresh to reduce UI freezing
            if abs(new_count - old_count) < 3 and old_count > 0:
                return
                
            # Do the refresh
            self._refresh_processes()
            
            # Restore selection if the process still exists
            if selected_pid:
                for i in range(self.process_tree.topLevelItemCount()):
                    item = self.process_tree.topLevelItem(i)
                    if item and item.text(0) == selected_pid:
                        self.process_tree.setCurrentItem(item)
                        break
                        
        except Exception as e:
            # Fallback to normal refresh on error
            self._refresh_processes()
    
    # === FILESYSTEM SCANNER METHODS ===
    
    def _select_all_drives(self):
        """Select all available drives"""
        for checkbox in self.drive_checkboxes.values():
            checkbox.setChecked(True)
    
    def _select_system_drive(self):
        """Select only the system drive (C:)"""
        for letter, checkbox in self.drive_checkboxes.items():
            checkbox.setChecked(letter == 'C')
    
    def _clear_drive_selection(self):
        """Clear all drive selections"""
        for checkbox in self.drive_checkboxes.values():
            checkbox.setChecked(False)
    
    def _start_filesystem_quick_scan(self):
        """Start a quick filesystem scan of critical locations"""
        if self.fs_scanning:
            return
        
        # Quick scan targets common malware locations
        scan_paths = [
            "C:\\Windows\\System32\\",
            "C:\\Windows\\SysWOW64\\",
            "C:\\Program Files\\",
            "C:\\Program Files (x86)\\",
            "C:\\Users\\",
            "C:\\Temp\\",
            "C:\\Windows\\Temp\\"
        ]
        
        if self.scan_browser_artifacts.isChecked():
            scan_paths.extend(self._get_browser_scan_paths())

        self._start_filesystem_scan("quick", scan_paths)

    def _get_browser_scan_paths(self):
        """Return known browser profile/cache locations on Windows."""
        local = os.environ.get('LOCALAPPDATA', '')
        roaming = os.environ.get('APPDATA', '')

        candidates = [
            os.path.join(local, 'Google', 'Chrome', 'User Data'),
            os.path.join(local, 'Microsoft', 'Edge', 'User Data'),
            os.path.join(local, 'BraveSoftware', 'Brave-Browser', 'User Data'),
            os.path.join(roaming, 'Mozilla', 'Firefox', 'Profiles'),
            os.path.join(roaming, 'Opera Software')
        ]

        unique_paths = []
        for path in candidates:
            if path and os.path.isdir(path) and path not in unique_paths:
                unique_paths.append(path)
        return unique_paths

    def _start_browser_deep_clean_scan(self):
        """Start focused browser profile/cache/extension scan."""
        if self.fs_scanning:
            return

        browser_paths = self._get_browser_scan_paths()
        if not browser_paths:
            QMessageBox.information(self, "Browser Scan", "No browser profile paths were found on this host.")
            return

        self._start_filesystem_scan("browser", browser_paths)
    
    def _start_filesystem_full_scan(self):
        """Start a full system scan of all selected drives"""
        if self.fs_scanning:
            return
        
        # Get selected drives
        selected_drives = []
        for letter, checkbox in self.drive_checkboxes.items():
            if checkbox.isChecked():
                selected_drives.append(f"{letter}:\\")
        
        if not selected_drives:
            QMessageBox.warning(self, "No Drives Selected", "Please select at least one drive to scan.")
            return
        
        self._start_filesystem_scan("full", selected_drives)
    
    def _start_filesystem_custom_scan(self):
        """Start a custom filesystem scan with user-defined parameters"""
        if self.fs_scanning:
            return
        
        # Get selected drives
        selected_drives = []
        for letter, checkbox in self.drive_checkboxes.items():
            if checkbox.isChecked():
                selected_drives.append(f"{letter}:\\")
        
        if not selected_drives:
            QMessageBox.warning(self, "No Drives Selected", "Please select at least one drive to scan.")
            return
        
        # For now, same as full scan but with custom options
        self._start_filesystem_scan("custom", selected_drives)
    
    def _start_filesystem_scan(self, scan_type, paths):
        """Start the actual filesystem scanning process"""
        self.fs_scanning = True
        self.fs_files_scanned = 0
        self.fs_threats_found = 0
        
        # Update UI
        self.fs_quick_scan_btn.setEnabled(False)
        self.fs_full_scan_btn.setEnabled(False)
        self.fs_custom_scan_btn.setEnabled(False)
        self.fs_browser_scan_btn.setEnabled(False)
        self.fs_stop_scan_btn.setEnabled(True)
        
        self.fs_current_file_label.setText("Initializing scan...")
        self.fs_files_scanned_label.setText("Files Scanned: 0")
        self.fs_threats_found_label.setText("Threats Found: 0")
        self.fs_scan_speed_label.setText("Speed: 0 files/sec")
        self.fs_progress_bar.setValue(0)
        
        # Create and start scan worker
        self.fs_scan_worker = FilesystemScanWorker(scan_type, paths, self)
        self.fs_scan_worker.progress_updated.connect(self._update_filesystem_progress)
        self.fs_scan_worker.threat_found.connect(self._add_filesystem_threat)
        self.fs_scan_worker.scan_completed.connect(self._filesystem_scan_completed)
        self.fs_scan_worker.start()
    
    def _stop_filesystem_scan(self):
        """Stop the current filesystem scan"""
        if self.fs_scan_worker:
            self.fs_scan_worker.stop()
        self._filesystem_scan_completed()
    
    def _update_filesystem_progress(self, progress, current_file, files_scanned, scan_speed):
        """Update filesystem scan progress display"""
        self.fs_progress_bar.setValue(progress)
        self.fs_current_file_label.setText(f"Scanning: {current_file}")
        self.fs_files_scanned_label.setText(f"Files Scanned: {files_scanned}")
        self.fs_scan_speed_label.setText(f"Speed: {scan_speed} files/sec")
        self.fs_files_scanned = files_scanned
    
    def _add_filesystem_threat(self, threat_info):
        """Add a detected threat to the results table and main detections"""
        self.fs_threats_found += 1
        self.fs_threats_found_label.setText(f"Threats Found: {self.fs_threats_found}")
        
        # Add to filesystem results table
        row = self.fs_results_table.rowCount()
        self.fs_results_table.insertRow(row)
        
        # Format detailed information
        details = threat_info.get('details', '')
        if hasattr(threat_info, 'yara_match') and hasattr(threat_info['yara_match'], 'detailed_info'):
            detailed_info = threat_info['yara_match'].detailed_info
            techniques = ', '.join(detailed_info.get('technique_indicators', []))
            pattern_count = len(detailed_info.get('matched_patterns', []))
            details = f"Techniques: {techniques} | Patterns: {pattern_count} | {detailed_info.get('description', details)}"
        
        items = [
            threat_info.get('name', 'Unknown Threat'),
            threat_info.get('path', ''),
            threat_info.get('type', 'Malware'),
            threat_info.get('severity', 'Medium'),
            threat_info.get('action', 'Detected'),
            details
        ]
        
        for col, item in enumerate(items):
            table_item = QTableWidgetItem(str(item))
            # Color code by severity
            severity = str(threat_info.get('severity', 'Medium')).lower()
            if severity == 'high':
                table_item.setBackground(QColor('#ff4444'))
            elif severity == 'medium':
                table_item.setBackground(QColor('#ff8800'))
            elif severity == 'low':
                table_item.setBackground(QColor('#ffcc00'))
            
            self.fs_results_table.setItem(row, col, table_item)
        
        # Also add to main detections pane for centralized threat management
        from datetime import datetime
        detection_data = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'process': 'Filesystem Scan',
            'pid': 'N/A',
            'threat': f"{threat_info.get('name', 'Unknown')} - {threat_info.get('type', 'Malware')}",
            'severity': threat_info.get('severity', 'Medium'),
            'details': f"File: {threat_info.get('path', '')} | {threat_info.get('details', '')}"
        }
        self._add_detection(detection_data)
        
        # Also add to dedicated scan results tab
        self._add_to_scan_results_tab(threat_info)
        
        # Trigger auto-learning analysis
        self._trigger_auto_learning(threat_info)
    
    def _filesystem_scan_completed(self):
        """Handle filesystem scan completion"""
        self.fs_scanning = False
        
        # Update UI
        self.fs_quick_scan_btn.setEnabled(True)
        self.fs_full_scan_btn.setEnabled(True)
        self.fs_custom_scan_btn.setEnabled(True)
        self.fs_browser_scan_btn.setEnabled(True)
        self.fs_stop_scan_btn.setEnabled(False)
        
        self.fs_current_file_label.setText(f"Scan completed! {self.fs_files_scanned} files scanned, {self.fs_threats_found} threats found.")
        self.fs_progress_bar.setValue(100)
        
        # Update scan results tab summary
        from datetime import datetime
        self.sr_files_scanned_label.setText(f"Files Scanned: {self.fs_files_scanned}")
        self.sr_last_scan_label.setText(f"Last Scan: {datetime.now().strftime('%H:%M:%S')}")
        
        # Determine scan type
        if hasattr(self, 'fs_scan_worker') and self.fs_scan_worker:
            scan_type = getattr(self.fs_scan_worker, 'scan_type', 'Unknown')
            self.sr_scan_type_label.setText(f"Scan Type: {scan_type.title()}")
        
        # Show completion message
        if self.fs_threats_found > 0:
            QMessageBox.warning(self, "Threats Found", 
                              f"Scan completed. Found {self.fs_threats_found} threats.\n\n"
                              f"Check the 'Scan Results' tab for detailed threat management.")
        else:
            QMessageBox.information(self, "Scan Complete", 
                                  f"Filesystem scan completed!\n\nFiles Scanned: {self.fs_files_scanned}\nNo threats detected.")
    
    def _quarantine_selected_files(self):
        """Quarantine selected files from filesystem scan results"""
        selected_rows = set()
        for item in self.fs_results_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select files to quarantine.")
            return
        
        quarantined_count = 0
        protected_count = 0
        skipped_count = 0
        
        for row in sorted(selected_rows, reverse=True):
            file_path = self._resolve_actionable_file_path(self.fs_results_table, row, 1)
            if not file_path:
                skipped_count += 1
                self.log_output.append(f"⚠️ Skipping quarantine for non-file scan result row {row + 1}")
                continue

            # Safety check - protect system files
            if self._is_system_file_protected(file_path):
                protected_count += 1
                continue
            
            try:
                # Perform quarantine
                if self._quarantine_file(file_path):
                    self.fs_results_table.setItem(row, 4, QTableWidgetItem("Quarantined"))
                    self.fs_results_table.item(row, 4).setBackground(QColor('#ffcc00'))
                    quarantined_count += 1
            except Exception as e:
                self.log_output.append(f"Error quarantining {file_path}: {str(e)}")
        
        message = f"Quarantined {quarantined_count} files"
        if protected_count > 0:
            message += f"\n{protected_count} system files were protected from quarantine"
        if skipped_count > 0:
            message += f"\n{skipped_count} entries were skipped because they do not reference filesystem paths"
        QMessageBox.information(self, "Quarantine Complete", message)
    
    def _delete_selected_files(self):
        """Delete selected files from filesystem scan results"""
        selected_rows = set()
        for item in self.fs_results_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select files to delete.")
            return
        
        reply = QMessageBox.question(
            self, 
            "Confirm Deletion", 
            f"Are you sure you want to permanently delete {len(selected_rows)} files?\n\nThis action cannot be undone!",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            deleted_count = 0
            protected_count = 0
            skipped_count = 0
            
            for row in sorted(selected_rows, reverse=True):
                file_path = self._resolve_actionable_file_path(self.fs_results_table, row, 1)
                if not file_path:
                    skipped_count += 1
                    self.log_output.append(f"⚠️ Skipping delete for non-file scan result row {row + 1}")
                    continue

                # Safety check - protect system files
                if self._is_system_file_protected(file_path):
                    protected_count += 1
                    continue
                
                try:
                    import os
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        self.fs_results_table.setItem(row, 4, QTableWidgetItem("Deleted"))
                        self.fs_results_table.item(row, 4).setBackground(QColor('#cc0000'))
                        deleted_count += 1
                except Exception as e:
                    self.log_output.append(f"Error deleting {file_path}: {str(e)}")
            
            message = f"Deleted {deleted_count} files"
            if protected_count > 0:
                message += f"\n{protected_count} system files were protected from deletion"
            if skipped_count > 0:
                message += f"\n{skipped_count} entries were skipped because they do not reference filesystem paths"
            QMessageBox.information(self, "Deletion Complete", message)
    
    def _export_scan_results(self):
        """Export scan results to a file"""
        if self.fs_results_table.rowCount() == 0:
            QMessageBox.warning(self, "No Results", "No scan results to export.")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.csv"
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                import csv
                writer = csv.writer(csvfile)
                
                # Write headers
                headers = []
                for col in range(self.fs_results_table.columnCount()):
                    headers.append(self.fs_results_table.horizontalHeaderItem(col).text())
                writer.writerow(headers)
                
                # Write data
                for row in range(self.fs_results_table.rowCount()):
                    row_data = []
                    for col in range(self.fs_results_table.columnCount()):
                        item = self.fs_results_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)
            
            QMessageBox.information(self, "Export Complete", f"Results exported to {filename}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")
            
    def _terminate_process(self):
        """Terminate selected process"""
        current_item = self.process_tree.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Error", "Please select a process to terminate")
            return
            
        pid = int(current_item.text(0))
        name = current_item.text(1)
        
        # Check if it's a critical process
        if name.lower() in self.critical_processes:
            QMessageBox.warning(self, "Warning", f"Cannot terminate critical system process: {name}")
            return
            
        reply = QMessageBox.question(self, "Confirm", f"Terminate process {name} (PID: {pid})?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                self.log_output.append(f"Terminated process: {name} (PID: {pid})")
                self._refresh_processes()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to terminate process: {str(e)}")
                
    def _suspend_process(self):
        """Suspend selected process"""
        current_item = self.process_tree.currentItem()
        if not current_item:
            QMessageBox.warning(self, "Error", "Please select a process to suspend")
            return
            
        pid = int(current_item.text(0))
        name = current_item.text(1)
        
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            self.log_output.append(f"Suspended process: {name} (PID: {pid})")
            self._refresh_processes()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to suspend process: {str(e)}")
            
    # === YARA METHODS ===
    
    def _compile_yara(self):
        """Compile YARA rules"""
        if not self.yara_manager:
            self.yara_output.append("YARA manager not available")
            return
            
        try:
            self.yara_output.append("Compiling YARA rules...")
            self.compiled_rules = self.yara_manager.compile_combined_rules()
            
            if self.compiled_rules:
                self.yara_output.append("YARA rules compiled successfully")
                self.rules_loaded = True
                self.rules_label.setText("Rules: Loaded")
            else:
                self.yara_output.append("YARA rules compilation failed")
                self.rules_loaded = False
                self.rules_label.setText("Rules: Failed")
                
        except Exception as e:
            self.yara_output.append(f"YARA compile error: {str(e)}")
            
    def _reload_yara(self):
        """Reload YARA rules"""
        if not self.yara_manager:
            self.yara_output.append("YARA manager not available")
            return
            
        try:
            self.yara_output.append("Reloading YARA rules...")
            self.yara_manager.fetch_all_rules()
            self.yara_manager.create_missing_rules()
            self._compile_yara()
        except Exception as e:
            self.yara_output.append(f"YARA reload error: {str(e)}")
            
    def _test_yara(self):
        """Test YARA rules"""
        if not self.compiled_rules:
            self.yara_output.append("No compiled rules available for testing")
            return
            
        self.yara_output.append("YARA rules are compiled and ready for use")
        
    # === PROTECTION METHODS ===
    
    def enable_protection(self):
        """Enable real-time protection"""
        self.monitoring_active = True
        self.status_label.setText("Protected")
        self.status_label.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 14px;")
        self.log_output.append("Real-time protection enabled")
        
    def disable_protection(self):
        """Disable real-time protection"""
        self.monitoring_active = False
        self.status_label.setText("Unprotected")
        self.status_label.setStyleSheet("color: #ff6600; font-weight: bold; font-size: 14px;")
        self.log_output.append("Real-time protection disabled")
        
    def quarantine_selected(self):
        """Quarantine selected item"""
        try:
            if hasattr(self, 'detections_table') and hasattr(self, 'detections_tab') and self.tabs.currentWidget() is self.detections_tab:
                self._quarantine_selected_detections()
                return

            if hasattr(self, 'scan_results_table') and self._is_scan_results_tab_active():
                self._quarantine_selected_results()
                return

            if hasattr(self, 'fs_results_table') and self._is_filesystem_tab_active():
                self._quarantine_selected_files()
                return

            # Fallback: use scan results if there is a selection there
            if hasattr(self, 'scan_results_table') and self.scan_results_table.selectedItems():
                self._quarantine_selected_results()
                return

            if hasattr(self, 'fs_results_table') and self.fs_results_table.selectedItems():
                self._quarantine_selected_files()
                return

            if hasattr(self, 'detections_table') and self.detections_table.selectedItems():
                self._quarantine_selected_detections()
                return

            QMessageBox.information(self, "No Selection", "Select a threat in Detections, Scan Results, or Filesystem Results to quarantine.")
        except Exception as e:
            self.log_output.append(f"❌ Quarantine selection error: {str(e)}")

    def restore_selected(self):
        """Restore selected item"""
        self._restore_quarantined()
        
    # === QUARANTINE METHODS ===
    
    def _refresh_quarantine(self):
        """Refresh quarantine list"""
        self.quarantine_table.setRowCount(0)
        
        try:
            quarantine_dir = Path("quarantine")
            if not quarantine_dir.exists():
                self.log_output.append("Quarantine directory does not exist")
                return
            
            # Load quarantine log if available
            quarantine_log_path = quarantine_dir / "quarantine_log.json"
            log_data = {}
            if quarantine_log_path.exists():
                try:
                    import json
                    with open(quarantine_log_path, 'r') as f:
                        log_entries = json.load(f)
                        log_data = {entry['quarantine_path']: entry for entry in log_entries}
                except Exception as e:
                    self.log_output.append(f"Warning: Could not load quarantine log: {str(e)}")
            
            for item in quarantine_dir.iterdir():
                if item.is_file() and item.name != "quarantine_log.json":
                    row = self.quarantine_table.rowCount()
                    self.quarantine_table.insertRow(row)
                    
                    # Get info from log or use defaults
                    entry = log_data.get(str(item), {})
                    original_path = entry.get('original_path', 'Unknown')
                    threat_type = entry.get('threat_type', 'Unknown')
                    
                    self.quarantine_table.setItem(row, 0, QTableWidgetItem(item.name))
                    self.quarantine_table.setItem(row, 1, QTableWidgetItem(original_path))
                    self.quarantine_table.setItem(row, 2, QTableWidgetItem(
                        datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    ))
                    self.quarantine_table.setItem(row, 3, QTableWidgetItem(threat_type))
                    
        except Exception as e:
            self.log_output.append(f"Error refreshing quarantine: {str(e)}")
            
    def _restore_quarantined(self):
        """Restore quarantined file"""
        selected_rows = set()
        for item in self.quarantine_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select files to restore.")
            return
        
        restored_count = 0
        quarantine_dir = Path("quarantine")
        quarantine_log_path = quarantine_dir / "quarantine_log.json"
        
        # Load quarantine log
        log_entries = []
        if quarantine_log_path.exists():
            try:
                import json
                with open(quarantine_log_path, 'r') as f:
                    log_entries = json.load(f)
            except Exception as e:
                self.log_output.append(f"Error loading quarantine log: {str(e)}")
                return
        
        for row in sorted(selected_rows, reverse=True):
            quarantine_filename = self.quarantine_table.item(row, 0).text()
            quarantine_path = quarantine_dir / quarantine_filename
            
            # Find original path from log
            original_path = None
            for entry in log_entries:
                if entry.get('quarantine_path') == str(quarantine_path):
                    original_path = entry.get('original_path')
                    break
            
            if not original_path:
                self.log_output.append(f"⚠️ Could not find original path for {quarantine_filename}")
                continue
            
            try:
                import shutil
                import os
                
                if quarantine_path.exists():
                    # Restore to original location
                    os.makedirs(os.path.dirname(original_path), exist_ok=True)
                    shutil.move(str(quarantine_path), original_path)
                    
                    # Remove from log
                    log_entries = [e for e in log_entries if e.get('quarantine_path') != str(quarantine_path)]
                    
                    self.quarantine_table.removeRow(row)
                    restored_count += 1
                    self.log_output.append(f"✓ Restored: {original_path}")
            except Exception as e:
                self.log_output.append(f"Error restoring {quarantine_filename}: {str(e)}")
        
        # Save updated log
        if quarantine_log_path.exists():
            try:
                import json
                with open(quarantine_log_path, 'w') as f:
                    json.dump(log_entries, f, indent=2)
            except Exception as e:
                self.log_output.append(f"Warning: Could not update quarantine log: {str(e)}")
        
        QMessageBox.information(self, "Restore Complete", f"Restored {restored_count} files.")
         
    def _delete_quarantined(self):
        """Permanently delete quarantined file"""
        selected_rows = set()
        for item in self.quarantine_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select files to delete.")
            return
        
        reply = QMessageBox.question(
            self, "Confirm Permanent Deletion",
            f"Are you sure you want to permanently delete {len(selected_rows)} quarantined files?\n\nThis action cannot be undone!",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        deleted_count = 0
        quarantine_dir = Path("quarantine")
        quarantine_log_path = quarantine_dir / "quarantine_log.json"
        
        # Load quarantine log
        log_entries = []
        if quarantine_log_path.exists():
            try:
                import json
                with open(quarantine_log_path, 'r') as f:
                    log_entries = json.load(f)
            except Exception as e:
                self.log_output.append(f"Error loading quarantine log: {str(e)}")
                return
        
        for row in sorted(selected_rows, reverse=True):
            quarantine_filename = self.quarantine_table.item(row, 0).text()
            quarantine_path = quarantine_dir / quarantine_filename
            
            try:
                import os
                if quarantine_path.exists():
                    os.remove(quarantine_path)
                    
                    # Remove from log
                    log_entries = [e for e in log_entries if e.get('quarantine_path') != str(quarantine_path)]
                    
                    self.quarantine_table.removeRow(row)
                    deleted_count += 1
                    self.log_output.append(f"🗑️ Permanently deleted: {quarantine_filename}")
            except Exception as e:
                self.log_output.append(f"Error deleting {quarantine_filename}: {str(e)}")
        
        # Save updated log
        if quarantine_log_path.exists():
            try:
                import json
                with open(quarantine_log_path, 'w') as f:
                    json.dump(log_entries, f, indent=2)
            except Exception as e:
                self.log_output.append(f"Warning: Could not update quarantine log: {str(e)}")
        
        QMessageBox.information(self, "Deletion Complete", f"Permanently deleted {deleted_count} files.")
        
    # === DETECTION METHODS ===
    
    def _clear_detections(self):
        """Clear all detections"""
        self.detections.clear()
        self.detections_table.setRowCount(0)
        self.threats_found = 0
        self.threats_label.setText("Threats: 0")
        
    def _export_detections(self):
        """Export detections to file"""
        if not self.detections:
            QMessageBox.information(self, "Info", "No detections to export")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Detections", "detections.csv", "CSV Files (*.csv)")
        if file_path:
            try:
                import csv
                with open(file_path, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=['timestamp', 'type', 'name', 'pid', 'severity', 'description'])
                    writer.writeheader()
                    for detection in self.detections:
                        writer.writerow(detection)
                QMessageBox.information(self, "Success", f"Detections exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export detections: {str(e)}")
                
    # === LOG METHODS ===
    
    def _clear_logs(self):
        """Clear log output"""
        self.log_output.clear()
        
    def _save_logs(self):
        """Save logs to file"""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Logs", "orbital_station.log", "Log Files (*.log)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.log_output.toPlainText())
                QMessageBox.information(self, "Success", f"Logs saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save logs: {str(e)}")
                
    # === INITIALIZATION METHODS ===
    
    def initial_protection(self):
        """Initialize protection systems"""
        try:
            self.log_output.append("Initializing protection systems...")
            
            # Update status based on components
            status_parts = []
            if self.rules_loaded:
                status_parts.append("YARA")
                self.rules_label.setText("Rules: Loaded")
            else:
                self.rules_label.setText("Rules: Failed")
                
            if self.memory_scanner:
                status_parts.append("Memory")
                
            if self.malware_scanner:
                status_parts.append("Scanner")
                
            if status_parts:
                self.status_label.setText(f"Protected ({', '.join(status_parts)})")
                self.status_label.setStyleSheet("color: #00ff00; font-weight: bold; font-size: 14px;")
            else:
                self.status_label.setText("Limited Protection")
                self.status_label.setStyleSheet("color: #ffcc00; font-weight: bold; font-size: 14px;")
                
            self.monitoring_active = True
            self.log_output.append("Protection systems initialized")
            
            # Initial process refresh
            self._refresh_processes()
            
        except Exception as e:
            self.status_label.setText("Error")
            self.status_label.setStyleSheet("color: #ff0000; font-weight: bold; font-size: 14px;")
            self.log_output.append(f"Protection initialization error: {str(e)}")

    # === SCAN RESULTS TAB METHODS ===
    
    def _add_to_scan_results(self, detection):
        """Add detection to scan results table (converts detection format to scan results format)"""
        threat_info = {
            'name': detection.get('name', detection.get('type', 'Unknown')),
            'path': detection.get('path', f"PID: {detection.get('pid', 'N/A')}"),
            'type': detection.get('type', 'Detection'),
            'severity': detection.get('severity', 'Medium'),
            'action': 'Detected',
            'details': detection.get('description', detection.get('details', ''))
        }
        self._add_to_scan_results_tab(threat_info)
    
    def _add_to_scan_results_tab(self, threat_info):
        """Add threat to the dedicated scan results tab"""
        row = self.scan_results_table.rowCount()
        self.scan_results_table.insertRow(row)
        
        items = [
            threat_info.get('name', 'Unknown Threat'),
            threat_info.get('path', ''),
            threat_info.get('type', 'Malware'),
            threat_info.get('severity', 'Medium'),
            threat_info.get('action', 'Detected'),
            threat_info.get('details', ''),
            'Active'  # Status
        ]
        
        for col, item in enumerate(items):
            table_item = QTableWidgetItem(str(item))
            # Color code by severity
            severity = str(threat_info.get('severity', 'Medium')).lower()
            if severity == 'high':
                table_item.setBackground(QColor('#ff4444'))
            elif severity == 'medium':
                table_item.setBackground(QColor('#ff8800'))
            elif severity == 'low':
                table_item.setBackground(QColor('#ffcc00'))
            
            self.scan_results_table.setItem(row, col, table_item)
        
        # Update summary
        total_threats = self.scan_results_table.rowCount()
        self.sr_threats_found_label.setText(f"Threats Found: {total_threats}")
    
    def _update_threat_details(self):
        """Update threat details when selection changes"""
        current_row = self.scan_results_table.currentRow()
        if current_row >= 0:
            # Get threat details from the selected row
            name_item = self.scan_results_table.item(current_row, 0)
            path_item = self.scan_results_table.item(current_row, 1)
            type_item = self.scan_results_table.item(current_row, 2)
            severity_item = self.scan_results_table.item(current_row, 3)
            details_item = self.scan_results_table.item(current_row, 5)

            name = name_item.text() if name_item else "Unknown"
            path = path_item.text() if path_item else "Unknown"
            threat_type = type_item.text() if type_item else "Unknown"
            severity = severity_item.text() if severity_item else "Unknown"
            details = details_item.text() if details_item else ""
            
            # Format detailed information
            detail_text = f"""Threat Name: {name}
            File Path: {path}
            Type: {threat_type}
            Severity: {severity}
            Details: {details}

            Recommended Actions:
            - High Severity: Immediate quarantine or deletion
            - Medium Severity: Review and quarantine if suspicious
            - Low Severity: Monitor or whitelist if false positive
            """
            self.threat_details_text.setText(detail_text)
        else:
            self.threat_details_text.clear()
    
    def _quarantine_selected_results(self):
        """Quarantine selected threats with safety checks"""
        selected_rows = set()
        for item in self.scan_results_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select threats to quarantine")
            return
        
        quarantined_count = 0
        protected_count = 0
        skipped_count = 0
        
        for row in sorted(selected_rows, reverse=True):
            file_path = self._resolve_actionable_file_path(self.scan_results_table, row, 1)
            if not file_path:
                skipped_count += 1
                self.log_output.append(f"⚠️ Skipping quarantine for non-file threat row {row + 1}")
                continue
            self.threat_name = self.scan_results_table.item(row, 0).text()

            # Safety check - protect system files
            if self._is_system_file_protected(file_path):
                protected_count += 1
                continue
            
            try:
                # Perform quarantine
                if self._quarantine_file(file_path):
                    # Update status in table
                    self.scan_results_table.setItem(row, 6, QTableWidgetItem("Quarantined"))
                    self.scan_results_table.item(row, 6).setBackground(QColor('#ffcc00'))
                    quarantined_count += 1
                    
            except Exception as e:
                self.log_output.append(f"Error quarantining {file_path}: {str(e)}")
        
        # Show results
        message = f"Quarantined {quarantined_count} threats"
        if protected_count > 0:
            message += f"\n{protected_count} system files were protected from quarantine"
        if skipped_count > 0:
            message += f"\n{skipped_count} entries were skipped because they do not reference filesystem paths"

        QMessageBox.information(self, "Quarantine Complete", message)
    
    def _delete_selected_results(self):
        """Delete selected threats with safety checks"""
        selected_rows = set()
        for item in self.scan_results_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select threats to delete")
            return
        
        # Confirmation dialog
        reply = QMessageBox.question(
            self, "Confirm Deletion", 
            f"Are you sure you want to permanently delete {len(selected_rows)} selected files?\n\n"
            "This action cannot be undone!",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
        
        deleted_count = 0
        protected_count = 0
        skipped_count = 0
        
        for row in sorted(selected_rows, reverse=True):
            file_path = self._resolve_actionable_file_path(self.scan_results_table, row, 1)
            if not file_path:
                skipped_count += 1
                self.log_output.append(f"⚠️ Skipping delete for non-file threat row {row + 1}")
                continue

            is_system_file_protected = self._is_system_file_protected(file_path)
            # Safety check - protect system files
            if is_system_file_protected:
                protected_count += 1
                continue
            
            try:
                import os
                if os.path.exists(file_path):
                    os.remove(file_path)
                    # Update status in table
                    self.scan_results_table.setItem(row, 6, QTableWidgetItem("Deleted"))
                    self.scan_results_table.item(row, 6).setBackground(QColor('#cc0000'))
                    deleted_count += 1
                    
            except Exception as e:
                self.log_output.append(f"Error deleting {file_path}: {str(e)}")
        
        # Show results
        message = f"Deleted {deleted_count} threats"
        if protected_count > 0:
            message += f"\n{protected_count} system files were protected from deletion"
        if skipped_count > 0:
            message += f"\n{skipped_count} entries were skipped because they do not reference filesystem paths"
        
        QMessageBox.information(self, "Deletion Complete", message)
    
    def delete_selected(self):
        """Delete selected item from the currently active results tab."""
        try:
            if hasattr(self, 'detections_table') and hasattr(self, 'detections_tab') and self.tabs.currentWidget() is self.detections_tab:
                self._delete_selected_detections()
                return

            if hasattr(self, 'scan_results_table') and self._is_scan_results_tab_active():
                self._delete_selected_results()
                return

            if hasattr(self, 'fs_results_table') and self._is_filesystem_tab_active():
                self._delete_selected_files()
                return

            if hasattr(self, 'detections_table') and self.detections_table.selectedItems():
                self._delete_selected_detections()
                return

            if hasattr(self, 'scan_results_table') and self.scan_results_table.selectedItems():
                self._delete_selected_results()
                return

            if hasattr(self, 'fs_results_table') and self.fs_results_table.selectedItems():
                self._delete_selected_files()
                return

            QMessageBox.information(self, "No Selection", "Select a threat in Detections, Scan Results, or Filesystem Results to delete.")
        except Exception as e:
            self.log_output.append(f"❌ Delete selection error: {str(e)}")

    def _whitelist_selected_results(self):
        """Whitelist selected files to prevent future detection"""
        selected_rows = set()
        for item in self.scan_results_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select threats to whitelist")
            return
        
        whitelisted_count = 0
        
        for row in sorted(selected_rows, reverse=True):
            file_path = self.scan_results_table.item(row, 1).text()
            
            try:
                # Add to whitelist (implement whitelist functionality)
                # For now, just update the status
                self.scan_results_table.setItem(row, 6, QTableWidgetItem("Whitelisted"))
                self.scan_results_table.item(row, 6).setBackground(QColor('#00aa00'))
                whitelisted_count += 1
                    
            except Exception as e:
                self.log_output.append(f"Error whitelisting {file_path}: {str(e)}")
        
        QMessageBox.information(self, "Whitelist Complete", f"Whitelisted {whitelisted_count} files")
    
    def _export_scan_results(self):
        """Export scan results to CSV"""
        from datetime import datetime
        import csv
        import os
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_results_{timestamp}.csv"
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write header
                headers = []
                for col in range(self.scan_results_table.columnCount()):
                    headers.append(self.scan_results_table.horizontalHeaderItem(col).text())
                writer.writerow(headers)
                
                # Write data
                for row in range(self.scan_results_table.rowCount()):
                    row_data = []
                    for col in range(self.scan_results_table.columnCount()):
                        item = self.scan_results_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    writer.writerow(row_data)
            
            QMessageBox.information(self, "Export Complete", f"Scan results exported to {filename}")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Error exporting results: {str(e)}")
    
    def _clear_scan_results(self):
        """Clear all scan results"""
        reply = QMessageBox.question(
            self, "Clear Results", 
            "Are you sure you want to clear all scan results?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.scan_results_table.setRowCount(0)
            self.threat_details_text.clear()
            self.sr_threats_found_label.setText("Threats Found: 0")
            self.sr_files_scanned_label.setText("Files Scanned: 0")
    
    def _trigger_auto_learning(self, threat_info):
        """Trigger auto-learning analysis for detected threats"""
        try:
            if not self.yara_manager:
                return
            
            # Prepare detection data for analysis
            detection_data = {
                'process': threat_info.get('name', 'Unknown'),
                'file_path': threat_info.get('path', ''),
                'threat': threat_info.get('type', 'Unknown'),
                'severity': threat_info.get('severity', 'Medium'),
                'details': threat_info.get('details', '')
            }
            
            # Log the auto-learning attempt
            self.log_output.append(f"🧠 Auto-learning analysis triggered for: {detection_data['process']}")
            
            # Run analysis in background to avoid UI freezing
            import threading
            def run_analysis():
                try:
                    # Create Steam whitelist immediately if it's a Steam process
                    if 'steam' in detection_data['process'].lower():
                        self.yara_manager.create_steam_whitelist()
                        # Use QTimer to safely update UI from main thread
                        QTimer.singleShot(0, lambda: self.log_output.append("🎮 Applied Steam-specific whitelist rules"))
                    
                    # Run full analysis
                    success = self.yara_manager.analyze_detection_with_shellcode_magic(detection_data)
                    
                    if success:
                        # Use QTimer to safely update UI from main thread
                        QTimer.singleShot(0, lambda: self.log_output.append(f"✅ Auto-learning completed for: {detection_data['process']}"))
                    else:
                        # Use QTimer to safely update UI from main thread  
                        QTimer.singleShot(0, lambda: self.log_output.append(f"⚠️ Auto-learning failed for: {detection_data['process']}"))
                        
                except Exception as e:
                    # Use QTimer to safely update UI from main thread
                    QTimer.singleShot(0, lambda: self.log_output.append(f"❌ Auto-learning error: {str(e)}"))
            
            # Start analysis thread
            analysis_thread = threading.Thread(target=run_analysis, daemon=True)
            analysis_thread.start()
            
        except Exception as e:
            self.log_output.append(f"❌ Auto-learning trigger error: {str(e)}")

    def remove_infected_file(self):
        """Remove infected file from filesystem"""
        try:
            if self._is_scan_results_tab_active():
                current_row = self.scan_results_table.currentRow()
                if current_row < 0:
                    QMessageBox.warning(self, "No Selection", "Please select a detection to remove the file.")
                    return
                
                file_path_item = self.scan_results_table.item(current_row, 1)  # Path column
                if not file_path_item:
                    return
                
                file_path = file_path_item.text()
                
                # Confirm deletion
                reply = QMessageBox.question(self, "Confirm Deletion", 
                                           f"Are you sure you want to permanently delete:\n{file_path}",
                                           QMessageBox.Yes | QMessageBox.No)
                
                if reply == QMessageBox.Yes:
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                            self.log_output.append(f"🗑️ Successfully removed infected file: {file_path}")
                            # Remove from table
                            self.scan_results_table.removeRow(current_row)
                        else:
                            self.log_output.append(f"⚠️ File not found: {file_path}")
                    except PermissionError:
                        self.log_output.append(f"❌ Permission denied removing file: {file_path}")
                        QMessageBox.critical(self, "Permission Error", 
                                           f"Unable to remove file. Administrator rights may be required.")
                    except Exception as e:
                        self.log_output.append(f"❌ Error removing file {file_path}: {str(e)}")
                        QMessageBox.critical(self, "Error", f"Failed to remove file: {str(e)}")
            elif self._is_filesystem_tab_active():
                current_row = self.fs_results_table.currentRow()
                if current_row < 0:
                    QMessageBox.warning(self, "No Selection", "Please select a detection to remove the file.")
                    return

                path_item = self.fs_results_table.item(current_row, 1)  # Path column
                if not path_item:
                    return
                    
                file_path = path_item.text()
                
                # Confirm deletion
                reply = QMessageBox.question(self, "Confirm Deletion", 
                                           f"Are you sure you want to permanently delete:\n{file_path}",
                                           QMessageBox.Yes | QMessageBox.No)
                
                if reply == QMessageBox.Yes:
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                            self.log_output.append(f"🗑️ Successfully removed infected file: {file_path}")
                            # Remove from table
                            self.fs_results_table.removeRow(current_row)
                        else:
                            self.log_output.append(f"⚠️ File not found: {file_path}")
                    except PermissionError:
                        self.log_output.append(f"❌ Permission denied removing file: {file_path}")
                        QMessageBox.critical(self, "Permission Error", 
                                           f"Unable to remove file. Administrator rights may be required.")
                    except Exception as e:
                        self.log_output.append(f"❌ Error removing file {file_path}: {str(e)}")
                        QMessageBox.critical(self, "Error", f"Failed to remove file: {str(e)}")
                        
            elif self.scan_results_table.selectedItems():
                self._delete_selected_results()
            elif self.fs_results_table.selectedItems():
                self._delete_selected_files()
            else:
                QMessageBox.warning(self, "No Selection", "Select a threat in Scan Results or System Scanner to remove.")

        except Exception as e:
            self.log_output.append(f"❌ Remove file error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Remove file operation failed: {str(e)}")

    def _quarantine_file(self, file_path):
        """Quarantine a file - move to quarantine directory with metadata"""
        try:
            import shutil
            import uuid
            import json

            file_path = str(file_path).strip()
            if not file_path:
                self.log_output.append("⚠️ Empty file path provided for quarantine")
                return False

            file_path_lower = file_path.lower()
            if file_path_lower.startswith('pid:') or file_path_lower.startswith('memory:') or file_path_lower in ('n/a', 'na'):
                self.log_output.append(f"⚠️ Non-filesystem path cannot be quarantined: {file_path}")
                return False
            
            # Ensure quarantine directory exists
            quarantine_dir = Path("quarantine")
            quarantine_dir.mkdir(exist_ok=True)
            
            if not os.path.exists(file_path):
                self.log_output.append(f"⚠️ File not found for quarantine: {file_path}")
                return False
            
            # Generate unique quarantine filename
            file_ext = Path(file_path).suffix
            quarantine_name = f"quarantined_{uuid.uuid4().hex[:8]}{file_ext}"
            quarantine_path = quarantine_dir / quarantine_name
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Create quarantine log entry
            log_entry = {
                'original_path': file_path,
                'quarantine_path': str(quarantine_path),
                'timestamp': datetime.now().isoformat(),
                'source': 'Orbital Station Scanner'
            }
            
            # Save quarantine log
            quarantine_log = quarantine_dir / "quarantine_log.json"
            try:
                if quarantine_log.exists():
                    with open(quarantine_log, 'r') as f:
                        log_data = json.load(f)
                else:
                    log_data = []
                
                log_data.append(log_entry)
                
                with open(quarantine_log, 'w') as f:
                    json.dump(log_data, f, indent=2)
            except Exception as log_error:
                self.log_output.append(f"⚠️ Warning: Could not update quarantine log: {log_error}")
            
            self.log_output.append(f"🔒 Successfully quarantined file: {file_path} -> {quarantine_path}")
            return True
            
        except PermissionError:
            self.log_output.append(f"❌ Permission denied quarantining file: {file_path}")
            return False
        except Exception as e:
            self.log_output.append(f"❌ Error quarantining file {file_path}: {str(e)}")
            return False

    def quarantine_file(self):
        """Quarantine selected file"""
        try:
            if self._is_scan_results_tab_active():
                current_row = self.scan_results_table.currentRow()
                if current_row < 0:
                    QMessageBox.warning(self, "No Selection", "Please select a detection to quarantine the file.")
                    return
                
                file_path_item = self.scan_results_table.item(current_row, 1)  # Path column
                if not file_path_item:
                    return
                
                file_path = file_path_item.text()
                
                # Confirm quarantine
                reply = QMessageBox.question(self, "Confirm Quarantine", 
                                           f"Quarantine this file:\n{file_path}",
                                           QMessageBox.Yes | QMessageBox.No)
                
                if reply == QMessageBox.Yes:
                    if self._quarantine_file(file_path):
                        # Update status in table
                        self.scan_results_table.setItem(current_row, 6, QTableWidgetItem("Quarantined"))
                        self.scan_results_table.item(current_row, 6).setBackground(QColor('#ffcc00'))
            elif self._is_filesystem_tab_active():
                current_row = self.fs_results_table.currentRow()
                if current_row < 0:
                    QMessageBox.warning(self, "No Selection", "Please select a detection to quarantine the file.")
                    return

                path_item = self.fs_results_table.item(current_row, 1)  # Path column
                if not path_item:
                    return
                    
                file_path = path_item.text()
                
                # Confirm quarantine
                reply = QMessageBox.question(self, "Confirm Quarantine", 
                                           f"Quarantine this file:\n{file_path}",
                                           QMessageBox.Yes | QMessageBox.No)
                
                if reply == QMessageBox.Yes:
                    if self._quarantine_file(file_path):
                        # Update status in table
                        self.fs_results_table.setItem(current_row, 4, QTableWidgetItem("Quarantined"))
                        self.fs_results_table.item(current_row, 4).setBackground(QColor('#ffcc00'))
            elif self.scan_results_table.selectedItems():
                self._quarantine_selected_results()
            elif self.fs_results_table.selectedItems():
                self._quarantine_selected_files()
            else:
                QMessageBox.warning(self, "No Selection", "Select a threat in Scan Results or System Scanner to quarantine.")
                        
        except Exception as e:
            self.log_output.append(f"❌ Quarantine file error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Quarantine operation failed: {str(e)}")

    # Shellcode Detection Methods
    def _scan_memory_for_shellcode(self):
        """Scan system memory for shellcode patterns"""
        try:
            from ShellCodeMagic import ShellcodeDetector, ShellCodeTome
            
            self.log_output.append("🔍 Starting memory shellcode scan...")
            
            # Initialize shellcode detector
            detector = ShellcodeDetector()
            tome = ShellCodeTome()
            
            # Get sensitivity setting
            sensitivity = self.shellcode_sensitivity.currentText().lower()
            
            # Clear previous results
            self.shellcode_table.setRowCount(0)
            
            # Use the actual memory scanner for proper detection
            import psutil
            from Memory import MemoryScanner
            
            # Use existing memory scanner if available, otherwise create one
            if hasattr(self, 'memory_scanner') and self.memory_scanner:
                memory_scanner = self.memory_scanner
                self.log_output.append("Using existing memory scanner with shared YARA rules...")
            else:
                memory_scanner = MemoryScanner()
                self.log_output.append("Created new memory scanner...")
            scan_count = 0
            detection_count = 0
            
            # Protected process list - more comprehensive than the basic check
            protected_processes = [
                'System', 'Registry', 'Idle', 'smss.exe', 'csrss.exe', 
                'wininit.exe', 'services.exe', 'lsass.exe', 'winlogon.exe',
                'System Idle Process', 'dwm.exe', 'explorer.exe'
            ]
            
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    name = proc.info['name']
                    pid = proc.info['pid']
                    
                    # Skip protected/system processes
                    if name in protected_processes:
                        continue
                        
                    # Skip very low PIDs (usually system processes)
                    if pid < 100 and pid not in []:  # Allow specific low PIDs if needed
                        continue
                        
                    # Skip processes with very high memory usage (likely system processes)
                    try:
                        memory_info = proc.info.get('memory_info')
                        if memory_info and memory_info.rss > 1024 * 1024 * 500:  # 500MB+
                            continue
                    except:
                        pass
                    
                    scan_count += 1
                    
                    # Update status
                    self.log_output.append(f"📊 Scanning process: {name} (PID: {pid})")
                    if hasattr(self, 'scan_status_text'):
                        self.scan_status_text.append(f"🔍 Scanning: {name} (PID: {pid})")
                    
                    # Perform actual memory scanning with enhanced mode
                    detections = memory_scanner.scan_process_memory_enhanced(pid)
                    
                    if detections:
                        for detection in detections:
                            self._add_shellcode_detection(detection)
                            self._add_live_detection(detection)
                            detection_count += 1
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                    continue
                except Exception as e:
                    self.log_output.append(f"⚠️ Error scanning {proc.info.get('name', 'Unknown')}: {str(e)}")
                    
            self.log_output.append(f"✅ Memory scan completed - {scan_count} processes scanned, {detection_count} detections found")
            
        except ImportError:
            QMessageBox.warning(self, "Module Error", "ShellCodeMagic module not available")
        except Exception as e:
            self.log_output.append(f"❌ Memory scan error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Memory scan failed: {str(e)}")

    def _scan_process_for_shellcode(self):
        """Scan selected process for shellcode"""
        try:
            import psutil
            # Get list of running processes for selection
            processes = []
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    processes.append(f"{proc.info['name']} (PID: {proc.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if not processes:
                QMessageBox.warning(self, "No Processes", "No processes found to scan.")
                return
                
            # Show dialog to select process
            process_selection, ok = QInputDialog.getItem(self, "Select Process", 
                                                       "Choose a process to scan:", 
                                                       processes, 0, False)
            if not ok:
                return
                
            # Extract PID and name from selection
            import re
            match = re.search(r'(.*) \(PID: (\d+)\)', process_selection)
            if not match:
                return
                
            name = match.group(1)
            pid = int(match.group(2))
            
            self.log_output.append(f"🔍 Scanning process {name} (PID: {pid}) for shellcode...")
            
            from Memory import MemoryScanner
            memory_scanner = MemoryScanner()
            
            # Perform enhanced process memory scan with force reading
            detections = memory_scanner.scan_process_memory_enhanced(pid)
            
            for detection in detections:
                self._add_shellcode_detection(detection)
                self._add_live_detection(detection)
                
            self.log_output.append(f"✅ Process {name} shellcode scan completed")
            
        except Exception as e:
            self.log_output.append(f"❌ Process scan error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Process scan failed: {str(e)}")

    def _deep_shellcode_scan(self):
        """Perform deep system-wide shellcode scan"""
        try:
            reply = QMessageBox.question(self, "Deep Scan Warning", 
                                       "Deep shellcode scan may take several minutes and use significant resources.\n\nContinue?",
                                       QMessageBox.Yes | QMessageBox.No)
            
            if reply != QMessageBox.Yes:
                return
                
            self.log_output.append("🚨 Starting deep shellcode scan...")
            
            # Clear previous results
            self.shellcode_table.setRowCount(0)

            # Use real enhanced memory scanner pipeline
            from Memory import MemoryScanner
            memory_scanner = self.memory_scanner if self.memory_scanner else MemoryScanner()

            # Scan all accessible processes
            import psutil

            scanned_count = 0
            detected_count = 0
            
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    # Safety check for process info
                    if not proc.info or not proc.info.get('name') or not proc.info.get('pid'):
                        continue
                    
                    process_name = proc.info['name'] or f"Process_{proc.info['pid']}"
                    process_pid = proc.info['pid']
                    
                    # Skip system processes for safety
                    if process_name in ['System', 'Registry', 'csrss.exe', 'smss.exe']:
                        continue
                        
                    # Run actual enhanced memory scan for each process
                    detections = memory_scanner.scan_process_memory_enhanced(process_pid)
                    if detections:
                        for detection in detections:
                            detection.setdefault('process', process_name)
                            detection.setdefault('pid', process_pid)
                            detection.setdefault('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                            self._add_shellcode_detection(detection)
                            self._add_live_detection(detection)
                            detected_count += 1

                    scanned_count += 1
                    
                    # Update progress
                    if scanned_count % 10 == 0:
                        self.log_output.append(f"📊 Scanned {scanned_count} processes, found {detected_count} detections...")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError):
                    continue
                    
            self.log_output.append(f"✅ Deep scan completed: {scanned_count} processes scanned, {detected_count} detections found")
            
        except Exception as e:
            self.log_output.append(f"❌ Deep scan error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Deep scan failed: {str(e)}")

    def _clear_shellcode_results(self):
        """Clear shellcode detection results"""
        self.shellcode_table.setRowCount(0)
        self.shellcode_hex_view.clear()
        self.shellcode_disasm_view.clear()
        self.shellcode_patterns_view.clear()
        self.shellcode_metadata_view.clear()
        self.log_output.append("🧹 Shellcode detection results cleared")

    def _add_shellcode_detection(self, detection):
        """🧙‍♂️ Add a shellcode detection and learn it in the ancient tome"""
        try:
            # First, add to the ancient tome for learning
            if hasattr(self, 'shellcode_tome') and self.shellcode_tome:
                try:
                    # Determine the appropriate spell category
                    spell_category = self._classify_detection_type(detection.get('type', 'Unknown'))
                    
                    # Create enhanced detection entry for the tome
                    tome_entry = {
                        'type': detection.get('type', 'Unknown Spell'),
                        'process': detection.get('process', 'Unknown'),
                        'confidence': detection.get('confidence', 0),
                        'location': f"Memory: {detection.get('address', 'Unknown')}",
                        'details': f"Size: {detection.get('size', 0)} bytes, Risk: {detection.get('risk', 'Medium')}",
                        'entropy': detection.get('entropy', 0.0),
                        'disassembly': detection.get('disassembly', ''),
                        'shellcode': detection.get('shellcode', b''),
                        'patterns': detection.get('patterns', []),
                        'metadata': detection
                    }
                    
                    # Learn the spell in the ancient tome
                    self.shellcode_tome.add_entry(spell_category, tome_entry)
                    
                    # Update wisdom display
                    self._update_tome_wisdom_display()
                    
                    # Log the learning event
                    self.log_output.append(f"🌟 New {spell_category} spell learned and added to the Ancient Tome!")
                    
                except Exception as tome_error:
                    self.log_output.append(f"⚠️ Tome learning error: {str(tome_error)}")
            
            # Then add to the current session display table
            row = self.shellcode_table.rowCount()
            self.shellcode_table.insertRow(row)
            
            # Format detection data for new table format (9 columns)
            timestamp = detection.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            process = detection.get('process', 'Unknown')
            address = detection.get('address', 'N/A')
            shellcode_type = detection.get('type', 'Unknown')
            confidence = detection.get('confidence', 0)
            risk = detection.get('risk', 'Medium')
            size = detection.get('size', 0)
            
            # Convert risk to power rating for display
            power_rating = self._risk_to_power(risk)
            
            # Create table items for enhanced display
            items = [
                QTableWidgetItem(timestamp),                               # 🕐 Discovered
                QTableWidgetItem(shellcode_type),                         # 🏷️ Spell Name
                QTableWidgetItem(process),                                # ⚔️ Process
                QTableWidgetItem(f"0x{address:08x}" if isinstance(address, int) else str(address)), # 📍 Memory Realm
                QTableWidgetItem(f"{confidence}%"),                       # 🎯 Confidence
                QTableWidgetItem(str(power_rating)),                      # ⚡ Power
                QTableWidgetItem(str(size)),                              # 📏 Size
                QTableWidgetItem("1"),                                    # 🔄 Encounters (new detection)
                QTableWidgetItem("📖 View Spell")                        # 🛡️ Actions
            ]
            
            # Set items in table
            for col, item in enumerate(items):
                self.shellcode_table.setItem(row, col, item)
                
            # Color code by power level (enhanced)
            if power_rating >= 7:
                color = QColor('#ff4444')  # High power - red
                items[5].setToolTip("🔥 High Power Spell - Dangerous!")
            elif power_rating >= 4:
                color = QColor('#ffaa44')  # Medium power - orange  
                items[5].setToolTip("⚡ Medium Power Spell")
            else:
                color = QColor('#44ff44')  # Low power - green
                items[5].setToolTip("💚 Low Power Spell")
                
            items[5].setBackground(color)
            
            # Store detection data for detailed view with tome context
            detection_with_context = {
                **detection,
                'tome_learned': True,
                'spell_category': self._classify_detection_type(detection.get('type', 'Unknown')),
                'power_rating': power_rating
            }
            items[0].setData(Qt.UserRole, detection_with_context)
            
        except Exception as e:
            self.log_output.append(f"❌ Error adding shellcode detection: {str(e)}")
    
    def _classify_detection_type(self, detection_type):
        """🔮 Classify detection type into tome spell category"""
        detection_type = str(detection_type).lower()
        
        if 'api' in detection_type and 'hash' in detection_type:
            return 'api_hashing'
        elif 'egg hunter' in detection_type:
            return 'egg_hunters'
        elif 'injection' in detection_type:
            return 'process_injection'
        elif 'xor' in detection_type or 'encoding' in detection_type:
            return 'xor_encoding'
        elif 'stack string' in detection_type:
            return 'stack_strings'
        elif 'peb' in detection_type:
            return 'peb_access'
        elif 'reflective' in detection_type or 'loading' in detection_type:
            return 'reflective_loading'
        elif 'rop' in detection_type:
            return 'rop_chains'
        elif 'shellcode' in detection_type:
            return 'shellcode_patterns'
        elif 'rwx' in detection_type:
            return 'rwx_memory'
        elif 'wx' in detection_type:
            return 'wx_memory'
        elif 'cfg' in detection_type:
            return 'cfg_bypass'
        elif 'hollowing' in detection_type:
            return 'process_hollowing'
        elif 'memory' in detection_type:
            return 'suspicious_memory'
        elif 'unsigned' in detection_type:
            return 'unsigned_modules'
        elif 'registry' in detection_type:
            return 'suspicious_registry'
        elif 'command' in detection_type or 'cmdline' in detection_type:
            return 'suspicious_cmdline'
        elif 'yara' in detection_type:
            return 'yara_matches'
        else:
            return 'unknown_magic'
    
    def _risk_to_power(self, risk):
        """Convert risk level to mystical power rating"""
        risk = str(risk).lower()
        if risk == 'high':
            return 8
        elif risk == 'medium':
            return 5
        elif risk == 'low':
            return 2
        else:
            return 3

    def _update_shellcode_details(self):
        """Update shellcode details view when selection changes"""
        try:
            current_row = self.shellcode_table.currentRow()
            if current_row < 0:
                return
                
            timestamp_item = self.shellcode_table.item(current_row, 0)
            if not timestamp_item:
                return
                
            # Get detection data stored in UserRole
            detection = timestamp_item.data(Qt.UserRole)
            if not detection:
                return
            
            # Check if this is a tome spell that needs full details
            if 'id' in detection and not detection.get('shellcode'):
                try:
                    # This is a tome spell, get full details including pattern_data
                    spell_details = self.shellcode_tome.get_spell_details(detection['id'])
                    if spell_details and 'pattern_data' in spell_details:
                        # Extract the original detection data from pattern_data
                        original_detection = spell_details['pattern_data']
                        # Merge the spell metadata with the original detection data
                        detection.update(original_detection)
                    if spell_details:
                        detection.setdefault('spell_category', spell_details.get('category', 'unknown_magic'))
                        detection.setdefault('timestamp', spell_details.get('discovery_date', 'Unknown'))
                        detection.setdefault('power_rating', spell_details.get('power_rating', detection.get('power', 'Unknown')))
                        detection.setdefault('process', spell_details.get('process_name', detection.get('process', 'Unknown')))
                        detection.setdefault('address', spell_details.get('memory_address', detection.get('address', 'Unknown')))
                        detection.setdefault('disassembly', spell_details.get('disassembly', detection.get('disassembly', '')))

                        metadata = spell_details.get('metadata') if isinstance(spell_details.get('metadata'), dict) else {}
                        if metadata:
                            detection.setdefault('size', metadata.get('shellcode_size', detection.get('size', 0)))
                            detection.setdefault('details', metadata.get('details', detection.get('details', '')))
                except Exception as e:
                    self._append_log(f"❌ Error loading spell details: {str(e)}")
            
            # Update Raw Magic (Hex) view
            shellcode_bytes = detection.get('shellcode', b'')
            
            # Try alternative keys for shellcode data
            if not shellcode_bytes:
                shellcode_bytes = detection.get('data', b'')
            if not shellcode_bytes:
                shellcode_bytes = detection.get('raw_data', b'')
            if not shellcode_bytes:
                shellcode_bytes = detection.get('memory_content', b'')
                
            if isinstance(shellcode_bytes, str):
                # Try to decode hex string if it's a hex representation
                if all(c in '0123456789abcdefABCDEF' for c in shellcode_bytes.replace(' ', '')):
                    try:
                        shellcode_bytes = bytes.fromhex(shellcode_bytes.replace(' ', ''))
                    except ValueError:
                        shellcode_bytes = shellcode_bytes.encode('latin-1', errors='ignore')
                else:
                    shellcode_bytes = shellcode_bytes.encode('latin-1', errors='ignore')
            
            hex_output = ""
            if shellcode_bytes:
                # Format as hex dump with addresses
                for i in range(0, len(shellcode_bytes), 16):
                    chunk = shellcode_bytes[i:i+16]
                    hex_vals = ' '.join(f'{b:02x}' for b in chunk)
                    ascii_vals = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    hex_output += f"{i:08x}: {hex_vals:<48} |{ascii_vals}|\n"
            else:
                hex_output = "No raw shellcode data available"
            
            self.shellcode_hex_view.setText(hex_output)
            
            # Update Incantations (Disassembly) view
            disassembly = detection.get('disassembly', '')
            if not disassembly and shellcode_bytes:
                # Try to generate disassembly if not provided
                try:
                    from ShellCodeMagic import CodeDisassembler
                    disassembler = CodeDisassembler()
                    disassembly = disassembler.disassemble(shellcode_bytes)
                except:
                    disassembly = "Disassembly not available"
            
            if not disassembly:
                disassembly = "No disassembly data available"
                
            self.shellcode_disasm_view.setText(disassembly)
            
            # Update Pattern Runes view
            patterns = detection.get('patterns', [])
            pattern_output = ""
            if patterns:
                pattern_output = "🔮 Detected Patterns:\n\n"
                for i, pattern in enumerate(patterns, 1):
                    if isinstance(pattern, dict):
                        pattern_output += f"{i}. {pattern.get('name', 'Unknown Pattern')}\n"
                        pattern_output += f"   Description: {pattern.get('description', 'N/A')}\n"
                        pattern_output += f"   Confidence: {pattern.get('confidence', 'N/A')}\n\n"
                    else:
                        pattern_output += f"{i}. {pattern}\n\n"
            else:
                pattern_output = "No specific patterns detected"
                
            self.shellcode_patterns_view.setText(pattern_output)
            
            # Update Ancient Scroll (Metadata) view
            metadata_output = "🧙‍♂️ Spell Metadata:\n\n"
            
            # Core spell information
            metadata_output += f"📜 Spell Type: {detection.get('type', 'Unknown')}\n"
            metadata_output += f"⚔️ Target Process: {detection.get('process', 'Unknown')}\n"
            memory_realm = detection.get('address', detection.get('location', 'Unknown'))
            metadata_output += f"📍 Memory Realm: {memory_realm}\n"
            metadata_output += f"📏 Spell Size: {detection.get('size', 0)} bytes\n"
            metadata_output += f"🎯 Confidence: {detection.get('confidence', 0)}%\n"
            metadata_output += f"⚡ Power Level: {detection.get('power_rating', 'Unknown')}\n"
            metadata_output += f"🏷️ Spell Category: {detection.get('spell_category', 'Unknown')}\n\n"
            
            # Additional metadata
            metadata_output += "🔬 Analysis Details:\n"
            if 'entropy' in detection:
                metadata_output += f"  📊 Entropy: {detection['entropy']:.3f}\n"
            if 'risk' in detection:
                metadata_output += f"  ⚠️ Risk Level: {detection['risk']}\n"
            if 'hash' in detection:
                metadata_output += f"  🔐 Hash: {detection['hash']}\n"
            
            # Timestamp information
            timestamp = detection.get('timestamp', 'Unknown')
            metadata_output += f"\n🕐 Discovery Time: {timestamp}\n"
            
            if detection.get('tome_learned'):
                metadata_output += "\n🌟 This spell has been learned by the Ancient Tome"
                
            self.shellcode_metadata_view.setText(metadata_output)
            
            # Update Spell History view if available
            if hasattr(self, 'spell_history_view') and hasattr(self, 'shellcode_tome'):
                try:
                    spell_name = detection.get('type') or detection.get('name') or detection.get('spell_name') or 'Unknown'
                    spell_category = detection.get('spell_category', 'unknown_magic')
                    
                    # Get spell history from tome
                    history = self.shellcode_tome.get_spell_history(spell_category, spell_name)
                    
                    history_output = f"📚 Spell History for '{spell_name}':\n\n"
                    
                    if history:
                        history_output += f"🔄 Total Encounters: {len(history)}\n"
                        history_output += f"🕐 First Seen: {history[0].get('timestamp', 'Unknown')}\n"
                        history_output += f"🕐 Last Seen: {history[-1].get('timestamp', 'Unknown')}\n\n"
                        
                        history_output += "📋 Recent Encounters:\n"
                        for i, encounter in enumerate(history[-5:], 1):  # Show last 5
                            history_output += f"{i}. {encounter.get('timestamp', 'Unknown')} - "
                            history_output += f"Process: {encounter.get('process', 'Unknown')}, "
                            history_output += f"Confidence: {encounter.get('confidence', 0)}%\n"
                    else:
                        history_output += "No previous encounters recorded"
                        
                    self.spell_history_view.setText(history_output)
                except Exception as history_error:
                    self.spell_history_view.setText(f"Error loading spell history: {history_error}")
            
        except Exception as e:
            self._append_log(f"❌ Error updating shellcode details: {str(e)}")
            # Clear views on error
            if hasattr(self, 'shellcode_hex_view'):
                self.shellcode_hex_view.setText("Error loading details")
            if hasattr(self, 'shellcode_disasm_view'):
                self.shellcode_disasm_view.setText("Error loading details")
            if hasattr(self, 'shellcode_patterns_view'):
                self.shellcode_patterns_view.setText("Error loading details")
            if hasattr(self, 'shellcode_metadata_view'):
                self.shellcode_metadata_view.setText("Error loading details")
    
    # === ANCIENT TOME METHODS ===
    def _update_tome_wisdom_display(self):
        """🧙‍♂️ Update the tome wisdom display with current statistics"""
        try:
            if hasattr(self, 'shellcode_tome') and self.shellcode_tome:
                stats = self.shellcode_tome.get_tome_statistics()
                if stats:
                    overview = stats['overview']
                    self.tome_power_label.setText(f"⚡ Tome Power Level: {overview.get('power_level', 1)}")
                    self.tome_spells_label.setText(f"📚 Spells Learned: {overview.get('total_spells_learned', 0)}")
                    self.tome_categories_label.setText(f"🗂️ Categories: {len(overview.get('categories_discovered', []))}")
                    velocity = overview.get('learning_velocity', 0.0)
                    self.tome_velocity_label.setText(f"🚀 Learning Velocity: {velocity:.2f} spells/hour")
                else:
                    self._set_default_wisdom_display()
            else:
                self._set_default_wisdom_display()
        except Exception as e:
            logging.error(f"Error updating tome wisdom display: {str(e)}")
            self._set_default_wisdom_display()
    
    def _set_default_wisdom_display(self):
        """🧙‍♂️ Set default values for tome wisdom display"""
        try:
            if hasattr(self, 'tome_power_label'):
                self.tome_power_label.setText("⚡ Tome Power Level: 1")
            if hasattr(self, 'tome_spells_label'):
                self.tome_spells_label.setText("📚 Spells Learned: 0")
            if hasattr(self, 'tome_categories_label'):
                self.tome_categories_label.setText("🗂️ Categories: 0")
            if hasattr(self, 'tome_velocity_label'):
                self.tome_velocity_label.setText("🚀 Learning Velocity: 0.00 spells/hour")
        except Exception as e:
            logging.error(f"Error setting default wisdom display: {str(e)}")
    
    def _browse_ancient_tome(self):
        """📚 Browse all spells in the ancient tome"""
        try:
            if not hasattr(self, 'shellcode_tome') or not self.shellcode_tome:
                # Backend may still be initializing; avoid noisy startup popups.
                self._append_log("⏳ Ancient Tome is still initializing...")
                return
            
            # Get current filter
            category_filter = self.spell_category_filter.currentText()
            if category_filter == "All Spells":
                category = None
            else:
                # Convert display name to internal category
                category_map = {
                    "🪄 API Hashing": "api_hashing",
                    "🥚 Egg Hunters": "egg_hunters",
                    "💉 Process Injection": "process_injection",
                    "⚗️ XOR Encoding": "xor_encoding",
                    "📚 Stack Strings": "stack_strings",
                    "🏛️ PEB Access": "peb_access",
                    "🪞 Reflective Loading": "reflective_loading",
                    "⛓️ ROP Chains": "rop_chains",
                    "🐚 Pure Shellcode": "shellcode_patterns",
                    "🔥 RWX Memory": "rwx_memory",
                    "⚡ WX Memory": "wx_memory",
                    "🌊 CFG Bypass": "cfg_bypass",
                    "👻 Process Hollowing": "process_hollowing",
                    "🌫️ Suspicious Memory": "suspicious_memory",
                    "📋 Unsigned Modules": "unsigned_modules",
                    "🗝️ Suspicious Registry": "suspicious_registry",
                    "👑 Suspicious Cmdline": "suspicious_cmdline",
                    "🎯 YARA Matches": "yara_matches",
                    "🌟 Unknown Magic": "unknown_magic"
                }
                category = category_map.get(category_filter)
            
            # Browse spells from tome
            spells = self.shellcode_tome.browse_ancient_spells(category=category, limit=100)
            
            # Clear and populate table
            self.shellcode_table.setRowCount(0)
            
            for spell in spells:
                self._add_spell_to_table(spell, from_tome=True)
            
            self._append_log(f"📚 Browsed {len(spells)} ancient spells from the tome")
            
        except Exception as e:
            self._append_log(f"❌ Error browsing ancient tome: {str(e)}")
            QMessageBox.critical(self, "Tome Error", f"Failed to browse the ancient tome: {str(e)}")
    
    def _search_tome(self):
        """🔍 Search the ancient tome for specific spells"""
        try:
            search_term, ok = QInputDialog.getText(
                self, 
                "🔍 Search Ancient Tome", 
                "Enter search term (spell name, process, address):",
                QLineEdit.Normal,
                ""
            )
            
            if not ok or not search_term.strip():
                return
            
            if not hasattr(self, 'shellcode_tome') or not self.shellcode_tome:
                QMessageBox.warning(self, "Tome Unavailable", "The Ancient Shellcode Tome is not initialized.")
                return
            
            # Get current category filter
            category_filter = self.spell_category_filter.currentText()
            category = None if category_filter == "All Spells" else self._get_category_from_filter(category_filter)
            
            # Search the tome
            results = self.shellcode_tome.search_spells(search_term.strip(), category=category)
            
            # Clear and populate table with results
            self.shellcode_table.setRowCount(0)
            
            for result in results:
                self._add_spell_to_table(result, from_tome=True)
            
            if results:
                self._append_log(f"🔍 Found {len(results)} spells matching '{search_term}'")
            else:
                self._append_log(f"🔍 No spells found matching '{search_term}'")
                QMessageBox.information(self, "Search Results", f"No spells found matching '{search_term}'")
            
        except Exception as e:
            self._append_log(f"❌ Error searching tome: {str(e)}")
            QMessageBox.critical(self, "Search Error", f"Failed to search the tome: {str(e)}")
    
    def _show_tome_statistics(self):
        """📊 Show comprehensive tome statistics"""
        try:
            if not hasattr(self, 'shellcode_tome') or not self.shellcode_tome:
                QMessageBox.warning(self, "Tome Unavailable", "The Ancient Shellcode Tome is not initialized.")
                return
            
            stats = self.shellcode_tome.get_tome_statistics()
            if not stats:
                QMessageBox.warning(self, "No Statistics", "Unable to retrieve tome statistics.")
                return
            
            # Create statistics dialog
            stats_dialog = QDialog(self)
            stats_dialog.setWindowTitle("📊 Ancient Tome Statistics")
            stats_dialog.setMinimumSize(600, 500)
            
            layout = QVBoxLayout(stats_dialog)
            
            # Create tabs for different statistics
            stats_tabs = QTabWidget()
            
            # Overview tab
            overview_text = QTextEdit()
            overview_text.setReadOnly(True)
            overview_info = self._format_overview_stats(stats['overview'])
            overview_text.setText(overview_info)
            stats_tabs.addTab(overview_text, "📋 Overview")
            
            # Category breakdown tab
            category_text = QTextEdit()
            category_text.setReadOnly(True)
            category_info = self._format_category_stats(stats['category_breakdown'])
            category_text.setText(category_info)
            stats_tabs.addTab(category_text, "🗂️ Categories")
            
            # Recent activity tab
            recent_text = QTextEdit()
            recent_text.setReadOnly(True)
            recent_info = self._format_recent_activity(stats['recent_activity'])
            recent_text.setText(recent_info)
            stats_tabs.addTab(recent_text, "🕐 Recent Activity")
            
            # Top spells tab
            top_text = QTextEdit()
            top_text.setReadOnly(True)
            top_info = self._format_top_spells(stats)
            top_text.setText(top_info)
            stats_tabs.addTab(top_text, "🏆 Top Spells")
            
            layout.addWidget(stats_tabs)
            
            # Close button
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(stats_dialog.close)
            layout.addWidget(close_btn)
            
            stats_dialog.exec()
            
        except Exception as e:
            self.log_output.append(f"❌ Error showing tome statistics: {str(e)}")
            QMessageBox.critical(self, "Statistics Error", f"Failed to show statistics: {str(e)}")
    
    def _filter_spells_by_category(self):
        """🗂️ Filter displayed spells by category"""
        # This will be called when the category filter changes
        # For now, we'll just trigger a browse refresh
        if hasattr(self, 'shellcode_tome') and self.shellcode_tome:
            self._browse_ancient_tome()
    
    def _add_spell_to_table(self, spell_data, from_tome=False):
        """Add a spell to the results table"""
        try:
            row = self.shellcode_table.rowCount()
            self.shellcode_table.insertRow(row)
            
            # Format spell data for display
            if from_tome:
                # Data from tome database
                spell_location = spell_data.get('location') or spell_data.get('address') or spell_data.get('memory_address') or 'Tome Archive'
                spell_size = spell_data.get('size') if spell_data.get('size') not in (None, '') else spell_data.get('shellcode_size', 'N/A')
                items = [
                    QTableWidgetItem(spell_data.get('discovered', 'Unknown')),
                    QTableWidgetItem(spell_data.get('name', 'Unknown Spell')),
                    QTableWidgetItem(spell_data.get('process', 'Unknown')),
                    QTableWidgetItem(str(spell_location)),
                    QTableWidgetItem(spell_data.get('confidence', 'Unknown')),
                    QTableWidgetItem(str(spell_data.get('power', 1))),
                    QTableWidgetItem(str(spell_size)),
                    QTableWidgetItem(str(spell_data.get('encounters', 1))),
                    QTableWidgetItem("📖 View Details")
                ]
            else:
                # Data from live detection
                timestamp = spell_data.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                process = spell_data.get('process', 'Unknown')
                address = spell_data.get('address', 'N/A')
                spell_type = spell_data.get('type', 'Unknown')
                confidence = spell_data.get('confidence', 0)
                risk = spell_data.get('risk', 'Medium')
                size = spell_data.get('size', 0)
                
                items = [
                    QTableWidgetItem(timestamp),
                    QTableWidgetItem(spell_type),
                    QTableWidgetItem(process),
                    QTableWidgetItem(f"0x{address:08x}" if isinstance(address, int) else str(address)),
                    QTableWidgetItem(f"{confidence}%"),
                    QTableWidgetItem(risk),
                    QTableWidgetItem(str(size)),
                    QTableWidgetItem("1"),
                    QTableWidgetItem("📖 View Details")
                ]
            
            # Set items in table
            for col, item in enumerate(items):
                self.shellcode_table.setItem(row, col, item)
                
            # Color code by power/risk level
            if from_tome:
                power = spell_data.get('power', 1)
                if power >= 7:
                    color = QColor('#ff4444')  # High power - red
                elif power >= 4:
                    color = QColor('#ffaa44')  # Medium power - orange
                else:
                    color = QColor('#44ff44')  # Low power - green
                items[5].setBackground(color)
            else:
                risk = str(spell_data.get('risk', 'Medium')).lower()
                if risk == 'high':
                    color = QColor('#ff4444')
                elif risk == 'medium':
                    color = QColor('#ffaa44')
                else:
                    color = QColor('#44ff44')
                items[5].setBackground(color)
            
            # Store spell data for detailed view
            if from_tome and spell_data.get('id'):
                enriched_spell = dict(spell_data)
                try:
                    spell_details = self.shellcode_tome.get_spell_details(spell_data.get('id')) if self.shellcode_tome else None
                except Exception:
                    spell_details = None

                if spell_details:
                    pattern_data = spell_details.get('pattern_data') or {}
                    if isinstance(pattern_data, dict):
                        enriched_spell.update(pattern_data)

                    metadata = spell_details.get('metadata') or {}
                    if isinstance(metadata, dict):
                        if not enriched_spell.get('size'):
                            enriched_spell['size'] = metadata.get('shellcode_size', enriched_spell.get('size', 0))
                        if not enriched_spell.get('details'):
                            enriched_spell['details'] = metadata.get('details', enriched_spell.get('details', ''))

                    enriched_spell['spell_category'] = spell_details.get('category', enriched_spell.get('spell_category', 'unknown_magic'))
                    enriched_spell['timestamp'] = spell_details.get('discovery_date', enriched_spell.get('timestamp', enriched_spell.get('discovered', 'Unknown')))
                    enriched_spell['risk'] = enriched_spell.get('risk', enriched_spell.get('severity', 'Medium'))

                items[0].setData(Qt.UserRole, enriched_spell)
            else:
                items[0].setData(Qt.UserRole, spell_data)

        except Exception as e:
            self._append_log(f"❌ Error adding spell to table: {str(e)}")
    
    def _get_category_from_filter(self, filter_text):
        """Convert filter display text to internal category name"""
        category_map = {
            "🪄 API Hashing": "api_hashing",
            "🥚 Egg Hunters": "egg_hunters", 
            "💉 Process Injection": "process_injection",
            "⚗️ XOR Encoding": "xor_encoding",
            "📚 Stack Strings": "stack_strings",
            "🏛️ PEB Access": "peb_access",
            "🪞 Reflective Loading": "reflective_loading",
            "⛓️ ROP Chains": "rop_chains",
            "🐚 Pure Shellcode": "shellcode_patterns",
            "🔥 RWX Memory": "rwx_memory",
            "⚡ WX Memory": "wx_memory",
            "🌊 CFG Bypass": "cfg_bypass",
            "👻 Process Hollowing": "process_hollowing",
            "🌫️ Suspicious Memory": "suspicious_memory",
            "📋 Unsigned Modules": "unsigned_modules",
            "🗝️ Suspicious Registry": "suspicious_registry",
            "👑 Suspicious Cmdline": "suspicious_cmdline",
            "🎯 YARA Matches": "yara_matches",
            "🌟 Unknown Magic": "unknown_magic"
        }
        return category_map.get(filter_text)
    
    def _format_overview_stats(self, overview):
        """Format overview statistics for display"""
        return f"""🧙‍♂️ Ancient Tome Overview

⚡ Power Level: {overview.get('power_level', 1)}
📚 Total Spells Learned: {overview.get('total_spells_learned', 0)}
🗂️ Categories Discovered: {len(overview.get('categories_discovered', []))}
🔬 Unique Patterns: {overview.get('unique_patterns_identified', 0)}
🚀 Learning Velocity: {overview.get('learning_velocity', 0.0):.2f} spells/hour

📅 Tome Created: {overview.get('tome_creation_date', 'Unknown')}
🕐 Last Learning Session: {overview.get('last_learning_session', 'Never')}

🌟 Ancient Knowledge Unlocked:
{chr(10).join(f"  • {knowledge}" for knowledge in overview.get('ancient_knowledge_unlocked', ['None yet']))}
"""
    
    def _format_category_stats(self, categories):
        """Format category statistics for display"""
        if not categories:
            return "No spell categories discovered yet."
        
        text = "🗂️ Spell Category Breakdown\n\n"
        for category, stats in categories.items():
            text += f"📂 {category.replace('_', ' ').title()}:\n"
            text += f"   • Count: {stats['count']} spells\n"
            text += f"   • Average Power: {stats['avg_power']}\n"
            text += f"   • Max Encounters: {stats['max_encounters']}\n\n"
        
        return text
    
    def _format_recent_activity(self, activity):
        """Format recent activity for display"""
        if not activity:
            return "No recent spell learning activity."
        
        text = "🕐 Recent Spell Learning Activity\n\n"
        for spell in activity:
            text += f"🌟 {spell['name']} ({spell['category']})\n"
            text += f"   • Discovered: {spell['date']}\n"
            text += f"   • Power Level: {spell['power']}\n\n"
        
        return text
    
    def _format_top_spells(self, stats):
        """Format top spells statistics"""
        text = "🏆 Most Powerful & Encountered Spells\n\n"
        
        text += "⚡ Highest Power Spells:\n"
        for spell in stats.get('highest_power_spells', []):
            text += f"  • {spell['name']} (Power: {spell['power']}, Category: {spell['category']})\n"
        
        text += "\n🔄 Most Encountered Spells:\n"
        for spell in stats.get('most_encountered_spells', []):
            text += f"  • {spell['name']} ({spell['encounters']} times, Category: {spell['category']})\n"
        
        return text

    def _format_hex_dump(self, data):
        """Format binary data as hex dump"""
        try:
            if not data:
                return "No data"
                
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                lines.append(f'{i:08x}: {hex_part:<48} {ascii_part}')
                
            return '\n'.join(lines)
            
        except Exception as e:
            return f"Error formatting hex dump: {str(e)}"

    # === LEGACY ScannerGui COMPATIBILITY API ===

    def __new__(cls, *args, **kwargs):
        """Compatibility constructor for legacy ScannerGui call sites."""
        return super().__new__(cls)

    def _setup_logging(self):
        """Legacy logging setup entrypoint."""
        self.logger = logging.getLogger('OrbitalStationUI')
        return self.logger

    def create_utility_functions(self):
        """Legacy no-op hook retained for ScannerGui compatibility."""
        return None

    def setup_gui(self):
        """Legacy GUI setup entrypoint (UI is already created in __init__)."""
        if not hasattr(self, 'tabs'):
            self._create_ui()

    def create_tabs(self):
        """Legacy tab creation hook (tabs are built by _create_ui)."""
        return None

    def create_tree_utilities(self):
        """Legacy tree utility hook retained for API compatibility."""
        return None

    def update_rule_status(self):
        self.update_rule_status_display()

    def update_rule_status_display(self):
        if hasattr(self, 'rules_label'):
            self.rules_label.setText("Rules: Loaded" if self.rules_loaded else "Rules: Failed")

    def initialize_security_patches(self):
        """Legacy bootstrap hook mapped to protection initialization."""
        self.initial_protection()

    def update_gui_detections(self):
        """Refresh detection table from stored detections."""
        if not hasattr(self, 'detections_table'):
            return
        self.detections_table.setRowCount(0)
        for detection in self.detections:
            self._add_detection(dict(detection))

    def update_status(self, message):
        self.set_status_label(message)

    def set_status_label(self, message):
        if hasattr(self, 'status_message'):
            self.status_message.setText(str(message))
        elif hasattr(self, 'status_label'):
            self.status_label.setText(str(message))

    def create_detection_item(self, detection):
        """Return normalized detection dict for legacy callers."""
        if isinstance(detection, dict):
            return detection
        return {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'type': 'Detection',
            'name': str(detection),
            'severity': 'Medium',
            'description': str(detection)
        }

    def update_quarantine_settings(self):
        """Apply legacy quarantine controls to modern auto-quarantine settings."""
        enabled = True
        threshold = 70

        try:
            if hasattr(self, 'quarantine_var'):
                enabled = bool(self.quarantine_var.get())
        except Exception:
            pass

        try:
            if hasattr(self, 'threshold_var'):
                threshold = int(self.threshold_var.get())
        except Exception:
            pass

        self.auto_quarantine_enabled = enabled
        self.auto_quarantine_min_confidence = max(0, min(100, int(threshold)))

    def trace_pyhandle_errors(self, error):
        self._append_log(f"⚠️ Handle trace: {error}")

    def is_rules_loaded(self):
        return bool(self.rules_loaded)

    def _delayed_monitoring_start(self):
        QTimer.singleShot(250, self.enable_protection)

    def play_alert_sound(self):
        self.play_notification_sound()

    def alert_soun_path(self):
        """Legacy typo-preserved API for backward compatibility."""
        return getattr(self, 'alert_sound_path', '')

    def _log_detection_internal(self, detection):
        self.log_detection(detection)

    def is_critical_process(self, process_name):
        if not process_name:
            return False
        return str(process_name).lower() in {p.lower() for p in getattr(self, 'critical_processes', set())}

    def get_scan_priority(self, process_name):
        if self.is_critical_process(process_name):
            return 'low'
        suspicious = ['powershell', 'cmd', 'wscript', 'cscript', 'rundll32']
        if any(token in str(process_name).lower() for token in suspicious):
            return 'high'
        return 'normal'

    def should_scan_process(self, process_name):
        return not self.is_critical_process(process_name)

    def update_gui(self):
        self._smart_refresh_processes()
        self._refresh_quarantine()

    def update_scan_summary(self):
        if hasattr(self, 'status_message'):
            self.status_message.setText(
                f"Scanned: {self.total_processes_scanned} | Threats: {self.threats_found}"
            )

    def update_scan_progress(self, progress, message='Scanning...'):
        self._update_scan_progress(int(progress), str(message))

    def process_list_data(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'status']):
            try:
                processes.append(proc.info)
            except Exception:
                continue
        return processes

    def load_signatures(self, signature_file=None):
        """Load legacy hash signature database from text file."""
        self.signature_db = set()
        if not signature_file:
            return False
        if not os.path.exists(signature_file):
            return False

        try:
            with open(signature_file, 'r', encoding='utf-8', errors='ignore') as f:
                self.signature_db = {line.strip() for line in f if line.strip()}
            return True
        except Exception:
            return False

    def calculate_file_hash(self, filepath):
        if not filepath or not os.path.exists(filepath):
            return None
        import hashlib
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def check_signatures(self, filepath):
        file_hash = self.calculate_file_hash(filepath)
        if not file_hash:
            return False
        return file_hash in getattr(self, 'signature_db', set())

    def scan_file(self, filepath):
        """Legacy boolean file scan against loaded signatures."""
        return self.check_signatures(filepath)

    def log_detection(self, detection):
        normalized = self.create_detection_item(detection)
        if 'pid' not in normalized:
            normalized['pid'] = normalized.get('process_pid', '')
        self._add_detection(normalized)

    def remove_selected_detection(self):
        self._delete_selected_detections()

    def quarantine_memory_region(self):
        self._append_log("⚠️ Memory-region quarantine is not supported in the PySide UI; use process quarantine actions.")

    def terminate_selected_region(self):
        self._append_log("⚠️ Region-level termination is not supported in this UI build.")

    def terminate_selected_process(self):
        self._terminate_process()

    def remove_selected(self):
        self.delete_selected()

    def quarantine_selected_memory(self):
        self.quarantine_selected()

    def remove_file(self, file_path=None):
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
                self._append_log(f"🗑️ Removed file: {file_path}")
                return True
            except Exception as e:
                self._append_log(f"❌ Failed to remove file {file_path}: {e}")
                return False
        self.remove_infected_file()
        return True

    def kill_process(self, pid):
        try:
            psutil.Process(int(pid)).terminate()
            return True
        except Exception as e:
            self._append_log(f"❌ Failed to terminate PID {pid}: {e}")
            return False

    def kill_selected_process(self):
        self._terminate_process()

    def restore_process(self, pid):
        try:
            psutil.Process(int(pid)).resume()
            return True
        except Exception as e:
            self._append_log(f"❌ Failed to restore PID {pid}: {e}")
            return False

    def remove_quarantined(self):
        self._delete_quarantined()

    def create_test_detection(self):
        test_detection = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'type': 'Test Detection',
            'name': 'ofsp_test_payload.exe',
            'pid': 1337,
            'severity': 'Medium',
            'description': 'Compatibility test detection generated manually'
        }
        self._add_detection(test_detection)

    def update_process_list(self):
        self._refresh_processes()

    def load_rules_async(self):
        threading.Thread(target=self._reload_yara, daemon=True).start()

    def start_scan(self, mode='quick'):
        if str(mode).lower() == 'deep':
            self.start_deep_scan()
        else:
            self.start_quick_scan()

    def handle_detection_alert(self, detection):
        self._add_detection(self.create_detection_item(detection))

    def update_detection_trees(self):
        """Legacy bridge for tree/table refresh."""
        if hasattr(self, 'detections_table'):
            self.detections_table.viewport().update()

    def scanning_loop(self, mode='quick'):
        self.start_scan(mode)

    def log_suspicious_region(self, process, address, details='Suspicious memory region'):
        detection = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'type': 'Suspicious Memory Region',
            'name': process,
            'pid': '',
            'severity': 'High',
            'description': f"{details} @ {address}"
        }
        self._add_detection(detection)

    def display_threat_details(self):
        self._update_threat_details()

    def run_quick_scan(self):
        self.start_quick_scan()

    def run_deep_scan(self):
        self.start_deep_scan()

    def play_notification_sound(self):
        """Play an alert sound with platform-safe fallbacks."""
        try:
            if sys.platform == 'win32':
                import winsound
                winsound.PlaySound('SystemAsterisk', winsound.SND_ALIAS)
                return
        except Exception:
            pass

        try:
            QApplication.beep()
        except Exception:
            pass

    def cleanup_scan(self):
        self.scanning = False
        self._update_scan_ui_end()

    def clear_ui_elements(self):
        self._clear_detections()
        if hasattr(self, 'scan_results_table'):
            self.scan_results_table.setRowCount(0)
        if hasattr(self, 'fs_results_table'):
            self.fs_results_table.setRowCount(0)
        if hasattr(self, 'memory_output'):
            self.memory_output.clear()
        if hasattr(self, 'log_output'):
            self.log_output.clear()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ui = OrbitalStationUI()
    # show() is called inside __init__ now
    sys.exit(app.exec())
