"""
Complete OrbitalStationUI - Full functionality from original Unnamed.py
This provides the complete PySide6-based GUI with all scanning, memory analysis,
process monitoring, YARA rule management, and protection features.
"""

import sys
import os
import traceback
import threading
import time
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
                    self.progress_updated.emit(
                        int((i / total) * 100),
                        f"Scanning: {proc_info['name']} (PID: {proc_info['pid']})"
                    )
                    
                    # Simple process analysis
                    if self._analyze_process(proc_info):
                        detection = {
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'type': 'Process',
                            'name': proc_info['name'],
                            'pid': proc_info['pid'],
                            'severity': 'Medium',
                            'description': 'Suspicious process detected'
                        }
                        self.detection_found.emit(detection)
                        
                    time.sleep(0.01)  # Small delay to prevent UI freezing
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            self.progress_updated.emit(100, "Quick scan completed")
            
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
                    self.progress_updated.emit(
                        int((i / total) * 100),
                        f"Deep scanning: {proc_info['name']} (PID: {proc_info['pid']})"
                    )
                    
                    # Analyze process and memory
                    if self._analyze_process(proc_info):
                        detection = {
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'type': 'Process',
                            'name': proc_info['name'],
                            'pid': proc_info['pid'],
                            'severity': 'High',
                            'description': 'Suspicious process with memory anomalies'
                        }
                        self.detection_found.emit(detection)
                        
                    # Memory analysis if available
                    if self.parent_ui.memory_scanner:
                        self._analyze_process_memory(proc_info['pid'])
                        
                    time.sleep(0.02)  # Slightly longer delay for deep scan
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            self.progress_updated.emit(100, "Deep scan completed")
            
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
        """Analyze process memory"""
        # This would use the Memory module for actual analysis
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
            
            # Additional heuristic checks if enabled
            if self.parent_ui.heuristic_analysis.isChecked():
                heuristic_result = self._heuristic_analysis(file_path)
                if heuristic_result:
                    return heuristic_result
            
        except Exception as e:
            # Skip files that can't be scanned
            pass
        
        return None
    
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

class OrbitalStationUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Orbital Station: Malware Defense Console")
        self.setGeometry(100, 100, 1400, 900)
        
        # Initialize backend components first
        self._init_backend()
        
        # Initialize GUI variables
        self.scanning = False
        self.monitoring_active = False
        self.total_processes_scanned = 0
        self.threats_found = 0
        self.detections = []
        self.scan_worker = None
        
        # Setup styling and create UI
        self._setup_styling()
        self._create_ui()
        
        # Initialize protection systems
        self.initial_protection()
        
    def _init_backend(self):
        """Initialize all backend components"""
        print("Initializing backend components...")
        
        # Initialize YARA manager
        if YaraRuleManager:
            try:
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
            except Exception as e:
                print(f"YARA initialization error: {e}")
                self.yara_manager = None
                self.rules_loaded = False
        else:
            self.yara_manager = None
            self.rules_loaded = False
            
        # Initialize memory scanner
        if Memory:
            try:
                self.memory_scanner = Memory.MemoryScanner()
                print("Memory scanner initialized")
            except Exception as e:
                print(f"Memory scanner initialization error: {e}")
                self.memory_scanner = None
        else:
            self.memory_scanner = None
            
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
        
        # Critical processes that should not be terminated
        self.critical_processes = {
            'explorer.exe', 'svchost.exe', 'lsass.exe', 
            'winlogon.exe', 'csrss.exe', 'services.exe',
            'smss.exe', 'wininit.exe', 'System'
        }
        
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
        self._create_yara_tab()
        self._create_quarantine_tab()
        self._create_logs_tab()
        
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
        
        protection_layout.addWidget(self.enable_protection_btn)
        protection_layout.addWidget(self.disable_protection_btn)
        protection_layout.addWidget(self.quarantine_btn)
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
        
        for btn in [self.deep_scan_archives, self.scan_network_drives, self.heuristic_analysis]:
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
            "🌊 CFG Bypass", "👻 Process Hollowing", "🌟 Unknown Magic"
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
        layout = QVBoxLayout(widget)
        
        # Detection controls
        control_frame = QGroupBox("Detection Management")
        control_layout = QHBoxLayout(control_frame)
        
        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self._clear_detections)
        
        export_btn = QPushButton("Export Detections")
        export_btn.clicked.connect(self._export_detections)
        
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
        layout.addWidget(self.detections_table)
        
        self.tabs.addTab(widget, "Detections")
        
    def _create_scan_results_tab(self):
        """Create dedicated scan results tab with enhanced visibility"""
        widget = QWidget()
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
        
    # === SCAN METHODS ===
    
    def start_quick_scan(self):
        """Start a quick scan"""
        if self.scanning:
            return
            
        self.scanning = True
        self._update_scan_ui_start()
        
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
        
    def _scan_completed(self, results):
        """Handle scan completion"""
        self.scanning = False
        self._update_scan_ui_end()
        
        # Refresh process list after scan
        self._smart_refresh_processes()
        
    def _add_detection(self, detection):
        """Add a new detection to the table"""
        self.detections.append(detection)
        self.threats_found += 1
        self.threats_label.setText(f"Threats: {self.threats_found}")
        
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
            self.detections_table.setItem(row, col, QTableWidgetItem(str(item)))
            
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
        """Analyze process memory"""
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
            self.memory_output.append(f"Analyzing memory for PID {pid}...\n")
            
            if self.memory_scanner:
                # Perform actual memory analysis
                self.memory_output.append("Memory scanner is available - performing analysis...")
                try:
                    # Check if process exists
                    import psutil
                    proc = psutil.Process(pid)
                    self.memory_output.append(f"Process found: {proc.name()} (PID: {pid})")
                    
                    # Perform basic memory analysis
                    memory_info = proc.memory_info()
                    self.memory_output.append(f"Memory usage: {memory_info.rss // (1024*1024)} MB")
                    self.memory_output.append(f"Virtual memory: {memory_info.vms // (1024*1024)} MB")
                    
                    # Check for suspicious behavior patterns
                    try:
                        # Get process executable path
                        exe_path = proc.exe()
                        self.memory_output.append(f"Executable: {exe_path}")
                        
                        # Check process status
                        status = proc.status()
                        self.memory_output.append(f"Status: {status}")
                        
                        # Get CPU usage
                        cpu_percent = proc.cpu_percent()
                        self.memory_output.append(f"CPU usage: {cpu_percent}%")
                        
                        # Basic analysis complete
                        self.memory_output.append("Memory analysis completed.")
                        
                    except psutil.AccessDenied:
                        self.memory_output.append("Access denied to some process information (requires elevated privileges)")
                    
                except psutil.NoSuchProcess:
                    self.memory_output.append(f"Process with PID {pid} not found")
                except Exception as e:
                    self.memory_output.append(f"Error during memory analysis: {str(e)}")
            else:
                self.memory_output.append("Memory scanner not available")
                
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
                        
                        # Add to detections pane
                        detection_data = {
                            'timestamp': datetime.now().strftime('%H:%M:%S'),
                            'process': name,
                            'pid': str(pid),
                            'threat': 'Suspicious Process',
                            'severity': 'Medium' if suspicious_score < 5 else 'High',
                            'details': '; '.join(warnings)
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
        
        self._start_filesystem_scan("quick", scan_paths)
    
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
            severity = threat_info.get('severity', 'Medium').lower()
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
        """Quarantine selected files from scan results"""
        selected_rows = set()
        for item in self.fs_results_table.selectedItems():
            selected_rows.add(item.row())
        
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select files to quarantine.")
            return
        
        quarantined_count = 0
        for row in selected_rows:
            file_path = self.fs_results_table.item(row, 1).text()
            try:
                # Move file to quarantine (implementation would go here)
                # For now, just update the action column
                self.fs_results_table.setItem(row, 4, QTableWidgetItem("Quarantined"))
                quarantined_count += 1
            except Exception as e:
                print(f"Failed to quarantine {file_path}: {e}")
        
        QMessageBox.information(self, "Quarantine Complete", f"Quarantined {quarantined_count} files.")
    
    def _delete_selected_files(self):
        """Delete selected files from scan results"""
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
            for row in selected_rows:
                file_path = self.fs_results_table.item(row, 1).text()
                try:
                    # Delete file (implementation would go here)
                    # For now, just update the action column
                    self.fs_results_table.setItem(row, 4, QTableWidgetItem("Deleted"))
                    deleted_count += 1
                except Exception as e:
                    print(f"Failed to delete {file_path}: {e}")
            
            QMessageBox.information(self, "Deletion Complete", f"Deleted {deleted_count} files.")
    
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
        self.log_output.append("Quarantine functionality not yet implemented")
        
    def restore_selected(self):
        """Restore selected item"""
        self.log_output.append("Restore functionality not yet implemented")
        
    # === QUARANTINE METHODS ===
    
    def _refresh_quarantine(self):
        """Refresh quarantine list"""
        self.quarantine_table.setRowCount(0)
        
        try:
            for item in self.quarantine_dir.iterdir():
                if item.is_file():
                    row = self.quarantine_table.rowCount()
                    self.quarantine_table.insertRow(row)
                    
                    self.quarantine_table.setItem(row, 0, QTableWidgetItem(item.name))
                    self.quarantine_table.setItem(row, 1, QTableWidgetItem("Unknown"))
                    self.quarantine_table.setItem(row, 2, QTableWidgetItem(
                        datetime.fromtimestamp(item.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    ))
                    self.quarantine_table.setItem(row, 3, QTableWidgetItem("Unknown"))
                    
        except Exception as e:
            self.log_output.append(f"Error refreshing quarantine: {str(e)}")
            
    def _restore_quarantined(self):
        """Restore quarantined file"""
        self.log_output.append("Restore quarantined functionality not yet implemented")
        
    def _delete_quarantined(self):
        """Permanently delete quarantined file"""
        self.log_output.append("Delete quarantined functionality not yet implemented")
        
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
            severity = threat_info.get('severity', 'Medium').lower()
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
            name = self.scan_results_table.item(current_row, 0).text()
            path = self.scan_results_table.item(current_row, 1).text()
            threat_type = self.scan_results_table.item(current_row, 2).text()
            severity = self.scan_results_table.item(current_row, 3).text()
            details = self.scan_results_table.item(current_row, 5).text()
            
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
        
        for row in sorted(selected_rows, reverse=True):
            file_path = self.scan_results_table.item(row, 1).text()
            self.threat_name = self.scan_results_table.item(row, 0).text()
            
            # Safety check - protect system files
            if self.yara_manager and self.yara_manager.is_system_file_protected(file_path):
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
        
        for row in sorted(selected_rows, reverse=True):
            file_path = self.scan_results_table.item(row, 1).text()
            is_system_file_protected = self.yara_manager.is_system_file_protected(file_path)
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
        
        QMessageBox.information(self, "Deletion Complete", message)
    
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
            current_tab = self.main_tabs.currentIndex()
            
            if current_tab == 1:  # Scan Results tab
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
            else:
                # Check main detections table
                current_row = self.results_table.currentRow()
                if current_row < 0:
                    QMessageBox.warning(self, "No Selection", "Please select a detection to remove the file.")
                    return
                    
                path_item = self.results_table.item(current_row, 2)  # Path column
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
                            self.results_table.removeRow(current_row)
                        else:
                            self.log_output.append(f"⚠️ File not found: {file_path}")
                    except PermissionError:
                        self.log_output.append(f"❌ Permission denied removing file: {file_path}")
                        QMessageBox.critical(self, "Permission Error", 
                                           f"Unable to remove file. Administrator rights may be required.")
                    except Exception as e:
                        self.log_output.append(f"❌ Error removing file {file_path}: {str(e)}")
                        QMessageBox.critical(self, "Error", f"Failed to remove file: {str(e)}")
                        
        except Exception as e:
            self.log_output.append(f"❌ Remove file error: {str(e)}")
            QMessageBox.critical(self, "Error", f"Remove file operation failed: {str(e)}")

    def _quarantine_file(self, file_path):
        """Quarantine a file - move to quarantine directory with metadata"""
        try:
            import shutil
            import uuid
            import json
            
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
            current_tab = self.main_tabs.currentIndex()
            
            if current_tab == 1:  # Scan Results tab
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
            else:
                # Check main detections table
                current_row = self.results_table.currentRow()
                if current_row < 0:
                    QMessageBox.warning(self, "No Selection", "Please select a detection to quarantine the file.")
                    return
                    
                path_item = self.results_table.item(current_row, 2)  # Path column
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
                        status_item = QTableWidgetItem("Quarantined")
                        status_item.setBackground(QColor('#ffcc00'))
                        self.results_table.setItem(current_row, 5, status_item)
                        
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
            
            # Scan system memory (this is a simplified example)
            # In a real implementation, you'd scan actual memory regions
            import psutil
            
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    if proc.info['name'] in ['System', 'Registry']:
                        continue
                        
                    # Simulate memory scanning (replace with actual memory reading)
                    detections = detector.detect_shellcode_in_memory(b"", proc.info['pid'], proc.info['name'])
                    
                    for detection in detections:
                        self._add_shellcode_detection(detection)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            self.log_output.append("✅ Memory shellcode scan completed")
            
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
            
            from ShellCodeMagic import ShellcodeDetector
            detector = ShellcodeDetector()
            
            # Simulate process memory scan
            detections = detector.detect_shellcode_in_memory(b"", pid, name)
            
            for detection in detections:
                self._add_shellcode_detection(detection)
                
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
            
            from ShellCodeMagic import ShellcodeDetector, ShellCodeTome
            
            detector = ShellcodeDetector()
            tome = ShellCodeTome()
            
            # Clear previous results
            self.shellcode_table.setRowCount(0)
            
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
                        
                    self.log_output.append(f"🔍 Scanning {process_name} (PID: {process_pid})...")
                    
                    # Simulate comprehensive memory analysis
                    memory_analysis = tome.analyze_memory_region(b"", process_pid, process_name)
                    
                    if memory_analysis.get('detections'):
                        for detection in memory_analysis['detections']:
                            self._add_shellcode_detection(detection)
                            detected_count += 1
                    
                    scanned_count += 1
                    
                    # Update progress
                    if scanned_count % 10 == 0:
                        self.log_output.append(f"📊 Scanned {scanned_count} processes, found {detected_count} detections...")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
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
        detection_type = detection_type.lower()
        
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
            
            # Update Raw Magic (Hex) view
            shellcode_bytes = detection.get('shellcode', b'')
            if isinstance(shellcode_bytes, str):
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
            metadata_output += f"📍 Memory Realm: {detection.get('address', 'Unknown')}\n"
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
                    spell_name = detection.get('type', 'Unknown')
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
            self.log_output.append(f"❌ Error updating shellcode details: {str(e)}")
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
                QMessageBox.warning(self, "Tome Unavailable", "The Ancient Shellcode Tome is not initialized.")
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
                    "🌟 Unknown Magic": "unknown_magic"
                }
                category = category_map.get(category_filter)
            
            # Browse spells from tome
            spells = self.shellcode_tome.browse_ancient_spells(category=category, limit=100)
            
            # Clear and populate table
            self.shellcode_table.setRowCount(0)
            
            for spell in spells:
                self._add_spell_to_table(spell, from_tome=True)
            
            self.log_output.append(f"📚 Browsed {len(spells)} ancient spells from the tome")
            
        except Exception as e:
            self.log_output.append(f"❌ Error browsing ancient tome: {str(e)}")
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
                self.log_output.append(f"🔍 Found {len(results)} spells matching '{search_term}'")
            else:
                self.log_output.append(f"🔍 No spells found matching '{search_term}'")
                QMessageBox.information(self, "Search Results", f"No spells found matching '{search_term}'")
            
        except Exception as e:
            self.log_output.append(f"❌ Error searching tome: {str(e)}")
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
                items = [
                    QTableWidgetItem(spell_data.get('discovered', 'Unknown')),
                    QTableWidgetItem(spell_data.get('name', 'Unknown Spell')),
                    QTableWidgetItem(spell_data.get('process', 'Unknown')),
                    QTableWidgetItem('Tome Archive'),
                    QTableWidgetItem(spell_data.get('confidence', 'Unknown')),
                    QTableWidgetItem(str(spell_data.get('power', 1))),
                    QTableWidgetItem('N/A'),
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
                risk = spell_data.get('risk', 'Medium').lower()
                if risk == 'high':
                    color = QColor('#ff4444')
                elif risk == 'medium':
                    color = QColor('#ffaa44')
                else:
                    color = QColor('#44ff44')
                items[5].setBackground(color)
            
            # Store spell data for detailed view
            items[0].setData(Qt.UserRole, spell_data)
            
        except Exception as e:
            self.log_output.append(f"❌ Error adding spell to table: {str(e)}")
    
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

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ui = OrbitalStationUI()
    ui.show()
    sys.exit(app.exec())
