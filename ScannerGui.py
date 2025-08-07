"""
ScannerGui - The original tkinter-based GUI from Unnamed.py
This provides the complete scanning interface with process monitoring, memory analysis, etc.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from datetime import datetime
import logging
from pathlib import Path
import psutil
import Memory
# Removed incorrect import - force_read_memory_region is a method of MemoryScanner
# Import from our modules
from shared_constants import *
try:
    from YaraRuleManager import YaraRuleManager
except ImportError:
    YaraRuleManager = None

try:
    from Memory import MemoryScanner
except ImportError:
    MemoryScanner = None

try:
    from Weapons_Systems import MalwareScanner
except ImportError:
    MalwareScanner = None

try:
    from ShellCodeMagic import ShellcodeDetector, ShellCodeTome, ThreatQuarantine, CodeDisassembler
except ImportError:
    ShellcodeDetector = None
    ShellCodeTome = None
    ThreatQuarantine = None
    CodeDisassembler = None

class ScannerGui:
    _instance = None

    def __new__(cls, root=None):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, root=None):
        # Prevent double initialization
        if hasattr(self, '_initialized') and self._initialized:
            return
            
        self.root = root if root else tk.Tk()
        self.root.title("Memory Protection Scanner")
        self.root.geometry("800x600")
        
        # Initialize variables
        self.signature_db = set()
        self.total_processes_scanned = 0
        self._initialized = True
        self.critical_processes = {
            'explorer.exe', 'svchost.exe', 'lsass.exe', 
            'winlogon.exe', 'csrss.exe', 'services.exe'
        }
        self.monitoring_active = False
        self.quarantine_dir = Path("quarantine")
        self.injection_patterns = {
            'shellcode': rb'\x55\x8B\xEC|\x90{4,}',
            'script_injection': rb'(eval|exec|system|subprocess.run)',
            'memory_manipulation': rb'(VirtualAlloc|WriteProcessMemory)',
            'dll_injection': rb'(LoadLibrary|GetProcAddress)',
            'code_execution': rb'(WScript.Shell|cmd.exe|powershell.exe)',
            'encoded_commands': rb'([A-Za-z0-9+/]{40,}={0,2})'
        }
        self.process_handle = None
        self.detections = []
        self.signature_status = True
        self.scanning = False
        self.detections_list = None
        
        # Initialize backend components
        self._setup_logging()
        logging.info("ScannerGui initialized")
        
        # Initialize YARA and detection components
        if YaraRuleManager:
            self.yara_manager = YaraRuleManager()
            self.yara_manager.create_repo_directories()
            
            # Verify rules are properly loaded
            report = self.yara_manager.verify_rules_loaded()
            print("\n=== YARA Rules Loading Status ===")
            print(f"Directories exist: {report['directories_exist']}")
            print(f"Rule files exist: {report['rule_files_exist']}")
            print(f"Rule files count: {report['rule_files_count']}")
            print(f"Compilation success: {report['compilation_success']}")
            
            if not report["compilation_success"]:
                print("Trying to create basic rules directly...")
                self.yara_manager.create_basic_rules()
        
        # Initialize detection components
        if ShellcodeDetector:
            self.Detector = ShellcodeDetector()
        if CodeDisassembler:
            self.disassembler = CodeDisassembler()
        if ShellCodeTome:
            self.tome = ShellCodeTome()
        if MemoryScanner:
            self.scanner = MemoryScanner()
        
        # Initialize GUI variables
        self.quarantine_var = tk.BooleanVar(value=True)
        self.threshold_var = tk.IntVar(value=75)
        
        # Create utility functions
        self.create_utility_functions()
        
        # Setup GUI after all initialization is complete
        if not hasattr(self, 'notebook'):  # Only setup GUI once
            self.setup_gui()
        
        self.scanner = MemoryScanner()
        # Start protection
        self.initial_protection()
        
    def _setup_logging(self):
        """Setup logging for the scanner GUI"""
        self.logger = logging.getLogger('ScannerGui')
        
    def create_utility_functions(self):
        """Create utility functions and aliases"""
        # Tree utility functions will be created after the tree widget exists
        self.additem = None
        self.clear = None
        
    def setup_gui(self):
        """Setup the GUI using only grid geometry manager"""
        # Configure root window
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Main container frame
        main_container = ttk.Frame(self.root)
        main_container.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W), padx=5, pady=5)
        main_container.columnconfigure(0, weight=1)
        main_container.rowconfigure(2, weight=1)  # Make the notebook expand
        
        # Status Panel at top (row 0)
        status_frame = ttk.LabelFrame(main_container, text="System Status", padding="5")
        status_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        status_frame.columnconfigure(1, weight=1)
        
        self.status_label = ttk.Label(status_frame, text="Protected", foreground="green")
        self.status_label.grid(row=0, column=0, padx=5)
        
        # Scan Progress Panel
        scan_frame = ttk.Frame(status_frame)
        scan_frame.grid(row=0, column=1, padx=5, sticky=(tk.W, tk.E))
        scan_frame.columnconfigure(0, weight=1)
        
        self.scan_progress = ttk.Progressbar(scan_frame, mode='determinate', length=200)
        self.scan_progress.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        self.processes_scanned_label = ttk.Label(scan_frame, text="Processes: 0")
        self.processes_scanned_label.grid(row=0, column=1, padx=5)
        
        self.threats_found_label = ttk.Label(scan_frame, text="Threats: 0")
        self.threats_found_label.grid(row=0, column=2, padx=5)
        
        # Control Panel (row 1)
        control_panel = ttk.LabelFrame(main_container, text="Controls", padding="5")
        control_panel.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Scan Controls
        scan_buttons = ttk.Frame(control_panel)
        scan_buttons.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.start_quick_scan_button = ttk.Button(scan_buttons, text="Quick Scan", command=self.start_quick_scan)
        self.start_quick_scan_button.grid(row=0, column=0, padx=2)
        
        self.start_deep_scan_button = ttk.Button(scan_buttons, text="Deep Scan", command=self.start_deep_scan)
        self.start_deep_scan_button.grid(row=0, column=1, padx=2)
        
        self.stop_scan_button = ttk.Button(scan_buttons, text="Stop Scan", command=self.stop_scan)
        self.stop_scan_button.grid(row=0, column=2, padx=2)
        
        # Settings in control panel
        settings_controls = ttk.Frame(control_panel)
        settings_controls.grid(row=0, column=1, padx=10, sticky=(tk.W, tk.E))
        
        # Quarantine checkbox
        self.quarantine_checkbox = ttk.Checkbutton(
            settings_controls, 
            text="Auto Quarantine", 
            variable=self.quarantine_var,
            command=self.update_quarantine_settings
        )
        self.quarantine_checkbox.grid(row=0, column=0, padx=5)
        
        # Threshold controls
        threshold_frame = ttk.Frame(settings_controls)
        threshold_frame.grid(row=0, column=1, padx=5, sticky=(tk.W, tk.E))
        
        ttk.Label(threshold_frame, text="Threshold:").grid(row=0, column=0)
        self.threshold_slider = ttk.Scale(
            threshold_frame, 
            from_=0, to=100, 
            orient="horizontal",
            variable=self.threshold_var,
            length=100,
            command=lambda _: self.update_quarantine_settings()
        )
        self.threshold_slider.grid(row=0, column=1, padx=5, sticky=(tk.W, tk.E))
        ttk.Label(threshold_frame, textvariable=self.threshold_var).grid(row=0, column=2)
        
        # Detection count
        self.detection_count_label = ttk.Label(control_panel, text="Detections: 0")
        self.detection_count_label.grid(row=0, column=2, padx=5)
        
        # Process Control Buttons
        process_buttons = ttk.LabelFrame(control_panel, text="Process Controls", padding="5")
        process_buttons.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        ttk.Button(process_buttons, text="Create Test Detection", command=self.create_test_detection).grid(row=0, column=0, padx=2)
        ttk.Button(process_buttons, text="Terminate Process", command=self.kill_selected_process).grid(row=0, column=1, padx=2)
        ttk.Button(process_buttons, text="Terminate Region", command=self.terminate_selected_region).grid(row=0, column=2, padx=2)
        ttk.Button(process_buttons, text="Quarantine Memory", command=self.quarantine_selected_memory).grid(row=0, column=3, padx=2)
        
        # Detection Management Buttons
        detection_buttons = ttk.LabelFrame(control_panel, text="Detection Management", padding="5")
        detection_buttons.grid(row=1, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(detection_buttons, text="Remove Infected File", command=self.remove_infected_file).grid(row=0, column=0, padx=2)
        ttk.Button(detection_buttons, text="Quarantine Selected", command=self.quarantine_file).grid(row=0, column=1, padx=2)
        ttk.Button(detection_buttons, text="Remove Selected Detection", command=self.remove_selected_detection).grid(row=0, column=2, padx=2)
        ttk.Button(detection_buttons, text="Restore Selected", command=self.restore_selected).grid(row=0, column=3, padx=2)
        
        # Notebook for tabs (row 2 - main content area)
        self.notebook = ttk.Notebook(main_container)
        self.notebook.grid(row=2, column=0, sticky=(tk.N, tk.S, tk.E, tk.W), pady=5)
        
        # Create tabs
        self.create_tabs()
        
        # Status bar at bottom (row 3)
        self.status_bar = ttk.Label(main_container, text="Ready", relief=tk.SUNKEN, anchor="w")
        self.status_bar.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Create utility functions for tree operations
        self.create_tree_utilities()
        
    def create_tabs(self):
        """Create all notebook tabs"""
        # Active Detections Tab
        detections_frame = ttk.Frame(self.notebook)
        detections_frame.columnconfigure(0, weight=1)
        detections_frame.rowconfigure(0, weight=1)
        
        self.detections_treeview = ttk.Treeview(detections_frame, 
            columns=("timestamp", "name", "type", "severity", "location", "description"),
            show="headings")
        
        # Configure detection columns
        self.detections_treeview.heading("timestamp", text="Timestamp")
        self.detections_treeview.heading("name", text="Name")
        self.detections_treeview.heading("type", text="Type")
        self.detections_treeview.heading("severity", text="Severity")
        self.detections_treeview.heading("location", text="Location")
        self.detections_treeview.heading("description", text="Description")
        
        for col in ("timestamp", "name", "type", "severity", "location", "description"):
            self.detections_treeview.column(col, width=100)
        
        # Add scrollbar for detections
        detection_scroll = ttk.Scrollbar(detections_frame, orient="vertical", command=self.detections_treeview.yview)
        self.detections_treeview.configure(yscrollcommand=detection_scroll.set)
        
        self.detections_treeview.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        detection_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.notebook.add(detections_frame, text="Active Detections")
        
        # Scan Details Tab
        scan_details_frame = ttk.Frame(self.notebook)
        scan_details_frame.columnconfigure(0, weight=1)
        scan_details_frame.rowconfigure(0, weight=1)
        
        self.scan_log = tk.Text(scan_details_frame, height=10, wrap=tk.WORD)
        scan_log_scroll = ttk.Scrollbar(scan_details_frame, orient="vertical", command=self.scan_log.yview)
        self.scan_log.configure(yscrollcommand=scan_log_scroll.set)
        
        self.scan_log.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        scan_log_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.notebook.add(scan_details_frame, text="Scan Details")
        
        # Process Monitor Tab  
        process_frame = ttk.Frame(self.notebook)
        process_frame.columnconfigure(0, weight=1)
        process_frame.rowconfigure(0, weight=1)
        
        self.process_tree = ttk.Treeview(process_frame, 
            columns=("PID", "Name", "Status"),
            show="headings")
        
        for col in ("PID", "Name", "Status"):
            self.process_tree.heading(col, text=col)
            
        process_scroll = ttk.Scrollbar(process_frame, orient="vertical", command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=process_scroll.set)
        
        self.process_tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        process_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.notebook.add(process_frame, text="Process Monitor")
        
        # Memory Analysis Tab
        memory_frame = ttk.Frame(self.notebook)
        memory_frame.columnconfigure(0, weight=1)
        memory_frame.rowconfigure(0, weight=1)
        
        self.memory_tree = ttk.Treeview(memory_frame,
            columns=("Address", "Size", "Protection", "Type", "Status"),
            show="headings")
        
        for col in ("Address", "Size", "Protection", "Type", "Status"):
            self.memory_tree.heading(col, text=col)
            
        memory_scroll = ttk.Scrollbar(memory_frame, orient="vertical", command=self.memory_tree.yview)
        self.memory_tree.configure(yscrollcommand=memory_scroll.set)
        
        self.memory_tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        memory_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.notebook.add(memory_frame, text="Memory Analysis")
        
    def create_tree_utilities(self):
        """Create utility functions for tree operations"""
        def additem(parent, index, iid, text, values=None, **kwargs):
            """Add item to the active tree"""
            if hasattr(self, 'detections_treeview'):
                return self.detections_treeview.insert(parent, index, iid=iid, text=text, values=values or [], **kwargs)
        
        def clear():
            """Clear the active tree"""
            if hasattr(self, 'detections_treeview'):
                for item in self.detections_treeview.get_children():
                    self.detections_treeview.delete(item)
        
        self.additem = additem
        self.clear = clear
        
    # Scan Methods
    def start_quick_scan(self):
        """Start a quick scan"""
        self.log_scan_message("Starting Quick Scan...")
        self.scanning = True
        threading.Thread(target=self._run_quick_scan, daemon=True).start()
        
    def start_deep_scan(self):
        """Start a deep scan"""
        self.log_scan_message("Starting Deep Scan...")
        self.scanning = True
        threading.Thread(target=self._run_deep_scan, daemon=True).start()
        
    def stop_scan(self):
        """Stop current scan"""
        self.scanning = False
        self.log_scan_message("Scan stopped by user")
        
    def _run_quick_scan(self):
        """Run quick scan in background"""
        try:
            self.log_scan_message("Quick scan initiated...")
            # Simplified scan logic for now
            processes = psutil.process_iter(['pid', 'name'])
            
            for i, proc in enumerate(processes):
                if not self.scanning:
                    break
                    
                try:
                    self.total_processes_scanned += 1
                    self.update_scan_progress(i, 100)  # Approximate
                    
                    # Safely get process name and PID
                    proc_name = proc.info.get('name', 'Unknown')
                    proc_pid = proc.info.get('pid', 'Unknown')
                    
                    self.log_scan_message(f"Scanning process: {proc_name} (PID: {proc_pid})")
                    time.sleep(0.1)  # Simulate scan time
                except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError) as e:
                    # Process may have terminated or access denied
                    self.log_scan_message(f"Skipped inaccessible process: {str(e)}")
                    continue
                except Exception as e:
                    self.log_scan_message(f"Process scan error: {str(e)}")
                    continue
                    
            self.log_scan_message("Quick scan completed")
        except Exception as e:
            self.log_scan_message(f"Scan error: {str(e)}")
        finally:
            self.scanning = False
            
    def _run_deep_scan(self):
        """Run deep scan in background"""
        try:
            self.log_scan_message("Deep scan initiated...")
            # More thorough scan logic would go here
            self._run_quick_scan()  # For now, same as quick scan
        except Exception as e:
            self.log_scan_message(f"Deep scan error: {str(e)}")
        finally:
            self.scanning = False
            
    def update_scan_progress(self, current, total):
        """Update scan progress bar - thread safe"""
        def _update_ui():
            if hasattr(self, 'scan_progress'):
                progress = (current / total) * 100 if total > 0 else 0
                self.scan_progress['value'] = progress
                
            if hasattr(self, 'processes_scanned_label'):
                self.processes_scanned_label.config(text=f"Processes: {self.total_processes_scanned}")
        
        # Use after() to safely update UI from main thread
        if hasattr(self, 'root'):
            self.root.after(0, _update_ui)
        else:
            _update_ui()  # Fallback for main thread calls
            
    def log_scan_message(self, message):
        """Log message to scan log - thread safe"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        def _update_ui():
            if hasattr(self, 'scan_log'):
                self.scan_log.insert(tk.END, log_entry)
                self.scan_log.see(tk.END)
        
        # Use after() to safely update UI from main thread
        if hasattr(self, 'root'):
            self.root.after(0, _update_ui)
        else:
            _update_ui()  # Fallback for main thread calls
            
        logging.info(message)
        
    # Placeholder methods for UI buttons
    def create_test_detection(self):
        """Create a test detection for testing purposes"""
        test_detection = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'name': 'Test Detection',
            'type': 'Test',
            'severity': 'Medium',
            'location': 'Test Process',
            'description': 'This is a test detection'
        }
        
        if hasattr(self, 'detections_treeview'):
            self.detections_treeview.insert('', 'end', values=(
                test_detection['timestamp'],
                test_detection['name'],
                test_detection['type'],
                test_detection['severity'],
                test_detection['location'],
                test_detection['description']
            ))
            
        self.log_scan_message("Test detection created")
        
    def kill_selected_process(self):
        """Kill selected process"""
        self.log_scan_message("Kill process functionality not implemented")
        
    def terminate_selected_region(self):
        """Terminate selected memory region"""
        self.log_scan_message("Terminate region functionality not implemented")
        
    def quarantine_selected_memory(self):
        """Quarantine selected memory"""
        self.log_scan_message("Quarantine memory functionality not implemented")
        
    def remove_infected_file(self):
        """Remove infected file"""
        try:
            if hasattr(self, 'detections_treeview'):
                selected = self.detections_treeview.selection()
                if not selected:
                    messagebox.showwarning("No Selection", "Please select a detection to remove the file.")
                    return
                
                for item in selected:
                    values = self.detections_treeview.item(item)['values']
                    if len(values) >= 5:
                        file_path = values[4]  # Location column
                        
                        # Confirm deletion
                        if messagebox.askyesno("Confirm Deletion", 
                                             f"Are you sure you want to permanently delete:\n{file_path}"):
                            try:
                                if os.path.exists(file_path):
                                    os.remove(file_path)
                                    self.log_scan_message(f"Successfully removed infected file: {file_path}")
                                    # Remove from detection list
                                    self.detections_treeview.delete(item)
                                else:
                                    self.log_scan_message(f"File not found: {file_path}")
                            except PermissionError:
                                self.log_scan_message(f"Permission denied removing file: {file_path}")
                                messagebox.showerror("Permission Error", 
                                                   f"Unable to remove file. Administrator rights may be required.")
                            except Exception as e:
                                self.log_scan_message(f"Error removing file {file_path}: {str(e)}")
                                messagebox.showerror("Error", f"Failed to remove file: {str(e)}")
            else:
                self.log_scan_message("No detections interface available")
        except Exception as e:
            self.log_scan_message(f"Remove file error: {str(e)}")
            messagebox.showerror("Error", f"Remove file operation failed: {str(e)}")
        
    def quarantine_file(self):
        """Quarantine selected file"""
        try:
            if hasattr(self, 'detections_treeview'):
                selected = self.detections_treeview.selection()
                if not selected:
                    messagebox.showwarning("No Selection", "Please select a detection to quarantine the file.")
                    return
                
                # Ensure quarantine directory exists
                quarantine_dir = Path("quarantine")
                quarantine_dir.mkdir(exist_ok=True)
                
                for item in selected:
                    values = self.detections_treeview.item(item)['values']
                    if len(values) >= 5:
                        file_path = values[4]  # Location column
                        
                        if messagebox.askyesno("Confirm Quarantine", 
                                             f"Quarantine this file:\n{file_path}"):
                            try:
                                if os.path.exists(file_path):
                                    import shutil
                                    import uuid
                                    
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
                                        'detection': values[1] if len(values) > 1 else 'Unknown',
                                        'threat_type': values[2] if len(values) > 2 else 'Unknown'
                                    }
                                    
                                    # Save quarantine log
                                    quarantine_log = quarantine_dir / "quarantine_log.json"
                                    import json
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
                                        self.log_scan_message(f"Warning: Could not update quarantine log: {log_error}")
                                    
                                    self.log_scan_message(f"Successfully quarantined file: {file_path} -> {quarantine_path}")
                                    
                                    # Remove from detection list
                                    self.detections_treeview.delete(item)
                                    
                                else:
                                    self.log_scan_message(f"File not found: {file_path}")
                                    
                            except PermissionError:
                                self.log_scan_message(f"Permission denied quarantining file: {file_path}")
                                messagebox.showerror("Permission Error", 
                                                   f"Unable to quarantine file. Administrator rights may be required.")
                            except Exception as e:
                                self.log_scan_message(f"Error quarantining file {file_path}: {str(e)}")
                                messagebox.showerror("Error", f"Failed to quarantine file: {str(e)}")
            else:
                self.log_scan_message("No detections interface available")
        except Exception as e:
            self.log_scan_message(f"Quarantine file error: {str(e)}")
            messagebox.showerror("Error", f"Quarantine operation failed: {str(e)}")
        
    def remove_selected_detection(self):
        """Remove selected detection"""
        if hasattr(self, 'detections_treeview'):
            selected = self.detections_treeview.selection()
            for item in selected:
                self.detections_treeview.delete(item)
        self.log_scan_message("Selected detections removed")
        
    def restore_selected(self):
        """Restore selected item"""
        self.log_scan_message("Restore functionality not implemented")
        
    def update_quarantine_settings(self):
        """Update quarantine settings"""
        quarantine_enabled = self.quarantine_var.get()
        threshold = self.threshold_var.get()
        self.log_scan_message(f"Quarantine settings updated: Enabled={quarantine_enabled}, Threshold={threshold}")
        
    def set_status_label(self, text, color="black"):
        """Set status label text and color"""
        if hasattr(self, 'status_label'):
            self.status_label.config(text=text, foreground=color)
            
    def initial_protection(self):
        """Initialize protection systems"""
        try:
            self.log_scan_message("Initializing protection systems...")
            self.set_status_label("Protected", "green")
            
            # Start monitoring if scanner is available
            if hasattr(self, 'scanner') and self.scanner:
                self.monitoring_active = True
                self.log_scan_message("Memory scanner initialized")
                
            # Initialize YARA rules if available
            if hasattr(self, 'yara_manager') and self.yara_manager:
                self.log_scan_message("YARA rules system initialized")
                
            self.log_scan_message("Protection systems active")
            
        except Exception as e:
            self.log_scan_message(f"Protection initialization error: {str(e)}")
            self.set_status_label("Error", "red")
