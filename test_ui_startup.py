"""Test UI startup to find crash point"""
import sys
import traceback

print("Starting UI test...")
sys.stdout.flush()

try:
    print("Step 1: Importing PySide6...")
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt
    print("  OK")
    
    print("Step 2: Creating QApplication...")
    app = QApplication(sys.argv)
    print("  OK")
    
    print("Step 3: Importing OrbitalStationUI module...")
    import OrbitalStationUI_Complete as ui_mod
    print("  OK")
    
    print("Step 4: Creating OrbitalStationUI instance...")
    sys.stdout.flush()
    
    # Wrap the UI creation with detailed tracing
    class TracedUI(ui_mod.OrbitalStationUI):
        def __init__(self):
            print("  4a: Calling super().__init__...")
            sys.stdout.flush()
            try:
                # Call QMainWindow init only
                from PySide6.QtWidgets import QMainWindow
                QMainWindow.__init__(self)
                self.setWindowTitle("Orbital Station: Malware Defense Console")
                self.setGeometry(100, 100, 1400, 900)
                print("  4b: QMainWindow init done")
                
                # Initialize GUI variables
                self.scanning = False
                self.monitoring_active = False
                self.total_processes_scanned = 0
                self.threats_found = 0
                self.detections = []
                self.scan_worker = None
                print("  4c: GUI variables initialized")
                
                # Pre-initialize backend attributes
                self.memory_scanner = None
                self.yara_manager = None
                self.rules_loaded = False
                self.compiled_rules = None
                self.shellcode_detector = None
                self.shellcode_tome = None
                self.code_disassembler = None
                self.threat_quarantine = None
                self.malware_scanner = None
                print("  4d: Backend attrs pre-initialized")
                
                # Setup styling
                print("  4e: Setting up styling...")
                self._setup_styling()
                print("  4f: Styling done")
                
                # Create UI
                print("  4g: Creating UI...")
                sys.stdout.flush()
                self._create_ui()
                print("  4h: UI created")
                
                # Show window
                self.show()
                app.processEvents()
                print("  4i: Window shown")
                
                # Init backend
                print("  4j: Initializing backend...")
                sys.stdout.flush()
                self._init_backend()
                print("  4k: Backend initialized")
                
                # Init protection
                print("  4l: Initializing protection...")
                self.initial_protection()
                print("  4m: Protection initialized")
                
            except Exception as e:
                print(f"  ERROR in __init__: {e}")
                traceback.print_exc()
                raise
    
    ui = TracedUI()
    print("Step 5: UI created successfully")
    
    print("Step 6: Starting event loop...")
    sys.exit(app.exec())
    
except Exception as e:
    print(f"\nFATAL ERROR: {type(e).__name__}: {e}")
    traceback.print_exc()
    sys.exit(1)
