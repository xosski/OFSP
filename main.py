#!/usr/bin/env python3
"""
Orbital Station: Malware Defense Console
Main entry point for the application

This is the primary launcher that initializes and starts the Orbital Station GUI application.
"""

import sys
import os
import ctypes
import logging
from pathlib import Path

# Import shared constants and utilities
from shared_constants import setup_application_logging, is_admin

def main():
    """Main application entry point"""
    
    # Set up logging first
    logger = setup_application_logging()
    logger.info("Starting Orbital Station application")
    
    # Check for admin privileges
    if not is_admin():
        logger.warning("Application not running with administrator privileges")
        logger.info("Requesting elevation...")
        try:
            # Request elevation
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, f'"{__file__}"', None, 1
            )
            sys.exit(0)
        except Exception as e:
            logger.error(f"Failed to elevate privileges: {str(e)}")
            print(f"Error: Failed to get administrator privileges: {str(e)}")
            print("Please run this application as Administrator")
            return False
    
    logger.info("Running with administrator privileges")
    
    try:
        # Try to use PySide6 UI first
        try:
            from PySide6.QtWidgets import QApplication
            from OrbitalStationUI import OrbitalStationUI
            
            logger.info("Initializing PySide6 GUI")
            app = QApplication(sys.argv)
            ui = OrbitalStationUI()
            ui.show()
            
            logger.info("Starting PySide6 event loop")
            return app.exec()
            
        except ImportError as e:
            logger.warning(f"PySide6 not available: {e}")
            logger.info("Falling back to tkinter GUI")
            
            # Fallback to tkinter - try ScannerGui first
            try:
                import tkinter as tk
                from ScannerGui import ScannerGui
                
                logger.info("Initializing original ScannerGui (tkinter)")
                root = tk.Tk()
                root.title("Orbital Station: Memory Protection Scanner")
                root.geometry("800x600")
                
                # Initialize the original scanner GUI
                app = ScannerGui(root)
                
                logger.info("Starting ScannerGui event loop")
                root.mainloop()
                return True
                
            except ImportError as e2:
                logger.warning(f"ScannerGui not available: {e2}")
                logger.info("Falling back to basic tkinter interface")
                
                # Final fallback - basic tkinter
                try:
                    import tkinter as tk
                    
                    root = tk.Tk()
                    root.title("Orbital Station: Malware Defense Console")
                    root.geometry("800x600")
                    
                    # Basic message for now
                    label = tk.Label(root, text="Orbital Station GUI (Basic Mode)\nModules loading...", 
                                   font=("Consolas", 12))
                    label.pack(expand=True)
                    
                    # Try to load available modules
                    status_text = "Available modules:\n"
                    
                    try:
                        import YaraRuleManager
                        status_text += "✓ YARA Rule Manager\n"
                    except ImportError:
                        status_text += "✗ YARA Rule Manager\n"
                    
                    try:
                        import Memory
                        status_text += "✓ Memory Scanner\n"
                    except ImportError:
                        status_text += "✗ Memory Scanner\n"
                    
                    try:
                        import Weapons_Systems
                        status_text += "✓ Weapons Systems\n"
                    except ImportError:
                        status_text += "✗ Weapons Systems\n"
                    
                    try:
                        import ShellCodeMagic
                        status_text += "✓ ShellCode Magic\n"
                    except ImportError:
                        status_text += "✗ ShellCode Magic\n"
                    
                    label.config(text=status_text)
                    
                    logger.info("Starting basic tkinter event loop")
                    root.mainloop()
                    return True
                    
                except ImportError:
                    logger.error("No GUI framework available (neither PySide6 nor tkinter)")
                    print("Error: No GUI framework available")
                    return False
                
    except Exception as e:
        logger.exception("Fatal error occurred during startup")
        print(f"Fatal error: {str(e)}")
        return False

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        sys.exit(1)
