"""Test HadesAI import with PySide6"""
import sys

print("Testing HadesAI import with PySide6...")

# Import PySide6 first (like OFSP does)
from PySide6.QtWidgets import QApplication
app = QApplication(sys.argv)
print("  PySide6 QApplication created")

# Now import HadesAI
try:
    import HadesAI
    print("  HadesAI imported successfully!")
    print(f"  - Qt Backend: {getattr(HadesAI, 'QT_BACKEND', 'Unknown')}")
    print(f"  - KnowledgeBase: {hasattr(HadesAI, 'KnowledgeBase')}")
    print(f"  - ChatProcessor: {hasattr(HadesAI, 'ChatProcessor')}")
    print(f"  - BrowserScanner: {hasattr(HadesAI, 'BrowserScanner')}")
    print(f"  - NetworkMonitor: {hasattr(HadesAI, 'NetworkMonitor')}")
    
    # Test creating instances
    print("\nTesting component instantiation...")
    kb = HadesAI.KnowledgeBase()
    print(f"  - KnowledgeBase instance: OK")
    
    chat = HadesAI.ChatProcessor(kb)
    print(f"  - ChatProcessor instance: OK")
    
    print("\n✅ All HadesAI tests PASSED!")
    
except Exception as e:
    print(f"  ERROR: {e}")
    import traceback
    traceback.print_exc()
    print("\n❌ HadesAI tests FAILED!")

sys.exit(0)
