#!/usr/bin/env python3

print("Starting Memory import test...")

# Test imports one by one
try:
    print("1. Testing ctypes...")
    import ctypes
    print("   ctypes OK")
    
    print("2. Testing logging...")
    import logging
    print("   logging OK")
    
    print("3. Testing psutil...")
    import psutil
    print("   psutil OK")
    
    print("4. Testing YaraRuleManager...")
    import YaraRuleManager
    print("   YaraRuleManager OK")
    
    print("5. Testing shared_constants...")
    import shared_constants
    print("   shared_constants OK")
    
    print("6. Testing wmi...")
    import wmi
    print("   wmi OK")
    
    print("7. Now testing Memory module...")
    import Memory
    print("   Memory imported successfully!")
    
    print("8. Creating MemoryScanner...")
    scanner = Memory.MemoryScanner()
    print("   MemoryScanner created successfully!")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
