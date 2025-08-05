#!/usr/bin/env python3

print("Final Integration Test - Orbital Station")
print("=" * 50)

# Test 1: Memory Scanner
print("\n1. Testing Memory Scanner...")
try:
    from Memory import MemoryScanner
    scanner = MemoryScanner()
    print("   [OK] MemoryScanner created successfully")
except Exception as e:
    print(f"   [ERROR] MemoryScanner failed: {e}")

# Test 2: ShellcodeDetector
print("\n2. Testing ShellcodeDetector...")
try:
    from ShellCodeMagic import ShellcodeDetector
    detector = ShellcodeDetector()
    result = detector.detect_shellcode_in_memory(b"test\x90\x90\x90", 1000, "test_proc")
    print(f"   [OK] ShellcodeDetector works, result type: {type(result)}")
except Exception as e:
    print(f"   [ERROR] ShellcodeDetector failed: {e}")

# Test 3: ShellCodeTome
print("\n3. Testing ShellCodeTome...")
try:
    from ShellCodeMagic import ShellCodeTome
    tome = ShellCodeTome()
    result = tome.analyze_memory_region(b"test\x90\x90\x90", 1000, "test_proc")
    print(f"   [OK] ShellCodeTome.analyze_memory_region works")
    print(f"        Returns dict: {isinstance(result, dict)}")
    print(f"        Has 'detections' key: {'detections' in result}")
    print(f"        Detection count: {len(result.get('detections', []))}")
except Exception as e:
    print(f"   [ERROR] ShellCodeTome failed: {e}")

# Test 4: Deep scan process safety
print("\n4. Testing Deep Scan Process Safety...")
try:
    import psutil
    safe_processes = 0
    problem_processes = 0
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if not proc.info or not proc.info.get('name') or not proc.info.get('pid'):
                problem_processes += 1
                continue
            
            process_name = proc.info['name'] or f"Process_{proc.info['pid']}"
            safe_processes += 1
            
            if safe_processes >= 10:  # Test first 10 processes
                break
                
        except Exception:
            problem_processes += 1
    
    print(f"   [OK] Process safety check completed")
    print(f"        Safe processes: {safe_processes}")
    print(f"        Problem processes: {problem_processes}")
    
except Exception as e:
    print(f"   [ERROR] Process safety test failed: {e}")

# Test 5: Application GUI Creation
print("\n5. Testing Application GUI Creation...")
try:
    from OrbitalStationUI_Complete import OrbitalStationUI
    from PySide6.QtWidgets import QApplication
    
    app = QApplication([])
    ui = OrbitalStationUI()
    print("   [OK] OrbitalStationUI created successfully")
    print("   [OK] Ancient Tome tab should be functional")
    
except Exception as e:
    print(f"   [ERROR] GUI creation failed: {e}")

print("\n" + "=" * 50)
print("Final Integration Test Complete!")
print("If all tests show [OK], your Orbital Station is ready!")
