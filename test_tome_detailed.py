#!/usr/bin/env python3

print("=== DETAILED TOME DEBUGGING ===")

# Test 1: Import and basic creation
print("\n1. Testing imports and creation...")
try:
    from ShellCodeMagic import ShellcodeDetector, ShellCodeTome
    print("   [OK] Imports successful")
    
    detector = ShellcodeDetector()
    print("   [OK] ShellcodeDetector created")
    print(f"   Detector type: {type(detector)}")
    print(f"   Detector attributes: {[attr for attr in dir(detector) if not attr.startswith('_')]}")
    
    tome = ShellCodeTome()
    print("   [OK] ShellCodeTome created")
    print(f"   Tome type: {type(tome)}")
    
except Exception as e:
    print(f"   [ERROR] Import/creation failed: {e}")
    import traceback
    traceback.print_exc()

# Test 2: Test detect_shellcode_in_memory directly
print("\n2. Testing detect_shellcode_in_memory directly...")
try:
    from ShellCodeMagic import ShellcodeDetector
    detector = ShellcodeDetector()
    
    print("   Testing method existence...")
    if hasattr(detector, 'detect_shellcode_in_memory'):
        print("   [OK] detect_shellcode_in_memory method exists")
        
        print("   Testing method call...")
        result = detector.detect_shellcode_in_memory(b"test\x90\x90\x90\x90", 1000, "test_process")
        print(f"   [OK] Method call successful, result type: {type(result)}")
        print(f"   Result length: {len(result) if hasattr(result, '__len__') else 'No length'}")
        print(f"   Result sample: {str(result)[:200]}...")
        
    else:
        print("   [ERROR] detect_shellcode_in_memory method does NOT exist")
        print(f"   Available methods: {[m for m in dir(detector) if 'detect' in m.lower()]}")

except Exception as e:
    print(f"   [ERROR] detect_shellcode_in_memory test failed: {e}")
    import traceback
    traceback.print_exc()

# Test 3: Test tome analyze_memory_region in detail
print("\n3. Testing tome analyze_memory_region in detail...")
try:
    from ShellCodeMagic import ShellCodeTome
    tome = ShellCodeTome()
    
    print("   Testing basic call...")
    result = tome.analyze_memory_region(b"test\x90\x90\x90\x90", 1000, "test_process")
    print(f"   [OK] Basic call successful, result: {result}")
    
    print("   Testing with larger data...")
    larger_data = b"test" * 20 + b"\x90" * 50 + b"\x48\x31\xc0" * 10  # More realistic shellcode-like data
    result2 = tome.analyze_memory_region(larger_data, 2000, "larger_test_process")
    print(f"   [OK] Larger data call successful, result: {result2}")
    
except Exception as e:
    print(f"   [ERROR] tome analyze_memory_region failed: {e}")
    import traceback
    traceback.print_exc()

# Test 4: Test what happens inside analyze_memory_region
print("\n4. Testing analyze_memory_region internals...")
try:
    from ShellCodeMagic import ShellCodeTome
    tome = ShellCodeTome()
    
    # Check if tome has Magic attribute
    print(f"   Tome has Magic attribute: {hasattr(tome, 'Magic')}")
    
    # Try to initialize Magic manually
    if not hasattr(tome, 'Magic'):
        print("   Manually initializing Magic...")
        from ShellCodeMagic import ShellcodeDetector
        tome.Magic = ShellcodeDetector()
        print("   [OK] Magic initialized manually")
    
    print(f"   Magic type: {type(tome.Magic)}")
    print(f"   Magic has scan_for_shellcode: {hasattr(tome.Magic, 'scan_for_shellcode')}")
    
    # Test scan_for_shellcode directly
    if hasattr(tome.Magic, 'scan_for_shellcode'):
        print("   Testing scan_for_shellcode...")
        scan_result = tome.Magic.scan_for_shellcode(
            b"test\x90\x90\x90\x90", 
            base_address=1000,
            process_info={'name': 'test', 'pid': 1000, 'memory_region': 'test'}
        )
        print(f"   [OK] scan_for_shellcode result: {type(scan_result)} - {scan_result}")
    
except Exception as e:
    print(f"   [ERROR] analyze_memory_region internals failed: {e}")
    import traceback
    traceback.print_exc()

print("\n=== DEBUG COMPLETE ===")
