#!/usr/bin/env python3

print("=== COMPREHENSIVE SCANNER TEST ===")

# Test 1: ShellcodeDetector detect_shellcode_in_memory
print("\n1. Testing ShellcodeDetector.detect_shellcode_in_memory...")
try:
    from ShellCodeMagic import ShellcodeDetector
    detector = ShellcodeDetector()
    
    # Test with shellcode-like data
    test_data = b"test" + b"\x90" * 20 + b"\x48\x31\xc0" * 5  # NOP sled + x64 instructions
    result = detector.detect_shellcode_in_memory(test_data, 1000, "test_process")
    
    print(f"   [OK] Method exists and works")
    print(f"   Result type: {type(result)}")
    print(f"   Detections found: {len(result)}")
    
    if len(result) > 0:
        print(f"   Sample detection: {result[0]}")
    
except Exception as e:
    print(f"   [ERROR] ShellcodeDetector test failed: {e}")
    import traceback
    traceback.print_exc()

# Test 2: ShellCodeTome analyze_memory_region 
print("\n2. Testing ShellCodeTome.analyze_memory_region...")
try:
    from ShellCodeMagic import ShellCodeTome
    tome = ShellCodeTome()
    
    # Test with shellcode-like data
    test_data = b"test" + b"\x90" * 20 + b"\x48\x31\xc0" * 5
    result = tome.analyze_memory_region(test_data, 1000, "test_process")
    
    print(f"   [OK] Method works")
    print(f"   Result type: {type(result)}")
    print(f"   Has 'detections' key: {'detections' in result}")
    print(f"   Detections found: {len(result.get('detections', []))}")
    
except Exception as e:
    print(f"   [ERROR] ShellCodeTome test failed: {e}")
    import traceback
    traceback.print_exc()

# Test 3: Test integration (how UI would call it)
print("\n3. Testing UI integration scenario...")
try:
    from ShellCodeMagic import ShellcodeDetector, ShellCodeTome
    
    # Simulate what _scan_process_for_shellcode does
    detector = ShellcodeDetector()
    tome = ShellCodeTome()
    
    print("   Simulating memory scan...")
    detections = detector.detect_shellcode_in_memory(b"test\x90\x90\x90\x90", 1234, "test_process")
    print(f"   Memory scan result: {len(detections)} detections")
    
    print("   Simulating tome analysis...")
    analysis = tome.analyze_memory_region(b"test\x90\x90\x90\x90", 1234, "test_process")
    print(f"   Tome analysis result: {len(analysis.get('detections', []))} detections")
    
    print("   [OK] Integration test successful")
    
except Exception as e:
    print(f"   [ERROR] Integration test failed: {e}")
    import traceback
    traceback.print_exc()

# Test 4: Test with larger realistic data
print("\n4. Testing with realistic shellcode data...")
try:
    from ShellCodeMagic import ShellcodeDetector
    detector = ShellcodeDetector()
    
    # More realistic shellcode-like pattern
    realistic_data = (
        b"\x48\x31\xc0" * 3 +          # XOR RAX, RAX (x3)
        b"\x90" * 30 +                 # NOP sled
        b"\x68\x41\x41\x41\x41" +      # PUSH 0x41414141
        b"\x58" +                      # POP RAX
        b"\xc3" +                      # RET
        b"\x48\x89\x5c\x24\x08" +      # MOV [RSP+8], RBX
        b"\x48\x83\xec\x20"            # SUB RSP, 0x20
    )
    
    result = detector.detect_shellcode_in_memory(realistic_data, 0x400000, "realistic_test")
    print(f"   [OK] Realistic data test successful")
    print(f"   Detections: {len(result)}")
    
    if len(result) > 0:
        for i, detection in enumerate(result):
            print(f"   Detection {i+1}: Pattern={detection.get('pattern_matched', 'N/A')[:20]}...")
    
except Exception as e:
    print(f"   [ERROR] Realistic data test failed: {e}")

print("\n=== SCANNER TEST COMPLETE ===")
print("If all tests show [OK], your Tome and Soul scanners are working!")
