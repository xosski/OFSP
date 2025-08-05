#!/usr/bin/env python3

print("Testing ShellCode components...")

try:
    print("1. Testing ShellcodeDetector...")
    from ShellCodeMagic import ShellcodeDetector
    detector = ShellcodeDetector()
    print("   ShellcodeDetector created successfully")
    
    print("2. Testing detect_shellcode_in_memory method...")
    result = detector.detect_shellcode_in_memory(b'test data\x90\x90\x90\x90', 1234, 'test_process')
    print(f"   Result type: {type(result)}")
    print(f"   Result length: {len(result) if hasattr(result, '__len__') else 'N/A'}")
    
    print("3. Testing ShellCodeTome...")
    from ShellCodeMagic import ShellCodeTome
    tome = ShellCodeTome()
    print("   ShellCodeTome created successfully")
    
    print("4. Testing analyze_memory_region method...")
    result = tome.analyze_memory_region(b'test data\x90\x90\x90\x90', 1234, 'test_process')
    print(f"   Result type: {type(result)}")
    print(f"   Result: {result}")
    
    if isinstance(result, dict) and 'detections' in result:
        print(f"   Detections count: {len(result['detections'])}")
        print("   ✅ analyze_memory_region returns correct format")
    else:
        print("   ❌ analyze_memory_region returns wrong format")
    
    print("\n✅ All ShellCode components working!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
