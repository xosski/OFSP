#!/usr/bin/env python3

print("Testing ShellCodeTome memory scanning...")

try:
    from ShellCodeMagic import ShellCodeTome, ShellcodeDetector
    
    print("1. Creating ShellCodeTome...")
    tome = ShellCodeTome()
    print("   ✅ ShellCodeTome created")
    
    print("2. Creating ShellcodeDetector...")
    detector = ShellcodeDetector()
    print("   ✅ ShellcodeDetector created")
    
    print("3. Testing scan_for_shellcode method...")
    result = detector.scan_for_shellcode(b"test data\x90\x90\x90\x90", 0x1000, {"name": "test"})
    print(f"   scan_for_shellcode result type: {type(result)}")
    print(f"   scan_for_shellcode result keys: {result.keys() if isinstance(result, dict) else 'Not a dict'}")
    
    if isinstance(result, dict):
        print(f"   Has 'is_shellcode' key: {'is_shellcode' in result}")
        print(f"   Has 'shellcode_score' key: {'shellcode_score' in result}")
        print(f"   Has 'patterns_found' key: {'patterns_found' in result}")
    
    print("4. Testing tome analyze_memory_region...")
    tome_result = tome.analyze_memory_region(b"test data\x90\x90\x90\x90", 1234, "test_process")
    print(f"   analyze_memory_region result type: {type(tome_result)}")
    print(f"   analyze_memory_region result: {tome_result}")
    
    print("✅ All tests passed!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
