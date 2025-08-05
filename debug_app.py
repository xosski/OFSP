#!/usr/bin/env python3

print("Debugging Orbital Station issues...")

# Test 1: Memory Scanner in Tome
print("\n1. Testing Memory Scanner in Tome...")
try:
    from ShellCodeMagic import ShellCodeTome
    tome = ShellCodeTome()
    
    # Test basic memory analysis
    result = tome.analyze_memory_region(b"test\x90\x90\x90", 1000, "test_proc")
    print(f"   [OK] analyze_memory_region works, type: {type(result)}")
    
    if isinstance(result, dict) and 'detections' in result:
        print(f"   [OK] Returns correct format with {len(result['detections'])} detections")
    else:
        print(f"   [ERROR] Wrong format: {result}")
        
except Exception as e:
    print(f"   [ERROR] Error in tome memory scanner: {e}")

# Test 2: Random name error in deep scan
print("\n2. Testing process iteration for name errors...")
try:
    import psutil
    problem_processes = []
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if not proc.info or not proc.info.get('name'):
                problem_processes.append(f"PID {proc.info.get('pid', 'unknown')}: name={proc.info.get('name')}")
            
            if len(problem_processes) > 5:  # Limit output
                break
                
        except Exception as e:
            problem_processes.append(f"Error getting process info: {e}")
            if len(problem_processes) > 5:
                break
    
    if problem_processes:
        print(f"   [ERROR] Found processes with missing name data:")
        for proc in problem_processes:
            print(f"      {proc}")
    else:
        print("   [OK] All processes have proper name data")
        
except Exception as e:
    print(f"   [ERROR] Error in process iteration: {e}")

# Test 3: YARA compilation
print("\n3. Testing YARA compilation...")
try:
    import yara
    test_rule = '''
    rule test_rule {
        strings:
            $test = "test"
        condition:
            $test
    }
    '''
    compiled = yara.compile(source=test_rule)
    print("   [OK] YARA compilation works")
    
except Exception as e:
    print(f"   [ERROR] YARA compilation error: {e}")

print("\nDebug complete!")
