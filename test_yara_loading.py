#!/usr/bin/env python3
"""
Test script to verify YARA rules are loading correctly
"""

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_yara_rules():
    """Test YARA rule loading and compilation"""
    
    print("Testing YARA Rule Loading...")
    
    try:
        from YaraRuleManager import YaraRuleManager
        
        # Initialize YARA manager
        print("Initializing YaraRuleManager...")
        yara_manager = YaraRuleManager()
        
        # Test basic initialization
        print(f"Rules directory: {yara_manager.rules_dir}")
        
        # Fetch all rules including OTX
        print("Fetching all rules (including OTX)...")
        success = yara_manager.fetch_all_rules()
        print(f"Rule fetching success: {success}")
        
        # Verify rules are loaded
        print("Verifying rules loaded...")
        report = yara_manager.verify_rules_loaded()
        
        print("\nRule Loading Report:")
        print(f"  Directories exist: {report['directories_exist']}")
        print(f"  Rule files exist: {report['rule_files_exist']}")
        print(f"  Rule files count: {report['rule_files_count']}")
        print(f"  Compilation success: {report['compilation_success']}")
        
        if report['error_message']:
            print(f"  Error: {report['error_message']}")
        
        # Test rule compilation
        print("\nTesting rule compilation...")
        try:
            compiled_rules = yara_manager.compile_combined_rules()
            if compiled_rules:
                print("Rules compiled successfully!")
                
                # Test a simple scan
                test_data = b"This is test data with some NOPs: \x90\x90\x90\x90\x90"
                matches = compiled_rules.match(data=test_data)
                print(f"Test scan found {len(matches)} matches")
                
                for match in matches:
                    print(f"   - Rule: {match.rule}")
                    
            else:
                print("Rule compilation failed")
                
        except Exception as e:
            print(f"Rule compilation error: {str(e)}")
        
        # Check OTX specific status
        print("\nOTX Integration Status:")
        print(f"  OTX fetched: {getattr(yara_manager, '_otx_fetched', False)}")
        print(f"  OTX rules processed: {getattr(yara_manager, '_otx_rules_processed', False)}")
        
        # Check OTX directory
        try:
            from pathlib import Path
            if isinstance(yara_manager.rules_dir, str):
                rules_dir = Path(yara_manager.rules_dir)
            else:
                rules_dir = yara_manager.rules_dir
                
            otx_dir = rules_dir / "otx"
            yara_rules_dir = otx_dir / "yara-rules"
            
            print(f"  OTX directory exists: {otx_dir.exists()}")
            print(f"  OTX YARA repo exists: {yara_rules_dir.exists()}")
            
            if yara_rules_dir.exists():
                otx_rule_count = len(list(yara_rules_dir.glob('**/*.yar*')))
                print(f"  OTX rules found: {otx_rule_count}")
            
        except Exception as e:
            print(f"  OTX check error: {str(e)}")
        
        return success and report['compilation_success']
        
    except Exception as e:
        print(f"Test failed with error: {str(e)}")
        return False

def test_rule_categories():
    """Test individual rule categories"""
    
    print("\nTesting Rule Categories...")
    
    try:
        from YaraRuleManager import YaraRuleManager
        yara_manager = YaraRuleManager()
        
        categories = ['memory_rules', 'shellcode_rules', 'injection_rules', 'malware_rules', 'custom_rules']
        
        for category in categories:
            try:
                from pathlib import Path
                if isinstance(yara_manager.rules_dir, str):
                    rules_dir = Path(yara_manager.rules_dir)
                else:
                    rules_dir = yara_manager.rules_dir
                    
                category_dir = rules_dir / category
                rule_files = list(category_dir.glob('*.yar*'))
                
                print(f"  {category}: {len(rule_files)} files")
                
                # Try to compile one rule from this category
                if rule_files:
                    test_file = rule_files[0]
                    try:
                        import yara
                        yara.compile(str(test_file))
                        print(f"    Sample rule compiles: {test_file.name}")
                    except Exception as e:
                        print(f"    Sample rule error: {str(e)}")
                        
            except Exception as e:
                print(f"  Category {category} error: {str(e)}")
                
    except Exception as e:
        print(f"Category test failed: {str(e)}")

if __name__ == "__main__":
    print("Starting YARA Rule Loading Tests...\n")
    
    # Test main functionality
    success = test_yara_rules()
    
    # Test categories
    test_rule_categories()
    
    print(f"\nOverall test result: {'PASSED' if success else 'FAILED'}")
