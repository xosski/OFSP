#!/usr/bin/env python3
"""
Test script to verify tome is properly storing and retrieving shellcode data
"""

import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ShellCodeMagic import ShellCodeTome

def test_tome_shellcode_storage():
    """Test if the tome properly stores and retrieves shellcode data"""
    
    # Create tome instance
    tome = ShellCodeTome()
    
    # Test shellcode data
    test_shellcode = b'\x90\x90\x90\x90\x48\x31\xc0\x48\x31\xdb'  # Sample shellcode
    
    # Create test entry with shellcode
    test_entry = {
        'type': 'Test Shellcode',
        'process': 'test_process.exe',
        'address': 0x12345678,
        'confidence': 'high',
        'shellcode': test_shellcode,
        'details': 'Test detection for tome storage'
    }
    
    print("🧪 Testing tome shellcode storage...")
    
    # Add entry to tome
    success = tome.add_entry('shellcode_patterns', test_entry)
    print(f"✅ Entry added: {success}")
    
    # Browse spells to get the ID
    spells = tome.browse_ancient_spells(category='shellcode_patterns', limit=5)
    if spells:
        latest_spell = spells[0]  # Most recent
        spell_id = latest_spell['id']
        print(f"📖 Found spell ID: {spell_id}")
        
        # Get full spell details
        spell_details = tome.get_spell_details(spell_id)
        if spell_details:
            print(f"📜 Spell details loaded: {bool(spell_details)}")
            
            # Check if pattern_data contains shellcode
            pattern_data = spell_details.get('pattern_data', {})
            if pattern_data:
                print(f"🔍 Pattern data keys: {list(pattern_data.keys())}")
                
                # Check for shellcode data
                shellcode_found = pattern_data.get('shellcode', b'')
                if shellcode_found:
                    print(f"✅ Shellcode found in pattern_data: {len(shellcode_found)} bytes")
                    print(f"   First 10 bytes: {shellcode_found[:10].hex()}")
                    print(f"   Expected: {test_shellcode[:10].hex()}")
                    
                    if shellcode_found == test_shellcode:
                        print("🎉 SUCCESS: Shellcode data matches original!")
                        return True
                    else:
                        print("❌ ERROR: Shellcode data doesn't match original")
                        return False
                else:
                    print("❌ ERROR: No shellcode found in pattern_data")
                    # Try alternative keys
                    for key in ['data', 'raw_data', 'memory_content']:
                        if pattern_data.get(key):
                            print(f"   Found data in key '{key}': {len(pattern_data[key])} bytes")
                    return False
            else:
                print("❌ ERROR: No pattern_data found")
                return False
        else:
            print("❌ ERROR: Failed to load spell details")
            return False
    else:
        print("❌ ERROR: No spells found")
        return False

if __name__ == "__main__":
    success = test_tome_shellcode_storage()
    print(f"\n🏁 Test result: {'PASSED' if success else 'FAILED'}")
