from pathlib import Path
import os
import hashlib
import binascii
import logging
import ctypes
import json
import uuid
import datetime
import requests
import re
import math
import time
import dis
import queue
import threading
import types
import inspect
import sqlite3
import sys
import traceback
import tkinter as tk
from datetime import datetime
from collections import Counter
from math import log2
import YaraRuleManager
import ScannerGui
from ScannerGui import ScannerGui
# Import from our modules
try:
    # from Memory import MemoryScanner  # Circular import - will import when needed
    pass  # Placeholder since we're not importing anything here
except ImportError:
    # Create a dummy class if Memory module isn't available
    class MemoryScanner:
        def __init__(self):
            pass

class ShellcodeCapture:
    def __init__(self):
        self.shellcode_tome = {}  # Our magical tome to store shellcode
        try:
            self.scanner = MemoryScanner()
        except:
            self.scanner = None
    def capture_shellcode(self, memory_region, start_addr=0, size=None, source_info=None):
        """
        Captures shellcode from a memory region and stores it in the shellcode tome
        
        Args:
            memory_region: The memory buffer/region containing potential shellcode
            start_addr: Starting address of the memory region (for reference)
            size: Size to capture (None means capture all)
            source_info: Additional context about where this shellcode was found
            
        Returns:
            shellcode_id: Identifier for the captured shellcode in the tome
        """
        # Extract the relevant portion of memory
        if size is None:
            extracted_data = memory_region
        else:
            extracted_data = memory_region[:size]
            
        # Generate a unique ID for this shellcode (using hash)
        shellcode_hash = hashlib.sha256(extracted_data).hexdigest()[:16]
        
        # Only store if we haven't seen this exact shellcode before
        if shellcode_hash not in self.shellcode_tome:
            self.shellcode_tome[shellcode_hash] = {
                'data': extracted_data,
                'size': len(extracted_data),
                'hex': binascii.hexlify(extracted_data).decode('utf-8'),
                'first_seen': datetime.now(),
                'seen_count': 1,
                'sources': [source_info] if source_info else [],
                'memory_addresses': [start_addr] if start_addr is not None else []
            }
        else:
            # Update existing entry
            self.shellcode_tome[shellcode_hash]['seen_count'] += 1
            if source_info and source_info not in self.shellcode_tome[shellcode_hash]['sources']:
                self.shellcode_tome[shellcode_hash]['sources'].append(source_info)
            if start_addr is not None and start_addr not in self.shellcode_tome[shellcode_hash]['memory_addresses']:
                self.shellcode_tome[shellcode_hash]['memory_addresses'].append(start_addr)
        
        return shellcode_hash
    def list_all_shellcodes(self, memory_regions_dict):
        self.MagicAnalyzer = MagicAnalyzer()
        
        """Scans multiple memory regions and lists all detected shellcode using the existing analyzers and detection patterns. Args:memory_regions_dict: Dictionary mapping region names to (memory_data, base_address) tuples Returns:
            Dictionary of region names to lists of detected shellcode"""
        results = {}
        
        for region_name, (memory_data, base_address) in memory_regions_dict.items():
            # Initialize results for this region
            results[region_name] = []
            
            # Skip empty regions
            if not memory_data:
                continue
                
            # Check memory with the magic analyzer
            magic_analysis = self.MagicAnalyzer.analyze_memory(memory_data)
            if magic_analysis and "shellcode" in magic_analysis.lower():
                shellcode_entry = self.Detector._create_shellcode_entry(
                    memory_data, 
                    base_address, 
                    region_name, 
                    "magic_detection"
                )
                results[region_name].append(shellcode_entry)
                
            # Check for shellcode patterns with regex
            for pattern_name, pattern in self.shellcode_patterns.items():
                matches = self.Detector._find_pattern_matches(memory_data, pattern)
                for match_start, match_end in matches:
                    # Extract the shellcode with some context
                    extract_start = max(0, match_start - 16)
                    extract_end = min(len(memory_data), match_end + 64)
                    shellcode_fragment = memory_data[extract_start:extract_end]
                    
                    shellcode_entry = self.Detector._create_shellcode_entry(
                        shellcode_fragment,
                        base_address + extract_start,
                        region_name,
                        f"pattern_match:{pattern_name}"
                    )
                    results[region_name].append(shellcode_entry)
                    
            # Apply heuristic detection
            if len(memory_data) >= 10:
                # Check for NOP sleds
                nop_sled_results = self.Detector._detect_nop_sleds(memory_data, base_address)
                results[region_name].extend(nop_sled_results)
                
                # Check for API usage patterns common in shellcode
                api_pattern_results = self.Detector._detect_api_patterns(memory_data, base_address)
                results[region_name].extend(api_pattern_results)
                
                # Look for characteristic shellcode encoders/decoders
                decoder_results = self.Detector._detect_shellcode_decoders(memory_data, base_address)
                results[region_name].extend(decoder_results)
                
            # Check for executable memory indicators
            if self.Detector._is_likely_executable(memory_data):
                executable_regions = self.Detector._analyze_executable_content(
                    memory_data, 
                    base_address,
                    region_name
                )
                results[region_name].extend(executable_regions)
                
            # Apply your custom detection engine
            custom_detections = self.Detector.scan_for_shellcode(
                memory_data,
                base_address,
                region_name
            )
            results[region_name].extend(custom_detections)
            
            # Store all detected shellcode in the tome
            for shellcode_entry in results[region_name]:
                self.Detector._add_to_tome(shellcode_entry['id'], shellcode_entry)
                
        return results
    def export_tome(self, filename):
        """Export the shellcode tome to a file"""
        import json
        with open(filename, 'w') as f:
            # Convert binary data to hex strings for JSON serialization
            export_data = {}
            for sc_id, sc_data in self.shellcode_tome.items():
                export_data[sc_id] = sc_data.copy()
                if isinstance(export_data[sc_id]['data'], bytes):
                    export_data[sc_id]['data'] = binascii.hexlify(export_data[sc_id]['data']).decode('utf-8')
                export_data[sc_id]['first_seen'] = export_data[sc_id]['first_seen'].isoformat()
            
            json.dump(export_data, f, indent=2) 
class ThreatQuarantine:
    def __init__(self, quarantine_dir=None):
        self.quarantine_dir = quarantine_dir or os.path.join(os.path.expanduser("~"), "scanner_quarantine")
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
        self.logger = logging.getLogger(__name__)
        
    def quarantine_process(self, pid, process_info, threat_details):
        """Quarantine a malicious process by suspending it and logging details"""
        try:
            # Safety check - return early if quarantine is disabled
            if not getattr(self, 'quarantine_enabled', False):
                return False
                
            # Safety check - return early if quarantine directory isn't available
            if not getattr(self, 'quarantine_dir', None):
                logging.error("Quarantine directory not available")
                return False
                
            # Get process handle with PROCESS_SUSPEND_RESUME rights
            process_handle = ctypes.windll.kernel32.OpenProcess(
                0x0800,  # PROCESS_SUSPEND_RESUME
                False,
                pid
            )
            
            if not process_handle:
                logging.error(f"Failed to open process {pid} for quarantine")
                return False
                
            # Suspend the process
            suspension_successful = self._suspend_process(process_handle)
            
            # Close the handle regardless of suspension success
            ctypes.windll.kernel32.CloseHandle(process_handle)
            
            if not suspension_successful:
                logging.error(f"Process suspension failed for PID {pid}")
                
            # Generate unique ID and prepare info even if suspension failed
            quarantine_id = str(uuid.uuid4())
            quarantine_info = {
                "quarantine_id": quarantine_id,
                "timestamp": datetime.datetime.now().isoformat(),
                "pid": pid,
                "process_name": process_info.get("Name", "Unknown"),
                "path": process_info.get("Path", "Unknown"),
                "threat_details": threat_details,
                "action": "process_suspended" if suspension_successful else "suspension_failed"
            }
            
            # Save quarantine info
            try:
                with open(os.path.join(self.quarantine_dir, f"{quarantine_id}.json"), "w") as f:
                    json.dump(quarantine_info, f, indent=2)
                    
                logging.warning(f"Process {pid} ({process_info.get('Name', 'Unknown')}) quarantined - ID: {quarantine_id}")
                return True
            except Exception as e:
                logging.error(f"Failed to save quarantine info: {str(e)}")
                return suspension_successful
            
        except Exception as e:
            logging.error(f"Error quarantining process {pid}: {str(e)}")
            return False
            
    def _suspend_process(self, process_handle):
        """Suspend a process using NtSuspendProcess from ntdll.dll"""
        try:
            ntdll = ctypes.windll.ntdll
            NtSuspendProcess = ntdll.NtSuspendProcess
            NtSuspendProcess(process_handle)
        except Exception as e:
            self.logger.error(f"Failed to suspend process: {str(e)}")
            raise
class OTXSubmitter:
    def __init__(self, api_key):
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {
            'X-OTX-API-KEY': 'Insert API Key',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def submit_file(self, file_path, file_name=None):
        """Submit file to OTX for analysis"""
        url = f"{self.base_url}/indicators/submit_file"
        
        with open(file_path, 'rb') as f:
            files = {'file': (file_name or os.path.basename(file_path), f)}
            response = requests.post(url, headers=self.headers, files=files)
            return response.json() if response.status_code == 200 else None

    def submit_url(self, url):
        """Submit single URL to OTX"""
        submit_url = f"{self.base_url}/indicators/submit_url"
        data = {'url': url}
        response = requests.post(submit_url, headers=self.headers, json=data)
        return response.json() if response.status_code == 200 else None

    def submit_urls(self, urls):
        """Submit multiple URLs to OTX"""
        submit_url = f"{self.base_url}/indicators/submit_urls"
        data = {'urls': urls}
        response = requests.post(submit_url, headers=self.headers, json=data)
        return response.json() if response.status_code == 200 else None

    def create_pulse(self, name, description, indicators, public=True, tlp='white'):
        """Create a new OTX pulse with indicators"""
        url = f"{self.base_url}/pulses/create"
        
        pulse_data = {
            'name': name,
            'description': description,
            'public': public,
            'TLP': tlp,
            'indicators': indicators
        }
        
        response = requests.post(url, headers=self.headers, json=pulse_data)
        return response.json() if response.status_code == 200 else None

    def submit_all_detections(self, detections):
        """Process and submit all types of detections to OTX"""
        results = {
            'files': [],
            'urls': [],
            'pulse': None
        }
        
        # Collect URLs and files
        urls = []
        files = []
        
        for detection in detections:
            if detection.get('type') == 'url':
                urls.append(detection['value'])
            elif detection.get('type') == 'file':
                files.append(detection['path'])
        
        # Submit URLs in batch
        if urls:
            results['urls'] = self.submit_urls(urls)
        
        # Submit files individually
        for file_path in files:
            result = self.submit_file(file_path)
            if result:
                results['files'].append(result)
        
        # Create a pulse with all indicators
        if urls or files:
            indicators = []
            indicators.extend([{'type': 'URL', 'indicator': url} for url in urls])
            indicators.extend([{'type': 'file', 'indicator': file} for file in files])
            
            pulse_result = self.create_pulse(
                name=f"Automated Detection Submission {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                description="Automated submission of detected threats",
                indicators=indicators
            )
            results['pulse'] = pulse_result
            
        return results
class MagicAnalyzer:
    def __init__(self):
        self.signatures = self._load_signatures()
        # Try to use python-magic if available
        try:
            import magic
            self.magic_lib = magic.Magic()
            self.has_magic_lib = True
        except ImportError:
            self.has_magic_lib = False
            logging.debug("python-magic library not available, using built-in signatures only")
    def _load_signatures(self):
        """Load built-in signatures for memory content identification"""
        return [
            # Shellcode signatures
            {
                'name': 'x86 shellcode',
                'patterns': [
                    rb'\x31\xc0[\x00-\xff]{0,10}\x50[\x00-\xff]{0,10}\x68',  # xor eax,eax + push eax + push DWORD
                    rb'\x33\xc0[\x00-\xff]{0,10}\x50',                       # xor eax,eax + push eax
                    rb'\xeb[\x00-\xff]\xe8[\x00-\xff]{4}',                   # jmp short + call
                    rb'\xe8[\x00-\xff]{4}\x59',                              # call + pop ecx
                    rb'\x68.{4}\xc3',                                        # push + ret
                    rb'\x90{10,}',                                           # NOP sled
                ],
                'description': 'x86 shellcode patterns'
            },
            {
                'name': 'x64 shellcode',
                'patterns': [
                    rb'\x48\x31\xc0[\x00-\xff]{0,15}\x50',                  # x64 xor rax,rax + push
                    rb'\x48\x83\xec',                                       # sub rsp, X
                    rb'\x48\x8d',                                           # lea r64
                ],
                'description': 'x64 shellcode patterns'
            },
            # PE file signatures
            {
                'name': 'PE executable',
                'patterns': [
                    rb'MZ.{30,200}PE\x00\x00',                              # MZ/PE header
                ],
                'description': 'Windows PE executable'
            },
            # .NET assembly
            {
                'name': '.NET assembly',
                'patterns': [
                    rb'BSJB',                                               # .NET metadata signature
                    rb'\x42\x53\x4A\x42',                                   # BSJB in hex
                ],
                'description': '.NET managed code assembly'
            },
            # Script signatures
            {
                'name': 'script',
                'patterns': [
                    rb'<script',                                            # JavaScript in HTML
                    rb'function\s*\(',                                      # JavaScript function
                    rb'import\s+[a-zA-Z_]',                                 # Python import
                    rb'#!/usr/bin/(env\s+)?python',                         # Python shebang
                ],
                'description': 'Script code (JavaScript, Python, etc.)'
            },
            # Encrypted/compressed data signatures
            {
                'name': 'encrypted data',
                'patterns': [],  # No specific pattern, will use entropy analysis
                'description': 'Possibly encrypted or compressed data'
            }
        ]
    
    def analyze_memory(self, memory_data):
        """
        Analyze memory data to determine its content type
        
        Args:
            memory_data: Bytes object containing memory to analyze
            
        Returns:
            String description of the content type, or None if unknown
        """
        if not memory_data or len(memory_data) < 4:
            return None
            
        # First try python-magic if available
        if self.has_magic_lib:
            try:
                magic_result = self.magic_lib.from_buffer(memory_data)
                # If magic identifies as executable, it might be shellcode
                if 'executable' in magic_result.lower() and 'PE' not in magic_result:
                    return "Possible shellcode (executable content)"
                return magic_result
            except Exception:
                pass  # Fall back to our signatures
        
        # Check against our built-in signatures
        for sig in self.signatures:
            for pattern in sig['patterns']:
                if re.search(pattern, memory_data):
                    return f"{sig['name']} ({sig['description']})"
        
        # Check for high entropy (possible encryption or compression)
        entropy = self._calculate_entropy(memory_data)
        if entropy > 7.0:
            return "Possibly encrypted or compressed data (high entropy)"
            
        # Check for executable characteristics
        if self._has_executable_characteristics(memory_data):
            return "Probable shellcode (executable characteristics)"
            
        return None
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
            
        import math
        from collections import Counter
            
        entropy = 0
        data_len = len(data)
        counter = Counter(data)
            
        for count in counter.values():
            p_x = count / data_len
            entropy += -p_x * math.log2(p_x)
                
        return entropy
    
    def _has_executable_characteristics(self, data):
        """
        Check if the data has characteristics of executable code
        This is a heuristic approach to detect code even without specific signatures
        """
        if len(data) < 20:
            return False
            
        # Count instruction prefixes common in x86/x64 code
        instruction_prefixes = [
            b'\x8B', b'\x89', b'\x8D',  # MOV variations
            b'\xFF', b'\xE8', b'\xE9',  # CALL/JMP variations
            b'\x83', b'\x81',           # ADD/SUB/CMP with immediate
            b'\x55', b'\x56', b'\x57',  # PUSH reg
            b'\x5D', b'\x5E', b'\x5F',  # POP reg
            b'\x68',                     # PUSH immediate
            b'\xC3', b'\xC2',           # RET variations
            b'\x74', b'\x75', b'\x7C',  # Jcc (conditional jumps)
            b'\xB8', b'\xB9',           # MOV reg, imm32
            b'\x48'                      # REX prefix (64-bit)
        ]
        
        # Count occurrences of instruction prefixes
        prefix_count = sum(data.count(prefix) for prefix in instruction_prefixes)
        
        # Check if the density of instruction prefixes is reasonable for code
        # Typical code has around 1 prefix per 3-5 bytes
        prefix_density = prefix_count / len(data)
        
        # Calculate entropy - code typically has entropy between 5.5 and 7.0
        entropy = self._calculate_entropy(data)
        
        # Executable code should have both reasonable prefix density and entropy
        return (prefix_density > 0.1) and (5.5 <= entropy <= 7.0)
class ShellcodeDetector:
    def __init__(self):
        self.shellcode_tome = {}  # Dictionary to store discovered shellcode
        try:
            from Memory import MemoryScanner as RealMemoryScanner
            self.scanner = RealMemoryScanner()
        except ImportError:
            self.scanner = MemoryScanner()  # Use dummy scanner
        # Initialize the magic analyzer
        self.magic_analyzer = MagicAnalyzer()
        self.disassembler = CodeDisassembler()
        self.ShellCode_Capture = ShellcodeCapture()
        self.tome = ShellCodeTome()
        # Set detector reference to avoid circular dependency
        self.tome.set_shellcode_detector(self)
        # Common shellcode patterns/signatures
        self.shellcode_patterns = [
            # Common x86/x64 shellcode patterns
            rb'\x31\xc0[\x00-\xff]{0,10}\x50[\x00-\xff]{0,10}\x68',  # xor eax,eax + push eax + push DWORD
            rb'\x48\x31\xc0[\x00-\xff]{0,15}\x50',                   # x64 xor rax,rax + push
            rb'\x31\xd2[\x00-\xff]{0,10}\x31\xc0',                   # xor edx,edx + xor eax,eax
            rb'\x68.{4}\xc3',                                         # push + ret
            rb'\x68.{4}\xc3',                                         # push + ret 
            rb'\xe8.{4}',                                             # call instruction with offset
            rb'\xeb\x0e',                                             # jmp short
            rb'\x90{5,}',                                             # NOP sled
        ]
        
    def _create_shellcode_entry(self, data, address, region_name, detection_method):
        """Create a standardized shellcode entry"""
        import hashlib
        import binascii
        from datetime import datetime
        
        shellcode_hash = hashlib.sha256(data).hexdigest()[:16]
        
        return {
            'id': shellcode_hash,
            'data': data,
            'address': address,
            'size': len(data),
            'region_name': region_name,
            'detection_method': detection_method,
            'hex': binascii.hexlify(data[:64]).decode('utf-8'),
            'detection_time': datetime.now(),
            'disassembly': self._try_disassemble(data, address) if self.disassembler else None
        }

    def _find_pattern_matches(self, data, pattern):
        """Find all instances of pattern in data"""
        import re
        return [(m.start(), m.end()) for m in re.finditer(pattern, data)]

    def detect_shellcode_in_memory(self, memory_region, pid=0, process_name="Unknown", base_address=0):
        """
        Detect potential shellcode in a memory region
        
        Args:
            memory_region: Bytes object containing memory data
            pid: Process ID 
            process_name: Name of the process
            base_address: The starting address of this memory region
            
        Returns:
            List of dictionaries containing detected shellcode entries
        """
        detected_shellcodes = []
        
        # Skip if memory region is empty or None
        if not memory_region:
            return detected_shellcodes
            
        # Search for known shellcode patterns
        for pattern in self.shellcode_patterns:
            for match in re.finditer(pattern, memory_region):
                # Extract shellcode with context (expand to include surrounding bytes)
                start_pos = max(0, match.start() - 16)
                end_pos = min(len(memory_region), match.end() + 64)
                
                shellcode_fragment = memory_region[start_pos:end_pos]
                fragment_addr = base_address + start_pos
                
                # Create a unique ID
                shellcode_hash = hashlib.sha256(shellcode_fragment).hexdigest()[:16]
                
                # Create shellcode entry
                shellcode_entry = {
                    'id': shellcode_hash,
                    'data': shellcode_fragment,
                    'address': fragment_addr,
                    'size': len(shellcode_fragment),
                    'pattern_matched': binascii.hexlify(match.group(0)).decode('utf-8'),
                    'region_name': process_name,
                    'detection_time': datetime.now()
                }
                
                # Add to results
                detected_shellcodes.append(shellcode_entry)
                
                # Optionally store in the tome
                self._add_to_tome(shellcode_hash, shellcode_entry)
                
        return detected_shellcodes

    def _detect_nop_sleds(self, data, base_address):
        """Detect NOP sleds in memory"""
        results = []
        # Classic x86 NOP sled
        nop_matches = self._find_pattern_matches(data, b'\x90{10,}')
        
        for start, end in nop_matches:
            shellcode_entry = self._create_shellcode_entry(
                data[start:end], 
                base_address + start,
                "memory_scan", 
                "nop_sled_detection"
            )
            results.append(shellcode_entry)
            
        # Multi-byte NOP instructions used for sleds
        multi_nop_patterns = [
            b'\x66\x90{5,}',  # 2-byte NOP
            b'(\x0f\x1f\x00){3,}',  # 3-byte NOP
            b'(\x0f\x1f\x40\x00){3,}'  # 4-byte NOP
        ]
        
        for pattern in multi_nop_patterns:
            matches = self._find_pattern_matches(data, pattern)
            for start, end in matches:
                entry = self._create_shellcode_entry(
                    data[start:end],
                    base_address + start,
                    "memory_scan",
                    "multi_byte_nop_detection"
                )
                results.append(entry)
                
        return results

    def _detect_api_patterns(self, data, base_address):
        """Detect API usage patterns common in shellcode"""
        results = []
        # Common shellcode API resolution patterns
        api_patterns = [
            (b'\x68.{4}\xB8.{4}\xFF\xD0', "call_via_eax"),
            (b'\xE8.{4}\x59', "call_pop_pattern"),
            (b'\x31\xc0[\x00-\xff]{0,10}\x50[\x00-\xff]{0,10}\x68', "xor_push_pattern"),
            # ... other API patterns from your existing code
        ]
        
        for pattern, name in api_patterns:
            matches = self._find_pattern_matches(data, pattern)
            for start, end in matches:
                context_start = max(0, start - 32)
                context_end = min(len(data), end + 64)
                
                entry = self._create_shellcode_entry(
                    data[context_start:context_end],
                    base_address + context_start,
                    "memory_scan",
                    f"api_pattern:{name}"
                )
                results.append(entry)
                
        return results

    def _detect_shellcode_decoders(self, data, base_address):
        """Detect shellcode decoder stubs"""
        results = []
        # Common decoder patterns
        decoder_patterns = [
            (b'\xEB\x0E.{14}\xE8.{4}', "jmp_call_pop_decoder"),
            (b'\x31\xC9[\x00-\xff]{0,6}\xB1.{1}[\x00-\xff]{0,6}\x80.{2}', "xor_decoder"),
            # ... other decoder patterns from your existing code
        ]
        
        for pattern, name in decoder_patterns:
            matches = self._find_pattern_matches(data, pattern)
            for start, end in matches:
                context_start = max(0, start - 16)
                context_end = min(len(data), end + 128)  # Include more bytes to capture decoded shellcode
                
                entry = self._create_shellcode_entry(
                    data[context_start:context_end],
                    base_address + context_start,
                    "memory_scan",
                    f"decoder:{name}"
                )
                results.append(entry)
                
        return results

    def _is_likely_executable(self, data):
        """Check if memory region is likely executable code"""
        # Simple heuristic: check for common instruction prefixes
        # and reasonable entropy
        if len(data) < 20:
            return False
            
        # Count instruction prefixes
        instruction_prefixes = [b'\x8B', b'\x89', b'\x8D', b'\xFF', b'\xE8', b'\xE9', b'\xEB']
        prefix_count = sum(data.count(prefix) for prefix in instruction_prefixes)
        
        # Calculate simple entropy
        import math
        from collections import Counter
        
        entropy = 0
        counter = Counter(data)
        for count in counter.values():
            p = count / len(data)
            entropy += -p * math.log2(p)
        
        # Executable code typically has entropy between 5.5 and 7.2
        return (prefix_count > len(data) / 30) and (5.5 <= entropy <= 7.2)

    def _analyze_executable_content(self, data, base_address, region_name):
        """Analyze regions that appear to be executable"""
        results = []
        
        # Look for function prologues
        prologue_patterns = [
            (b'\x55\x8B\xEC', "x86_function_prologue"),
            (b'\x55\x48\x89\xE5', "x64_function_prologue")
        ]
        
        for pattern, name in prologue_patterns:
            matches = self._find_pattern_matches(data, pattern)
            for start, end in matches:
                # Extract a reasonable function size (up to 512 bytes)
                end = min(len(data), start + 512)
                
                entry = self._create_shellcode_entry(
                    data[start:end],
                    base_address + start,
                    region_name,
                    f"executable:{name}"
                )
                results.append(entry)
        
        # If we have a disassembler, do more in-depth analysis
        if hasattr(self, 'disassembler') and self.disassembler:
            # Attempt to find code entry points
            entry_points = self.disassembler.find_entry_points(data, base_address)
            for addr, size in entry_points:
                offset = addr - base_address
                if 0 <= offset < len(data):
                    entry = self._create_shellcode_entry(
                        data[offset:offset+size],
                        addr,
                        region_name,
                        "disasm_entry_point"
                    )
                    results.append(entry)
                    
        return results

    def _try_disassemble(self, data, address):
        """Try to disassemble the given data"""
        if not hasattr(self, 'disassembler') or not self.disassembler:
            return "Disassembler not available"
            
        try:
            return self.disassembler.disassemble(data, address)
        except Exception as e:
            return f"Disassembly failed: {str(e)}"
    
    def _add_to_tome(self, shellcode_id, shellcode_entry):
        """Internal method to add detected shellcode to the tome"""
        if shellcode_id not in self.shellcode_tome:
            self.shellcode_tome[shellcode_id] = {
                'data': shellcode_entry['data'],
                'size': shellcode_entry['size'],
                'hex': binascii.hexlify(shellcode_entry['data']).decode('utf-8'),
                'first_seen': datetime.now(),
                'seen_count': 1,
                'locations': [{
                    'address': shellcode_entry['address'],
                    'region_name': shellcode_entry['region_name']
                }]
            }
        else:
            # Update existing entry
            self.shellcode_tome[shellcode_id]['seen_count'] += 1
            location = {
                'address': shellcode_entry['address'],
                'region_name': shellcode_entry['region_name']
            }
            if location not in self.shellcode_tome[shellcode_id]['locations']:
                self.shellcode_tome[shellcode_id]['locations'].append(location)   
    def analyze_shellcode_characteristics(self, shellcode_id):
        """
        Perform deeper analysis on a specific shellcode
        
        Args:
            shellcode_id: ID of the shellcode to analyze
            
        Returns:
            Dictionary of analysis results
        """
        shellcode = self.shellcode_tome.get(shellcode_id)
        if not shellcode:
            return {"error": "Shellcode not found"}
            
        results = {
            "id": shellcode_id,
            "size": shellcode['size'],
            "obfuscation_likelihood": self._detect_obfuscation(shellcode['data']),
            "api_calls": self._extract_potential_api_calls(shellcode['data']),
            "execution_characteristics": self._analyze_execution_flow(shellcode['data']),
            "similarity": self._find_similar_shellcodes(shellcode_id)
        }
        
        return results
    def _detect_obfuscation(self, shellcode_data, address=0):
        import re
        from collections import Counter
        from math import log2
        
        results = {
            'techniques': [],
            'confidence': 0,
            'details': {}
        }
        
        if not shellcode_data or len(shellcode_data) < 10:
            return results
            
        # Check entropy (high entropy suggests encryption or packing)
        entropy = 0
        counter = Counter(shellcode_data)
        for count in counter.values():
            p_x = count / len(shellcode_data)
            entropy += -p_x * log2(p_x)
            
        results['details']['entropy'] = entropy
        
        if entropy > 7.2:
            results['techniques'].append('encrypted')
            results['confidence'] += 0.8
        elif entropy > 6.8:
            results['techniques'].append('possibly_packed')
            results['confidence'] += 0.5
            
        # Look for XOR patterns (common in encoders)
        xor_patterns = [
            # XOR reg, reg followed by a loop
            rb'\x33[\xC0-\xFF][\x00-\xFF]{0,10}\xE2',  # xor reg, reg + loop
            rb'\x31[\xC0-\xFF][\x00-\xFF]{0,10}\xE2',  # xor reg, reg + loop
            
            # XOR byte ptr patterns
            rb'\x80\x34[\x00-\xFF]{1,4}[\x00-\xFF]',   # xor byte ptr [...], imm8
            rb'\x81\x34[\x00-\xFF]{1,4}[\x00-\xFF]{4}', # xor dword ptr [...], imm32
            
            # XOR with counter
            rb'\x30[\xC0-\xFF][\x00-\xFF]{0,4}\xFE',   # xor reg8, reg8 + inc/dec
            rb'\x31[\xC0-\xFF][\x00-\xFF]{0,4}\xFF'    # xor reg32, reg32 + inc/dec
        ]
        
        for pattern in xor_patterns:
            matches = re.finditer(pattern, shellcode_data)
            xor_count = sum(1 for _ in matches)
            if xor_count > 0:
                results['techniques'].append('xor_encoding')
                results['details']['xor_patterns'] = xor_count
                results['confidence'] += min(0.3 + (0.1 * xor_count), 0.7)
                break
        
        # Check for ADD/SUB encoding
        add_sub_patterns = [
            rb'\x80\xC0[\x00-\xFF][\x00-\xFF]{0,10}\xE2',  # add al, imm8 + loop
            rb'\x80\xE8[\x00-\xFF][\x00-\xFF]{0,10}\xE2',  # sub al, imm8 + loop
            rb'\x04[\x00-\xFF][\x00-\xFF]{0,10}\xE2',      # add al, imm8 + loop
            rb'\x2C[\x00-\xFF][\x00-\xFF]{0,10}\xE2'       # sub al, imm8 + loop
        ]
        
        for pattern in add_sub_patterns:
            matches = re.finditer(pattern, shellcode_data)
            addsub_count = sum(1 for _ in matches)
            if addsub_count > 0:
                results['techniques'].append('add_sub_encoding')
                results['details']['addsub_patterns'] = addsub_count
                results['confidence'] += min(0.2 + (0.1 * addsub_count), 0.6)
                break
        
        # Check for ROL/ROR encoding
        rotation_patterns = [
            rb'\xC0[\xC0-\xCF][\x00-\xFF][\x00-\xFF]{0,10}\xE2',  # rol/ror reg8, imm8 + loop
            rb'\xC1[\xC0-\xCF][\x00-\xFF][\x00-\xFF]{0,10}\xE2',  # rol/ror reg32, imm8 + loop
            rb'\xD0[\xC0-\xCF][\x00-\xFF]{0,10}\xE2',             # rol/ror reg8, 1 + loop
            rb'\xD1[\xC0-\xCF][\x00-\xFF]{0,10}\xE2'              # rol/ror reg32, 1 + loop
        ]
        
        for pattern in rotation_patterns:
            matches = re.finditer(pattern, shellcode_data)
            rot_count = sum(1 for _ in matches)
            if rot_count > 0:
                results['techniques'].append('rotation_encoding')
                results['details']['rotation_patterns'] = rot_count
                results['confidence'] += min(0.3 + (0.1 * rot_count), 0.7)
                break
        
        # Check for self-modifying code
        self_mod_patterns = [
            rb'\x89[\x00-\xFF]\x24[\x00-\xFF]',     # mov [esp+...], reg
            rb'\xC7[\x00-\xFF]{1,4}[\x00-\xFF]{4}',  # mov dword ptr [...], imm32
            rb'\x88[\x00-\xFF]\x24[\x00-\xFF]'      # mov byte ptr [esp+...], reg
        ]
        
        for pattern in self_mod_patterns:
            matches = re.finditer(pattern, shellcode_data)
            selfmod_count = sum(1 for _ in matches)
            if selfmod_count > 3:  # Need multiple instances to confirm
                results['techniques'].append('self_modifying')
                results['details']['selfmod_patterns'] = selfmod_count
                results['confidence'] += min(0.2 + (0.05 * selfmod_count), 0.7)
        
        # Look for push+ret JMP (common in obfuscation)
        push_ret_pattern = rb'\x68[\x00-\xFF]{4}\xC3'  # push addr + ret
        push_ret_count = len(re.findall(push_ret_pattern, shellcode_data))
        if push_ret_count > 0:
            results['techniques'].append('push_ret_jumps')
            results['details']['push_ret_count'] = push_ret_count
            results['confidence'] += min(0.1 * push_ret_count, 0.5)
        
        # If we have a disassembler, do more advanced checks
        if hasattr(self, 'disassembler') and self.disassembler:
            try:
                disasm = self.disassembler.disassemble(shellcode_data, address)
                
                # Look for instruction reordering/obfuscation (jmps between close addresses)
                if 'jmp short' in disasm and disasm.count('jmp short') > 3:
                    results['techniques'].append('instruction_reordering')
                    results['confidence'] += 0.5
                
                # Look for API hashing
                if self.disassembler._has_api_hashing(shellcode_data):
                    results['techniques'].append('api_hashing')
                    results['confidence'] += 0.7
            except Exception:
                pass
        
        # Normalize confidence between 0-1
        results['confidence'] = min(results['confidence'], 1.0)
        
        return results

    def _extract_potential_api_calls(self, shellcode_data, address=0):
        """
        Extract potential Windows API calls from shellcode
        
        Args:
            shellcode_data: The binary shellcode data
            address: Base address for disassembly reference
            
        Returns:
            List of dictionaries containing potential API call information
        """
        import re
        
        api_calls = []
        
        if not shellcode_data or len(shellcode_data) < 10:
            return api_calls
        
        # Common API call patterns
        direct_call_patterns = [
            # CALL dword ptr [...]
            (rb'\xFF\x15[\x00-\xFF]{4}', 'call_indirect'),
            
            # CALL register
            (rb'\xFF[\xD0-\xD7]', 'call_register'),
            
            # CALL immediate
            (rb'\xE8[\x00-\xFF]{4}', 'call_immediate')
        ]
        
        # Check for direct API calls
        for pattern, call_type in direct_call_patterns:
            for match in re.finditer(pattern, shellcode_data):
                offset = match.start()
                
                # Get the bytes of the call instruction
                call_bytes = shellcode_data[offset:offset+6 if call_type == 'call_indirect' else offset+5]
                
                # For CALL dword ptr [...], extract the pointer address
                target_addr = None
                if call_type == 'call_indirect' and len(call_bytes) >= 6:
                    # Extract the address from call instruction (little endian)
                    ptr_bytes = call_bytes[2:6]
                    target_addr = int.from_bytes(ptr_bytes, byteorder='little')
                
                # For CALL immediate, calculate target
                elif call_type == 'call_immediate' and len(call_bytes) >= 5:
                    rel_offset = int.from_bytes(call_bytes[1:5], byteorder='little')
                    # Target is: current position + instruction size + relative offset
                    target_addr = address + offset + 5 + rel_offset
                
                # Create API call entry
                api_call = {
                    'offset': offset,
                    'address': address + offset,
                    'type': call_type,
                    'bytes': call_bytes.hex(),
                    'target_addr': target_addr
                }
                
                # Look for potential API name pushes before the call
                pre_call_region = max(0, offset - 50)
                pre_call_bytes = shellcode_data[pre_call_region:offset]
                
                # Look for common patterns before API calls
                
                # PUSH immediate strings (often function name/hash)
                push_imm_matches = list(re.finditer(rb'\x68[\x00-\xFF]{4}', pre_call_bytes))
                if push_imm_matches:
                    last_push = push_imm_matches[-1]
                    push_value = pre_call_bytes[last_push.start()+1:last_push.start()+5]
                    api_call['potential_param'] = push_value.hex()
                
                # Check for common API setup patterns (LoadLibraryA, GetProcAddress)
                if b'LoadLibrary' in pre_call_bytes or b'GetProcAddress' in pre_call_bytes:
                    api_call['api_resolution'] = True
                
                api_calls.append(api_call)
        
        # Look for API hashing patterns
        api_hash_patterns = [
            # Common GetProcAddress hash calculation
            (rb'\x33\xC0\xAC\xC1[\x00-\xFF]{2}[\x00-\xFF]{0,10}\x03[\xC0-\xFF]', 'api_hashing'),
            (rb'\x31\xC0\xAC\xC1[\x00-\xFF]{2}[\x00-\xFF]{0,10}\x03[\xC0-\xFF]', 'api_hashing'),
        ]
        
        for pattern, hash_type in api_hash_patterns:
            for match in re.finditer(pattern, shellcode_data):
                offset = match.start()
                hash_bytes = shellcode_data[offset:offset+20]  # Capture enough of the hashing routine
                
                api_calls.append({
                    'offset': offset,
                    'address': address + offset,
                    'type': hash_type,
                    'bytes': hash_bytes.hex(),
                    'target_addr': None,
                    'is_hash_routine': True
                })
        
        # Use disassembler for more accurate analysis if available
        if hasattr(self, 'disassembler') and self.disassembler:
            try:
                # Find more sophisticated API calls through disassembly
                disasm_api_calls = self.disassembler._identify_api_calls(shellcode_data, address)
                
                # Merge with existing findings, avoiding duplicates
                existing_offsets = {call['offset'] for call in api_calls}
                for api_call in disasm_api_calls:
                    if api_call['offset'] not in existing_offsets:
                        api_calls.append(api_call)
                        existing_offsets.add(api_call['offset'])
            except Exception:
                pass
        
        return api_calls
    def _analyze_execution_flow(self, shellcode_data, address=0):
        import re
        
        results = {
            'entry_point': address,
            'branches': [],
            'loops': [],
            'calls': [],
            'complexity': 0,
            'linearized_flow': [],
            'suspicious_patterns': []
        }
        
        if not shellcode_data or len(shellcode_data) < 10:
            return results
        
        # Simple pattern-based analysis for branches and jumps
        jmp_patterns = [
            (rb'\xEB[\x00-\xFF]', 'jmp_short'),           # JMP short (relative)
            (rb'\xE9[\x00-\xFF]{4}', 'jmp_near'),         # JMP near (relative)
            (rb'\xFF[\xE0-\xE7]', 'jmp_register'),        # JMP register
            (rb'\xFF\x25[\x00-\xFF]{4}', 'jmp_indirect')  # JMP dword ptr [...]
        ]
        
        conditional_jmp_patterns = [
            (rb'\x0F[\x80-\x8F][\x00-\xFF]{4}', 'jcc_near'),  # Jcc near (relative)
            (rb'\x70[\x00-\xFF]', 'jo_short'),               # JO short
            (rb'\x71[\x00-\xFF]', 'jno_short'),              # JNO short
            (rb'\x72[\x00-\xFF]', 'jb_short'),               # JB/JNAE/JC short
            (rb'\x73[\x00-\xFF]', 'jnb_short'),              # JNB/JAE/JNC short
            (rb'\x74[\x00-\xFF]', 'je_short'),               # JE/JZ short
            (rb'\x75[\x00-\xFF]', 'jne_short'),              # JNE/JNZ short
            (rb'\x76[\x00-\xFF]', 'jbe_short'),              # JBE/JNA short
            (rb'\x77[\x00-\xFF]', 'jnbe_short'),             # JNBE/JA short
            (rb'\x78[\x00-\xFF]', 'js_short'),               # JS short
            (rb'\x79[\x00-\xFF]', 'jns_short'),              # JNS short
            (rb'\x7A[\x00-\xFF]', 'jp_short'),               # JP/JPE short
            (rb'\x7B[\x00-\xFF]', 'jnp_short'),              # JNP/JPO short
            (rb'\x7C[\x00-\xFF]', 'jl_short'),               # JL/JNGE short
            (rb'\x7D[\x00-\xFF]', 'jnl_short'),              # JNL/JGE short
            (rb'\x7E[\x00-\xFF]', 'jle_short'),              # JLE/JNG short
            (rb'\x7F[\x00-\xFF]', 'jnle_short')              # JNLE/JG short
        ]
        
        call_patterns = [
            (rb'\xE8[\x00-\xFF]{4}', 'call_near'),         # CALL near (relative)
            (rb'\xFF[\xD0-\xD7]', 'call_register'),        # CALL register
            (rb'\xFF\x15[\x00-\xFF]{4}', 'call_indirect')  # CALL dword ptr [...]
        ]
        
        loop_patterns = [
            (rb'\xE0[\x00-\xFF]', 'loopne'),              # LOOPNE/LOOPNZ
            (rb'\xE1[\x00-\xFF]', 'loope'),               # LOOPE/LOOPZ
            (rb'\xE2[\x00-\xFF]', 'loop'),                # LOOP
            (rb'\xE3[\x00-\xFF]', 'jcxz')                 # JECXZ/JCXZ
        ]
        
        # Find all jumps and branches
        for pattern, jump_type in jmp_patterns + conditional_jmp_patterns:
            for match in re.finditer(pattern, shellcode_data):
                offset = match.start()
                instruction_bytes = shellcode_data[offset:offset + len(pattern) - 2 + (4 if 'near' in jump_type or 'indirect' in jump_type else 1)]
                
                # Calculate target address
                target = None
                if jump_type in ('jmp_short', 'jo_short', 'jno_short', 'jb_short', 'jnb_short', 
                                'je_short', 'jne_short', 'jbe_short', 'jnbe_short', 'js_short', 
                                'jns_short', 'jp_short', 'jnp_short', 'jl_short', 'jnl_short', 
                                'jle_short', 'jnle_short'):
                    # Short jump: 1 byte offset (signed)
                    displacement = instruction_bytes[-1]
                    if displacement > 127:  # Convert to signed
                        displacement -= 256
                    target = address + offset + len(instruction_bytes) + displacement
                
                elif jump_type in ('jmp_near', 'jcc_near', 'call_near'):
                    # Near jump: 4 byte offset (signed)
                    displacement = int.from_bytes(instruction_bytes[-4:], byteorder='little', signed=True)
                    target = address + offset + len(instruction_bytes) + displacement
                
                elif jump_type in ('jmp_indirect', 'call_indirect'):
                    # Indirect jump through memory
                    ptr_address = int.from_bytes(instruction_bytes[-4:], byteorder='little')
                    target = ptr_address  # This is the address of the pointer, not the actual target
                
                # Add to appropriate list
                branch_info = {
                    'type': jump_type,
                    'offset': offset,
                    'address': address + offset,
                    'instruction_bytes': instruction_bytes.hex(),
                    'target': target
                }
                
                if 'call' in jump_type:
                    results['calls'].append(branch_info)
                elif any(x in jump_type for x in ('jo', 'jno', 'jb', 'jnb', 'je', 'jne', 'jbe', 'jnbe', 
                                                'js', 'jns', 'jp', 'jnp', 'jl', 'jnl', 'jle', 'jnle', 'jcc')):
                    results['branches'].append(branch_info)
                    results['complexity'] += 1
                else:
                    # Unconditional jumps
                    results['linearized_flow'].append(branch_info)
        
        # Find all loops
        for pattern, loop_type in loop_patterns:
            for match in re.finditer(pattern, shellcode_data):
                offset = match.start()
                instruction_bytes = shellcode_data[offset:offset + 2]
                
                # Calculate target (loops use short jumps: 1 byte signed offset)
                displacement = instruction_bytes[1]
                if displacement > 127:  # Convert to signed
                    displacement -= 256
                target = address + offset + 2 + displacement
                
                loop_info = {
                    'type': loop_type,
                    'offset': offset,
                    'address': address + offset,
                    'instruction_bytes': instruction_bytes.hex(),
                    'target': target
                }
                
                results['loops'].append(loop_info)
                results['complexity'] += 2  # Loops add more complexity
        
        # Look for suspicious patterns
        
        # Self-modifying code indicators
        self_mod_patterns = [
            rb'\x89[\x00-\xFF]\x24[\x00-\xFF]',     # mov [esp+...], reg
            rb'\xC7[\x00-\xFF]{1,4}[\x00-\xFF]{4}',  # mov dword ptr [...], imm32
            rb'\x88[\x00-\xFF]\x24[\x00-\xFF]'      # mov byte ptr [esp+...], reg
        ]
        
        for pattern in self_mod_patterns:
            for match in re.finditer(pattern, shellcode_data):
                offset = match.start()
                
                # Check if this instruction appears to be modifying code in the same region
                target_region = False
                if len(shellcode_data) > offset + 6:
                    # This is a simplistic check - more sophisticated analysis would need disassembly
                    mod_address = address + offset
                    
                    # If there are jumps/branches to an address after this instruction,
                    # it might be modifying executable code
                    for branch in results['branches'] + results['linearized_flow']:
                        if branch['target'] and mod_address <= branch['target'] < mod_address + 100:
                            target_region = True
                            break
                
                if target_region:
                    results['suspicious_patterns'].append({
                        'type': 'self_modifying_code',
                        'offset': offset,
                        'address': address + offset,
                        'instruction_bytes': shellcode_data[offset:offset+6].hex()
                    })
                    results['complexity'] += 3  # Self-modifying code is complex
        for call_pattern, call_type in call_patterns:
            for match in re.finditer(call_pattern, shellcode_data):
                offset = match.start()
                instruction_bytes = shellcode_data[offset:offset + len(call_pattern) - 2 + (4 if 'near' in call_type or 'indirect' in call_type else 1)]
                
                # Calculate target address
                target = None
                if call_type in ('call_near', 'call_indirect'):
                    # Near call: 4 byte offset (signed)
                    displacement = int.from_bytes(instruction_bytes[-4:], byteorder='little', signed=True)
                    target = address + offset + len(instruction_bytes) + displacement
                
                # Add to appropriate list
                branch_info = {
                    'type': call_type,
                    'offset': offset,
                    'address': address + offset,
                    'instruction_bytes': instruction_bytes.hex(),
                    'target': target
                }
                
                results['calls'].append(branch_info)
                results['complexity'] += 0.5  # Calls add some complexity
        # Use disassembler for more accurate analysis if available
        if hasattr(self, 'disassembler') and self.disassembler:
            try:
                # Enhanced flow analysis using disassembler
                disasm_flow = self.disassembler._analyze_flow(shellcode_data, address)
                
                # Merge with pattern-based results
                if disasm_flow:
                    # Keep specialized patterns that might be missed in disassembly
                    for key in ['suspicious_patterns', 'complexity']:
                        if key in disasm_flow:
                            results[key] = disasm_flow[key]
                    
                    # Update control flow information
                    for key in ['branches', 'loops', 'calls', 'linearized_flow']:
                        if key in disasm_flow and disasm_flow[key]:
                            # Add entries without duplicating
                            existing_addresses = {entry['address'] for entry in results[key]}
                            results[key].extend([
                                entry for entry in disasm_flow[key] 
                                if entry['address'] not in existing_addresses
                            ])
            except Exception:
                pass
        
        # Estimate overall complexity based on number and types of control flow structures
        # More branches, loops, and calls indicate higher complexity
        results['complexity'] += len(results['branches']) * 1
        results['complexity'] += len(results['loops']) * 2
        results['complexity'] += len(results['calls']) * 0.5
        
        # Normalize complexity to a 0-10 scale
        results['complexity'] = min(10, results['complexity'])
        
        return results
    def _find_similar_shellcodes(self, shellcode_data, threshold=0.7):
        
        from difflib import SequenceMatcher
        import hashlib
        
        similar_shellcodes = []
        
        if not shellcode_data or len(shellcode_data) < 10 or not self.shellcode_tome:
            return similar_shellcodes
        
        # Calculate various hashes for quick filtering
        shellcode_hash = hashlib.sha256(shellcode_data).hexdigest()
        shellcode_md5 = hashlib.md5(shellcode_data).hexdigest()
        
        # Function to calculate fuzzy hash (ssdeep-like but simpler)
        def simple_fuzzy_hash(data, block_size=64):
            if len(data) < block_size:
                return hashlib.md5(data).hexdigest()[:16]
            
            chunks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
            return hashlib.md5(b''.join([hashlib.md5(chunk).digest() for chunk in chunks])).hexdigest()
        
        fuzzy_hash = simple_fuzzy_hash(shellcode_data)
        
        # Function to calculate N-gram similarity
        def calculate_ngram_similarity(data1, data2, n=3):
            if len(data1) < n or len(data2) < n:
                return 0.0
                
            # Generate n-grams for both sequences
            def get_ngrams(data, n):
                return [data[i:i+n] for i in range(len(data)-n+1)]
            
            ngrams1 = set(get_ngrams(data1, n))
            ngrams2 = set(get_ngrams(data2, n))
            
            # Calculate Jaccard similarity
            if not ngrams1 or not ngrams2:
                return 0.0
                
            intersection = len(ngrams1.intersection(ngrams2))
            union = len(ngrams1.union(ngrams2))
            
            return intersection / union if union > 0 else 0.0
        
        # Function to calculate instruction similarity (if disassembler available)
        def calculate_instruction_similarity(data1, data2):
            if not hasattr(self, 'disassembler') or not self.disassembler:
                return None
                
            try:
                # Extract instructions without specific addresses/offsets
                instrs1 = self._extract_instructions(data1)
                instrs2 = self._extract_instructions(data2)
                
                if not instrs1 or not instrs2:
                    return None
                    
                # Compare instruction sequences
                matcher = SequenceMatcher(None, instrs1, instrs2)
                return matcher.ratio()
            except Exception:
                return None
        
        # Iterate through shellcode tome to find matches
        for sc_id, sc_entry in self.shellcode_tome.items():
            # Skip comparing with self
            if sc_id == shellcode_hash[:16]:
                continue
                
            # Get comparison shellcode
            tome_shellcode = sc_entry.get('data')
            if not tome_shellcode or not isinstance(tome_shellcode, bytes):
                # Try to convert hex string to bytes if necessary
                tome_hex = sc_entry.get('hex')
                if tome_hex:
                    try:
                        import binascii
                        tome_shellcode = binascii.unhexlify(tome_hex)
                    except Exception:
                        continue
                else:
                    continue
            
            # Quick size comparison first
            size_similarity = min(len(shellcode_data), len(tome_shellcode)) / max(len(shellcode_data), len(tome_shellcode))
            if size_similarity < threshold * 0.5:
                continue  # Size too different, skip detailed comparison
            
            # Calculate similarity using multiple metrics
            similarity_scores = {
                'size': size_similarity
            }
            
            # Byte-level sequence similarity
            if abs(len(shellcode_data) - len(tome_shellcode)) < 1024:  # Don't compare very different sizes
                # For large shellcodes, compare only parts to save time
                if len(shellcode_data) > 2048:
                    # Sample beginning, middle, and end
                    parts1 = [shellcode_data[:512], shellcode_data[len(shellcode_data)//2-256:len(shellcode_data)//2+256], shellcode_data[-512:]]
                    parts2 = [tome_shellcode[:512], tome_shellcode[len(tome_shellcode)//2-256:len(tome_shellcode)//2+256], tome_shellcode[-512:]]
                    
                    byte_similarity = 0
                    for i in range(3):
                        byte_similarity += SequenceMatcher(None, parts1[i], parts2[i]).ratio() / 3
                else:
                    # Compare entire sequences
                    byte_similarity = SequenceMatcher(None, shellcode_data, tome_shellcode).ratio()
                    
                similarity_scores['byte'] = byte_similarity
            
            # N-gram similarity (captures structural patterns)
            ngram_similarity = calculate_ngram_similarity(shellcode_data, tome_shellcode)
            similarity_scores['ngram'] = ngram_similarity
            
            # Instruction-level similarity (if disassembler available)
            instr_similarity = calculate_instruction_similarity(shellcode_data, tome_shellcode)
            if instr_similarity is not None:
                similarity_scores['instruction'] = instr_similarity
            
            # Calculate overall similarity score (weighted average)
            weights = {
                'size': 0.1,
                'byte': 0.3,
                'ngram': 0.4,
                'instruction': 0.6  # Higher weight if available
            }
            
            total_weight = sum(weights[key] for key in similarity_scores.keys() if key in weights)
            overall_similarity = sum(similarity_scores[key] * weights[key] for key in similarity_scores.keys() if key in weights) / total_weight
            
            # If similarity is above threshold, add to results
            if overall_similarity >= threshold:
                similar_shellcodes.append({
                    'id': sc_id,
                    'similarity': overall_similarity,
                    'metrics': similarity_scores,
                    'entry': sc_entry
                })
        
        # Sort by similarity (highest first)
        similar_shellcodes.sort(key=lambda x: x['similarity'], reverse=True)
        
        return similar_shellcodes
    def show_disassembly(self, obj, *, depth=0, show_line_numbers=True, show_bytecode=True):
        # Set disassembly options
        dis_options = {}
        if not show_line_numbers:
            dis_options['show_lineno'] = False
        if not show_bytecode:
            dis_options['show_codevalue'] = False
        
        # Handle different types of objects
        if isinstance(obj, types.CodeType):
            print(f"Disassembly of code object at {hex(id(obj))}:")
            dis.dis(obj, **dis_options)
        elif inspect.isfunction(obj) or inspect.ismethod(obj):
            print(f"Disassembly of {obj.__name__}:")
            dis.dis(obj, **dis_options)
        elif inspect.isclass(obj):
            print(f"Disassembly of class {obj.__name__}:")
            for name, method in inspect.getmembers(obj, predicate=inspect.isfunction):
                print(f"\nMethod: {name}")
                dis.dis(method, **dis_options)
        elif inspect.ismodule(obj):
            print(f"Disassembly of module {obj.__name__}:")
            for name, func in inspect.getmembers(obj, predicate=inspect.isfunction):
                print(f"\nFunction: {name}")
                dis.dis(func, **dis_options)
        else:
            try:
                code = compile(obj, '<string>', 'exec')
                print("Disassembly of compiled code:")
                dis.dis(code, **dis_options)
            except (TypeError, ValueError):
                print(f"Cannot disassemble object of type {type(obj).__name__}")
        
        # Handle recursion for nested code objects if depth > 0
        if depth > 0 and hasattr(obj, '__code__'):
            code = obj.__code__
            for const in code.co_consts:
                if isinstance(const, types.CodeType):
                    print("\n" + "-" * 40)
                    self.show_disassembly(const, depth=depth-1, 
                                show_line_numbers=show_line_numbers,
                                show_bytecode=show_bytecode)
    def _init_disassembler(self):
        """Initialize the disassembler component"""
        try:
            return CodeDisassembler()
        except Exception as e:
            logging.debug(f"Failed to initialize disassembler: {str(e)}")
            return None
    def scan_for_shellcode(self, memory_data, base_address=0, process_info=None, options=None):
        """
        Scan memory data for shellcode patterns and suspicious code constructs
        
        Args:
            memory_data (bytes): Binary data to scan for shellcode
            base_address (int): Base memory address of the data for proper address calculation
            process_info (dict): Information about the process (name, pid, etc.)
            options (dict): Scanning options and thresholds
        
        Returns:
            dict: Detection results including found patterns and disassembly
        """
        # Initialize disassembler if not already done
        if not hasattr(self, 'disassembler') or self.disassembler is None:
            self.disassembler = CodeDisassembler()
        
        # Default process info and options if not provided
        if process_info is None:
            process_info = {
                'name': 'unknown',
                'pid': 0,
                'path': '',
                'cmdline': '',
                'user': '',
                'start_time': '',
                'memory_region': 'unknown'
            }
            
        if options is None:
            options = {
                'entropy_threshold': 6.8,         # Threshold for high entropy detection
                'min_pattern_count': 2,           # Minimum patterns to consider as suspicious
                'max_disassembly_size': 8192,     # Maximum bytes to disassemble
                'show_disassembly': True,         # Whether to produce disassembly
                'search_xor': True,               # Look for XOR encoding
                'detect_nop_sleds': True,         # Look for NOP sleds
                'scan_depth': 'full'              # 'quick', 'normal', or 'full'
            }
            
        # Initialize result structure
        results = {
            'timestamp': self._get_timestamp(),
            'process': process_info,
            'base_address': base_address,
            'data_size': len(memory_data),
            'entropy': 0.0,
            'patterns_found': [],
            'shellcode_score': 0,
            'is_shellcode': False,
            'disassembly': [],
            'signatures_matched': []
        }
        
        # Check if enough data to analyze
        if len(memory_data) < 16:
            results['error'] = "Insufficient data for analysis"
            return results
            
        # Calculate entropy
        results['entropy'] = self._calculate_entropy(memory_data)
        
        # Perform shellcode pattern detection
        patterns = self.detect_shellcode(memory_data)
        
        # Add results - handle both tuple and dict formats
        if isinstance(patterns, list):
            for pattern_item in patterns:
                if isinstance(pattern_item, tuple) and len(pattern_item) >= 2:
                    pattern_name, offset = pattern_item[0], pattern_item[1]
                elif isinstance(pattern_item, dict):
                    pattern_name = pattern_item.get('type', 'Unknown Pattern')
                    offset = pattern_item.get('offset', 0)
                else:
                    continue
                    
                pattern_info = {
                    'pattern': pattern_name,
                    'offset': offset,
                    'address': base_address + offset,
                    'hex_signature': self._bytes_to_hex(memory_data[offset:offset+16])
                }
                results['patterns_found'].append(pattern_info)
                results['shellcode_score'] += 10  # Increment score for each pattern
        
        # Check for high entropy
        if results['entropy'] > options['entropy_threshold']:
            results['patterns_found'].append({
                'pattern': 'High Entropy Data',
                'offset': 0,
                'address': base_address,
                'hex_signature': self._bytes_to_hex(memory_data[0:16])
            })
            results['shellcode_score'] += 15
            
        # Check for NOP sleds if enabled
        if options['detect_nop_sleds'] and b'\x90\x90\x90\x90\x90\x90\x90\x90' in memory_data:
            nop_offset = memory_data.find(b'\x90\x90\x90\x90\x90\x90\x90\x90')
            results['patterns_found'].append({
                'pattern': 'NOP Sled',
                'offset': nop_offset,
                'address': base_address + nop_offset,
                'hex_signature': self._bytes_to_hex(memory_data[nop_offset:nop_offset+16])
            })
            results['shellcode_score'] += 20
            
        # Check for XOR encoding if enabled
        if options['search_xor'] and self._detect_xor_encoding(memory_data):
            results['patterns_found'].append({
                'pattern': 'Possible XOR Encoding',
                'offset': 0,
                'address': base_address,
                'hex_signature': self._bytes_to_hex(memory_data[0:16])
            })
            results['shellcode_score'] += 15
        
        # Determine if this is likely shellcode
        results['is_shellcode'] = (
            results['shellcode_score'] >= 20 or 
            len(results['patterns_found']) >= options['min_pattern_count'] or
            (results['entropy'] > options['entropy_threshold'] and len(results['patterns_found']) > 0)
        )
        
        # Generate disassembly if requested and shellcode is detected
        if options['show_disassembly'] and results['is_shellcode']:
            try:
                # Limit disassembly size
                disasm_size = min(len(memory_data), options['max_disassembly_size'])
                results['disassembly'] = self.disassembler.disassemble_bytes(
                    memory_data[:disasm_size], 
                    base_address
                )
            except Exception as e:
                logging.debug(f"Error generating disassembly: {str(e)}")
                results['disassembly'] = [{"error": f"Disassembly failed: {str(e)}"}]
        
        # Add detection entry if shellcode is found
        if results['is_shellcode'] and hasattr(self, 'tome') and self.tome:
            try:
                self.tome.add_entry('shellcode_patterns', {
                    'process': process_info.get('name', 'unknown'),
                    'pid': process_info.get('pid', 0),
                    'address': hex(base_address),
                    'size': len(memory_data),
                    'patterns': [p['pattern'] for p in results['patterns_found']],
                    'entropy': results['entropy'],
                    'timestamp': results['timestamp']
                })
            except Exception as e:
                logging.debug(f"Error adding to tome: {str(e)}")
            
        return results
    def detect_shellcode(self, memory_content, base_address=0, detailed=True):
        """
        Comprehensive shellcode detection with advanced heuristics
        
        Args:
            memory_content (bytes): Binary data to analyze
            base_address (int): Memory base address for reporting
            detailed (bool): Whether to return detailed analysis or simple findings
            
        Returns:
            If detailed=True: Dictionary with comprehensive analysis
            If detailed=False: List of tuples (pattern_name, offset)
        """
        # Initialize both simple and detailed result structures
        findings = []
        analysis = {
            'found': False,
            'patterns': [],
            'characteristics': [],
            'risk_level': 0,
            'location': hex(base_address),
            'entropy': 0.0,
            'size': len(memory_content),
            'disassembly_preview': []
        }
        
        # Skip analysis if content is too small
        if len(memory_content) < 8:
            if detailed:
                return analysis
            return findings
        
        # Calculate entropy first for early bailout optimization
        entropy = self._calculate_entropy(memory_content)
        analysis['entropy'] = entropy
        
        # Common shellcode patterns (combined from both implementations)
        PATTERNS = {
            # Core shellcode techniques
            'API_Hashing': rb'\x33\xC0\x68.*?\x00\x50\x68.*?\x00\x50|\x74\x0c\x75\x14\xb8[\x00-\xff]{4}',
            'Function_Prologue': rb'\x55\x8B\xEC|\x55\x89\xE5|\x48\x89\x5c',
            'Stack_Setup': rb'\x83\xec[\x00-\xff]\x83\xe4\xf0',
            'GetEIP': rb'\xE8\x00\x00\x00\x00\x58',
            'PEB_Access': rb'\x64\xA1\x30\x00\x00\x00',
            'SEH_Setup': rb'\x33\xC0\x64\x8B',
            'Egg_Hunter': rb'\x66\x81\xCA\xFF\x0F\x42|\x66\x81\xca\xff\x0f\x42\x52\x6a\x02',
            'NOP_Sled': rb'\x90\x90\x90\x90\x90\x90',
            'Syscall': rb'\x0f\x34|\x0f\x05|\xcd\x80',
            'Register_Zero': rb'\x33\xc0|\x31\xc0|\x48\x31',
            'ROP_Gadget': rb'\xc3|\xc2[\x00-\xff]{2}',
            'Memory_Allocation': rb'\x68[\x00-\xff]{4}\x54\xff\xd5',
            'String_Copy_Loop': rb'\xac\xaa\xe2\xfa',
            'XOR_Decoder': rb'\x30[\x00-\xff]\x40\x39[\x00-\xff]\x75',
            'Stack_Strings': rb'\x68[\x20-\x7f]{4}|\x6a[\x20-\x7f]'
        }
        
        # Scan for all patterns
        for name, pattern in PATTERNS.items():
            try:
                matches = re.finditer(pattern, memory_content, re.DOTALL)
                for match in matches:
                    offset = match.start()
                    
                    # Add to simple findings list
                    findings.append((name, offset))
                    
                    # Add to detailed analysis
                    pattern_info = {
                        'type': name,
                        'offset': offset,
                        'address': base_address + offset,
                        'bytes': memory_content[offset:min(offset+16, len(memory_content))].hex(' ')
                    }
                    analysis['patterns'].append(pattern_info)
                    
                    # Adjust risk level based on pattern type
                    if name in ['Egg_Hunter', 'PEB_Access', 'XOR_Decoder']:
                        analysis['risk_level'] += 3  # Higher risk patterns
                    elif name in ['NOP_Sled', 'GetEIP', 'Syscall']:
                        analysis['risk_level'] += 2  # Medium risk patterns
                    else:
                        analysis['risk_level'] += 1  # Standard patterns
            except Exception as e:
                import logging
                logging.debug(f"Error matching pattern {name}: {str(e)}")
        
        # Advanced heuristics
        characteristics = []
        
        # Check for position-independent code indicators
        if b'\xff\x34\x24' in memory_content or b'\x58\x59\x5a' in memory_content:
            characteristics.append('position_independent')
            analysis['risk_level'] += 2
        
        # High entropy indicates encryption/encoding
        if entropy > 7.0:
            characteristics.append('high_entropy')
            analysis['risk_level'] += 3
        elif entropy > 6.5:
            characteristics.append('medium_entropy')
            analysis['risk_level'] += 1
        
        # Check for small code blocks (common in shellcode)
        if len(memory_content) < 2048 and len(memory_content) > 40:
            characteristics.append('small_code_block')
            analysis['risk_level'] += 1
        
        # Check for stack/heap operations
        if b'\x89\xe5' in memory_content or b'\x8b\xe5' in memory_content:
            characteristics.append('stack_manipulation')
            analysis['risk_level'] += 1
        
        # Check for null-free sections (common in shellcode constraints)
        null_free_sections = self._find_null_free_sections(memory_content)
        if null_free_sections and max(null_free_sections, key=lambda x: x[1]-x[0])[1] - max(null_free_sections, key=lambda x: x[1]-x[0])[0] > 30:
            characteristics.append('null_free')
            analysis['risk_level'] += 2
        
        # Check for suspicious call patterns (commonly used in shellcode to get EIP)
        if b'\xe8' in memory_content and b'\x59' in memory_content:
            characteristics.append('call_pop_sequence')
            analysis['risk_level'] += 2
        
        # Executable stack indicators
        if b'\x64\x8f\x05\x00\x00\x00\x00' in memory_content:
            characteristics.append('executable_stack')
            analysis['risk_level'] += 3
        
        # Update analysis dictionary
        analysis['characteristics'] = characteristics
        analysis['found'] = analysis['risk_level'] > 3 or len(analysis['patterns']) >= 2
        
        # Generate brief disassembly preview if available
        if hasattr(self, 'disassembler') and callable(getattr(self.disassembler, 'disassemble_bytes', None)):
            try:
                preview_size = min(len(memory_content), 64)  # First 64 bytes
                preview = self.disassembler.disassemble_bytes(memory_content[:preview_size], base_address)
                analysis['disassembly_preview'] = preview[:10]  # First 10 instructions
            except Exception:
                pass
        
        # Return appropriate result based on detailed flag
        if detailed:
            return analysis
        return findings

    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of binary data"""
        import math
        if not data:
            return 0
            
        entropy = 0
        size = len(data)
        # Count byte occurrences
        counts = {}
        for byte in data:
            counts[byte] = counts.get(byte, 0) + 1
            
        # Calculate entropy
        for count in counts.values():
            probability = count / size
            entropy -= probability * math.log(probability, 2)
            
        return entropy

    def _find_null_free_sections(self, data, min_length=20):
        """Find sections of data without null bytes"""
        sections = []
        start = None
        
        for i, byte in enumerate(data):
            if byte != 0 and start is None:
                start = i
            elif byte == 0 and start is not None:
                if i - start >= min_length:
                    sections.append((start, i))
                start = None
        
        # Handle case where section extends to end
        if start is not None and len(data) - start >= min_length:
            sections.append((start, len(data)))
            
        return sections
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of binary data"""
        import math
        if not data:
            return 0
            
        entropy = 0
        size = len(data)
        # Count byte occurrences
        counts = {}
        for byte in data:
            counts[byte] = counts.get(byte, 0) + 1
            
        # Calculate entropy
        for count in counts.values():
            probability = count / size
            entropy -= probability * math.log(probability, 2)
            
        return entropy

    def _bytes_to_hex(self, data, max_len=32):
        """Convert bytes to hex string representation"""
        if len(data) > max_len:
            data = data[:max_len]
        return ' '.join(f'{b:02x}' for b in data)

    def _detect_xor_encoding(self, data, sample_size=256):
        """Detect possible XOR encoding in data"""
        if len(data) < 20:
            return False
            
        # Limit the sample size for performance
        sample = data[:min(len(data), sample_size)]
        
        # Look for repeating XOR patterns
        for key in range(1, 256):
            decoded = bytes(b ^ key for b in sample)
            
            # Check if decoded data looks like code or text
            text_chars = sum(1 for b in decoded if 32 <= b <= 126)
            if text_chars > len(decoded) * 0.7:
                return True
                
            # Check for code patterns in decoded data
            code_patterns = [b'\x55\x8b\xec', b'\x48\x89\x5c', b'\x48\x83\xec', b'\x55\x48\x8b\xec']
            if any(pattern in decoded for pattern in code_patterns):
                return True
                
        return False

    def _get_timestamp(self):
        """Get current timestamp string"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    def _extract_instructions(self, shellcode_data, address=0):
       
        if not shellcode_data:
            return []
            
        normalized_instructions = []
        
        try:
            # Try to use capstone if available
            if hasattr(self, 'cs'):
                instructions = list(self.cs.disasm(shellcode_data, address))
                
                for instr in instructions:
                    # Normalize the instruction by removing specific addresses
                    # Keep only mnemonic and register/immediate operands
                    normalized = instr.mnemonic
                    
                    # For instructions with operands, normalize them
                    if instr.op_str:
                        # Replace memory addresses with placeholder
                        op_normalized = re.sub(r'0x[0-9a-f]+', 'ADDR', instr.op_str)
                        # Replace specific offsets with placeholder
                        op_normalized = re.sub(r'\+[0-9a-f]+\]', '+OFFSET]', op_normalized)
                        # Keep register names and immediate values that aren't addresses
                        normalized += " " + op_normalized
                        
                    normalized_instructions.append(normalized)
            else:
                # Fallback to a more basic approach if no disassembler
                # This is a simplified approach that looks for common instruction patterns
                patterns = [
                    # mov instructions
                    (rb'\x89[\xC0-\xFF]', 'mov reg, reg'),
                    (rb'\x8B[\xC0-\xFF]', 'mov reg, reg'),
                    (rb'\xB8[\x00-\xFF]{4}', 'mov eax, imm32'),
                    (rb'\xB9[\x00-\xFF]{4}', 'mov ecx, imm32'),
                    # push/pop
                    (rb'\x50[\x00-\x57]', 'push reg'),
                    (rb'\x58[\x00-\x5F]', 'pop reg'),
                    # jumps
                    (rb'\xEB[\x00-\xFF]', 'jmp short'),
                    (rb'\xE9[\x00-\xFF]{4}', 'jmp near'),
                    # calls
                    (rb'\xE8[\x00-\xFF]{4}', 'call'),
                    (rb'\xFF[\xD0-\xD7]', 'call reg'),
                    # arithmetic
                    (rb'\x01[\xC0-\xFF]', 'add reg, reg'),
                    (rb'\x29[\xC0-\xFF]', 'sub reg, reg'),
                    (rb'\x31[\xC0-\xFF]', 'xor reg, reg'),
                    (rb'\x33[\xC0-\xFF]', 'xor reg, reg'),
                    # common shellcode instructions
                    (rb'\xC3', 'ret'),
                    (rb'\xC9', 'leave'),
                    (rb'\x90', 'nop'),
                ]
                
                # Scan shellcode for instruction patterns
                for i in range(len(shellcode_data)):
                    for pattern, instruction in patterns:
                        if i + len(pattern) - 1 < len(shellcode_data):
                            chunk = shellcode_data[i:i+len(pattern)]
                            if re.match(pattern, chunk):
                                normalized_instructions.append(instruction)
                                break
        except Exception as e:
            # Log error and return what we have so far
            if hasattr(self, 'logger'):
                logging.debug(f"Error extracting instructions: {str(e)}")
        
        return normalized_instructions
    def transfer_detected_to_capture(self, ShellCode_Capture):
        """
        Transfer all detected shellcode to a ShellcodeCapture instance
        
        Args:
            ShellCode_Capture (ShellcodeCapture): Instance of ShellcodeCapture to store the shellcode
        
        Returns:
            Number of shellcode entries transferred
        """
        sc_id = hashlib.sha256(sc_data['data']).hexdigest()[:16]
        count = 0
        for sc_id, sc_data in self.shellcode_tome.items():
            for location in sc_data['locations']:
                source_info = f"Region: {location['region_name']}, Address: {location['address']}"
                self.ShellCode_Capture.capture_shellcode(
                    sc_data['data'],
                    start_addr=location['address'],
                    source_info=source_info
                )
                count += 1
        return count
    def export_to_reporting(self, Reporter):
        """
        Export all shellcodes in the tome to the reporting system
        
        Args:
            reporter: Instance of ShellcodeReporter
            
        Returns:
            Number of shellcodes exported
        """
        self.Reporter = ShellcodeReporter
        count = 0
        for sc_id, sc_data in self.shellcode_tome.items():
            for location in sc_data.get('locations', []):
                shellcode_entry = {
                    'id': sc_id,
                    'data': sc_data.get('data', b''),
                    'size': sc_data.get('size', 0),
                    'address': location.get('address', 0),
                    'region_name': location.get('region_name', 'unknown'),
                    'detection_method': 'shellcode_detector_tome'
                }
                
                if self.Reporter.log_shellcode(shellcode_entry):
                    count += 1
                    
        return count
class ShellCodeTome:
    """
    🧙‍♂️ The Ancient ShellCode Tome - A mystical, ever-learning repository of dark magic 🧙‍♂️
    
    This arcane codex grows more powerful with each detection, learning patterns like an ancient wizard.
    Each shellcode discovered becomes a new spell in our grimoire of cyber defense knowledge.
    
    ✨ Features of the Ancient Tome:
    - 📜 Persistent learning from every encounter
    - 🔮 Pattern recognition that evolves over time
    - 🌟 Categorized spells for different types of dark magic
    - 📊 Wisdom statistics tracking the tome's growth
    - 🕯️ Mystical insights from accumulated knowledge
    """
    def __init__(self, shellcode_detector=None, disassembler=None, tome_path="memory_quarantine/ancient_tome.db"):
        # Ancient spell categories with mystical descriptions
        self.detections = {
            'api_hashing': [],      # 🪄 API Hashing Spells - Dynamic symbol resolution magic
            'egg_hunters': [],      # 🥚 Egg Hunter Incantations - Memory seeking rituals
            'process_injection': [],# 💉 Process Injection Spells - Soul transfer magic
            'xor_encoding': [],     # ⚗️ XOR Encoding Alchemy - Transformation ciphers
            'stack_strings': [],    # 📚 Stack String Scrolls - Hidden message spells
            'peb_access': [],       # 🏛️ PEB Access Rituals - System structure divination
            'reflective_loading': [],# 🪞 Reflective Loading - Mirror dimension conjuring
            'rop_chains': [],       # ⛓️ ROP Chain Binding - Code fragment linking spells
            'shellcode_patterns': [],# 🐚 Pure Shellcode - Raw magical essence
            'rwx_memory': [],       # 🔥 RWX Memory - Tri-permission fire magic
            'wx_memory': [],        # ⚡ WX Memory - Dual-permission lightning spells
            'cfg_bypass': [],       # 🌊 CFG Bypass - Control flow water magic
            'process_hollowing': [], # 👻 Process Hollowing - Possession rituals
            'suspicious_memory': [], # 🌫️ Suspicious Memory - Clouded realm detection
            'unsigned_modules': [], # 📋 Unsigned Modules - Untrusted artifact identification
            'suspicious_registry': [],# 🗝️ Registry Dark Arts - System key manipulation
            'suspicious_cmdline': [],# 👑 Command Line Sorcery - Terminal spell casting
            'yara_matches': [],     # 🎯 YARA Pattern Magic - Signature-based detection spells
            'unknown_magic': []     # 🌟 Unknown Magic - New spells yet to be categorized
        }
        
        # Tome's ancient wisdom tracking
        self.tome_wisdom = {
            'total_spells_learned': 0,
            'categories_discovered': set(),
            'unique_patterns_identified': 0,
            'tome_creation_date': datetime.now().isoformat(),
            'last_learning_session': None,
            'most_common_magic_type': None,
            'rarest_spells': [],
            'learning_velocity': 0.0,  # Spells learned per hour
            'power_level': 1,          # Increases with knowledge
            'ancient_knowledge_unlocked': []
        }
        
        # Database for persistent learning
        self.tome_path = tome_path
        self.ensure_tome_directory()
        self.init_ancient_database()
        
        # Load previous wisdom if available
        self.load_ancient_wisdom()
        self.ShellCodeDetector = None  # Will be set later to avoid circular dependency
        self.Disassembler = CodeDisassembler()
        self.total_detections = 0
        # Use provided components or create built-in versions
    
    def ensure_tome_directory(self):
        """Ensure the ancient tome's directory structure exists"""
        tome_dir = Path(self.tome_path).parent
        tome_dir.mkdir(parents=True, exist_ok=True)
        
    def init_ancient_database(self):
        """Initialize the SQLite database for persistent learning"""
        try:
            conn = sqlite3.connect(self.tome_path)
            cursor = conn.cursor()
            
            # Create spells table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ancient_spells (
                    id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    spell_name TEXT NOT NULL,
                    pattern_data BLOB,
                    discovery_date TEXT NOT NULL,
                    process_name TEXT,
                    memory_address TEXT,
                    entropy REAL,
                    confidence_level TEXT,
                    power_rating INTEGER DEFAULT 1,
                    times_encountered INTEGER DEFAULT 1,
                    last_seen TEXT,
                    disassembly TEXT,
                    metadata TEXT
                )
            ''')
            
            # Create wisdom table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tome_wisdom (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_date TEXT NOT NULL
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Failed to initialize ancient tome database: {str(e)}")
    
    def load_ancient_wisdom(self):
        """Load previously accumulated wisdom from the database"""
        try:
            conn = sqlite3.connect(self.tome_path)
            cursor = conn.cursor()
            
            # Load wisdom stats
            cursor.execute('SELECT key, value FROM tome_wisdom')
            for key, value in cursor.fetchall():
                if key in self.tome_wisdom:
                    try:
                        if key == 'categories_discovered':
                            self.tome_wisdom[key] = set(json.loads(value))
                        elif key in ['total_spells_learned', 'unique_patterns_identified', 'power_level']:
                            self.tome_wisdom[key] = int(value)
                        elif key == 'learning_velocity':
                            self.tome_wisdom[key] = float(value)
                        else:
                            self.tome_wisdom[key] = value
                    except (json.JSONDecodeError, ValueError):
                        pass
            
            # Load spells from database
            cursor.execute('SELECT category, COUNT(*) FROM ancient_spells GROUP BY category')
            for category, count in cursor.fetchall():
                if category in self.detections:
                    # We'll load actual spells on demand to save memory
                    self.tome_wisdom['categories_discovered'].add(category)
            
            conn.close()
            
            # Update power level based on accumulated knowledge
            self._calculate_power_level()
            
        except Exception as e:
            logging.debug(f"Could not load ancient wisdom: {str(e)}")
    
    def save_ancient_wisdom(self):
        """Save current wisdom to the database"""
        try:
            conn = sqlite3.connect(self.tome_path)
            cursor = conn.cursor()
            
            current_time = datetime.now().isoformat()
            
            for key, value in self.tome_wisdom.items():
                if key == 'categories_discovered':
                    value_str = json.dumps(list(value))
                else:
                    value_str = str(value)
                    
                cursor.execute('''
                    INSERT OR REPLACE INTO tome_wisdom (key, value, updated_date)
                    VALUES (?, ?, ?)
                ''', (key, value_str, current_time))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Failed to save ancient wisdom: {str(e)}")
    
    def _calculate_power_level(self):
        """Calculate the tome's power level based on accumulated knowledge"""
        total_spells = self.tome_wisdom['total_spells_learned']
        categories = len(self.tome_wisdom['categories_discovered'])
        patterns = self.tome_wisdom['unique_patterns_identified']
        
        # Ancient formula for power calculation
        base_power = min(10, total_spells // 10)  # 1 power per 10 spells
        category_bonus = min(5, categories)       # Bonus for diversity
        pattern_bonus = min(5, patterns // 20)   # Bonus for unique patterns
        
        self.tome_wisdom['power_level'] = max(1, base_power + category_bonus + pattern_bonus)
        
        # Unlock ancient knowledge at certain power levels
        if self.tome_wisdom['power_level'] >= 5 and "pattern_correlation" not in self.tome_wisdom['ancient_knowledge_unlocked']:
            self.tome_wisdom['ancient_knowledge_unlocked'].append("pattern_correlation")
            
        if self.tome_wisdom['power_level'] >= 10 and "predictive_analysis" not in self.tome_wisdom['ancient_knowledge_unlocked']:
            self.tome_wisdom['ancient_knowledge_unlocked'].append("predictive_analysis")

    def set_shellcode_detector(self, detector):
        """Set the shellcode detector to avoid circular dependency"""
        self.ShellCodeDetector = detector
    def _create_default_shellcode_detector(self):
        """Create a default shellcode detector instance"""
        return self.ShellCodeDetector()

    def _create_default_disassembler(self):
        """Create a default disassembler instance"""
        return self.Disassembler()
    def add_entry(self, category, entry):
        """🧙‍♂️ Add a new spell (detection entry) to the ancient tome with learning capabilities"""
        if category not in self.detections:
            # Unknown magic gets added to unknown_magic category
            category = 'unknown_magic'
            
        # Enhanced entry with magical metadata
        enhanced_entry = {
            **entry,
            'spell_id': hashlib.sha256(str(entry).encode()).hexdigest()[:16],
            'discovered_at': datetime.now().isoformat(),
            'power_rating': self._calculate_spell_power(entry),
            'tome_wisdom_level': self.tome_wisdom['power_level']
        }
        
        # Add to memory collection
        self.detections[category].append(enhanced_entry)
        self.total_detections += 1
        
        # Update tome wisdom
        self.tome_wisdom['total_spells_learned'] += 1
        self.tome_wisdom['categories_discovered'].add(category)
        self.tome_wisdom['last_learning_session'] = datetime.now().isoformat()
        
        # Calculate learning velocity
        if self.tome_wisdom['tome_creation_date']:
            creation_time = datetime.fromisoformat(self.tome_wisdom['tome_creation_date'])
            hours_elapsed = (datetime.now() - creation_time).total_seconds() / 3600
            if hours_elapsed > 0:
                self.tome_wisdom['learning_velocity'] = self.tome_wisdom['total_spells_learned'] / hours_elapsed
        
        # Persist to database
        self._persist_spell_to_database(category, enhanced_entry)
        
        # Update power level and unlock ancient knowledge
        self._calculate_power_level()
        
        # Save wisdom updates
        self.save_ancient_wisdom()
        
        # Log the mystical learning event
        logging.info(f"🌟 New {category} spell learned! Tome power level: {self.tome_wisdom['power_level']}")
        
        return True
    
    def _calculate_spell_power(self, entry):
        """Calculate the magical power of a detected spell"""
        base_power = 1
        
        # Boost power based on confidence
        confidence = entry.get('confidence', 'medium').lower()
        if confidence == 'high':
            base_power += 2
        elif confidence == 'medium':
            base_power += 1
            
        # Boost for certain types of magic
        entry_type = entry.get('type', '').lower()
        if any(keyword in entry_type for keyword in ['injection', 'hollowing', 'evasion']):
            base_power += 3
        elif any(keyword in entry_type for keyword in ['xor', 'encoding', 'obfuscation']):
            base_power += 2
            
        # Boost for rarity (less common patterns are more powerful)
        if entry_type and len([e for e in self.detections.get(self._get_category_for_type(entry_type), []) if e.get('type', '').lower() == entry_type]) < 5:
            base_power += 1
            
        return min(10, base_power)  # Cap at 10
    
    def _get_category_for_type(self, entry_type):
        """Determine the appropriate category for a detection type"""
        entry_type = entry_type.lower()
        
        if 'api' in entry_type and 'hash' in entry_type:
            return 'api_hashing'
        elif 'egg hunter' in entry_type:
            return 'egg_hunters'
        elif 'injection' in entry_type:
            return 'process_injection'
        elif 'xor' in entry_type:
            return 'xor_encoding'
        elif 'stack string' in entry_type:
            return 'stack_strings'
        elif 'peb' in entry_type:
            return 'peb_access'
        elif 'reflective' in entry_type or 'getpc' in entry_type:
            return 'reflective_loading'
        elif 'rop' in entry_type:
            return 'rop_chains'
        elif 'shellcode' in entry_type:
            return 'shellcode_patterns'
        elif 'rwx' in entry_type:
            return 'rwx_memory'
        elif 'wx' in entry_type:
            return 'wx_memory'
        elif 'cfg' in entry_type:
            return 'cfg_bypass'
        elif 'hollowing' in entry_type:
            return 'process_hollowing'
        elif 'memory' in entry_type:
            return 'suspicious_memory'
        elif 'unsigned' in entry_type:
            return 'unsigned_modules'
        elif 'registry' in entry_type:
            return 'suspicious_registry'
        elif 'command' in entry_type or 'cmdline' in entry_type:
            return 'suspicious_cmdline'
        elif 'yara' in entry_type:
            return 'yara_matches'
        else:
            return 'unknown_magic'
    
    def _persist_spell_to_database(self, category, entry):
        """Persist a spell to the ancient database"""
        try:
            conn = sqlite3.connect(self.tome_path)
            cursor = conn.cursor()
            
            spell_data = {
                'id': entry.get('spell_id'),
                'category': category,
                'spell_name': entry.get('type', 'Unknown Spell'),
                'pattern_data': json.dumps(entry).encode('utf-8'),
                'discovery_date': entry.get('discovered_at'),
                'process_name': entry.get('process', 'Unknown'),
                'memory_address': entry.get('location', ''),
                'entropy': entry.get('entropy', 0.0),
                'confidence_level': entry.get('confidence', 'medium'),
                'power_rating': entry.get('power_rating', 1),
                'times_encountered': 1,
                'last_seen': entry.get('discovered_at'),
                'disassembly': entry.get('disassembly', ''),
                'metadata': json.dumps({
                    'details': entry.get('details', ''),
                    'tome_power_level': entry.get('tome_wisdom_level', 1)
                })
            }
            
            # Check if spell already exists
            cursor.execute('SELECT id, times_encountered FROM ancient_spells WHERE id = ?', (spell_data['id'],))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing spell
                cursor.execute('''
                    UPDATE ancient_spells 
                    SET times_encountered = times_encountered + 1, last_seen = ?
                    WHERE id = ?
                ''', (datetime.now().isoformat(), spell_data['id']))
            else:
                # Insert new spell
                cursor.execute('''
                    INSERT INTO ancient_spells (
                        id, category, spell_name, pattern_data, discovery_date,
                        process_name, memory_address, entropy, confidence_level,
                        power_rating, times_encountered, last_seen, disassembly, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', tuple(spell_data.values()))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Failed to persist spell to database: {str(e)}")
    
    def browse_ancient_spells(self, category=None, limit=50, offset=0):
        """🔍 Browse the ancient spells stored in the tome"""
        try:
            conn = sqlite3.connect(self.tome_path)
            cursor = conn.cursor()
            
            if category:
                query = '''
                    SELECT id, spell_name, category, discovery_date, process_name, 
                           confidence_level, power_rating, times_encountered, last_seen
                    FROM ancient_spells 
                    WHERE category = ?
                    ORDER BY discovery_date DESC
                    LIMIT ? OFFSET ?
                '''
                cursor.execute(query, (category, limit, offset))
            else:
                query = '''
                    SELECT id, spell_name, category, discovery_date, process_name, 
                           confidence_level, power_rating, times_encountered, last_seen
                    FROM ancient_spells 
                    ORDER BY discovery_date DESC
                    LIMIT ? OFFSET ?
                '''
                cursor.execute(query, (limit, offset))
            
            spells = []
            for row in cursor.fetchall():
                spells.append({
                    'id': row[0],
                    'name': row[1],
                    'category': row[2],
                    'discovered': row[3],
                    'process': row[4],
                    'confidence': row[5],
                    'power': row[6],
                    'encounters': row[7],
                    'last_seen': row[8]
                })
            
            conn.close()
            return spells
            
        except Exception as e:
            logging.error(f"Failed to browse ancient spells: {str(e)}")
            return []
    
    def get_spell_details(self, spell_id):
        """📜 Get detailed information about a specific spell"""
        try:
            conn = sqlite3.connect(self.tome_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM ancient_spells WHERE id = ?
            ''', (spell_id,))
            
            row = cursor.fetchone()
            if row:
                spell_details = {
                    'id': row[0],
                    'category': row[1],
                    'spell_name': row[2],
                    'pattern_data': json.loads(row[3].decode('utf-8')),
                    'discovery_date': row[4],
                    'process_name': row[5],
                    'memory_address': row[6],
                    'entropy': row[7],
                    'confidence_level': row[8],
                    'power_rating': row[9],
                    'times_encountered': row[10],
                    'last_seen': row[11],
                    'disassembly': row[12],
                    'metadata': json.loads(row[13]) if row[13] else {}
                }
                
                conn.close()
                return spell_details
            
            conn.close()
            return None
            
        except Exception as e:
            logging.error(f"Failed to get spell details: {str(e)}")
            return None
    
    def get_tome_statistics(self):
        """📊 Get comprehensive statistics about the ancient tome"""
        try:
            stats = {
                'overview': self.tome_wisdom.copy(),
                'category_breakdown': {},
                'power_distribution': {},
                'recent_activity': [],
                'most_encountered_spells': [],
                'highest_power_spells': []
            }
            
            conn = sqlite3.connect(self.tome_path)
            cursor = conn.cursor()
            
            # Category breakdown
            cursor.execute('''
                SELECT category, COUNT(*), AVG(power_rating), MAX(times_encountered)
                FROM ancient_spells 
                GROUP BY category
                ORDER BY COUNT(*) DESC
            ''')
            
            for row in cursor.fetchall():
                stats['category_breakdown'][row[0]] = {
                    'count': row[1],
                    'avg_power': round(row[2], 2),
                    'max_encounters': row[3]
                }
            
            # Power distribution
            cursor.execute('''
                SELECT power_rating, COUNT(*) 
                FROM ancient_spells 
                GROUP BY power_rating
                ORDER BY power_rating
            ''')
            
            for row in cursor.fetchall():
                stats['power_distribution'][row[0]] = row[1]
            
            # Recent activity (last 10 spells)
            cursor.execute('''
                SELECT spell_name, category, discovery_date, power_rating
                FROM ancient_spells 
                ORDER BY discovery_date DESC
                LIMIT 10
            ''')
            
            for row in cursor.fetchall():
                stats['recent_activity'].append({
                    'name': row[0],
                    'category': row[1],
                    'date': row[2],
                    'power': row[3]
                })
            
            # Most encountered spells
            cursor.execute('''
                SELECT spell_name, category, times_encountered, power_rating
                FROM ancient_spells 
                ORDER BY times_encountered DESC
                LIMIT 10
            ''')
            
            for row in cursor.fetchall():
                stats['most_encountered_spells'].append({
                    'name': row[0],
                    'category': row[1],
                    'encounters': row[2],
                    'power': row[3]
                })
            
            # Highest power spells
            cursor.execute('''
                SELECT spell_name, category, power_rating, confidence_level
                FROM ancient_spells 
                ORDER BY power_rating DESC, times_encountered DESC
                LIMIT 10
            ''')
            
            for row in cursor.fetchall():
                stats['highest_power_spells'].append({
                    'name': row[0],
                    'category': row[1],
                    'power': row[2],
                    'confidence': row[3]
                })
            
            conn.close()
            return stats
            
        except Exception as e:
            logging.error(f"Failed to get tome statistics: {str(e)}")
            return None
    
    def search_spells(self, search_term, category=None):
        """🔍 Search for spells by name, process, or other attributes"""
        try:
            conn = sqlite3.connect(self.tome_path)
            cursor = conn.cursor()
            
            search_pattern = f'%{search_term}%'
            
            if category:
                query = '''
                    SELECT id, spell_name, category, discovery_date, process_name, power_rating
                    FROM ancient_spells 
                    WHERE category = ? AND (
                        spell_name LIKE ? OR 
                        process_name LIKE ? OR 
                        memory_address LIKE ?
                    )
                    ORDER BY power_rating DESC, discovery_date DESC
                '''
                cursor.execute(query, (category, search_pattern, search_pattern, search_pattern))
            else:
                query = '''
                    SELECT id, spell_name, category, discovery_date, process_name, power_rating
                    FROM ancient_spells 
                    WHERE spell_name LIKE ? OR 
                          process_name LIKE ? OR 
                          memory_address LIKE ?
                    ORDER BY power_rating DESC, discovery_date DESC
                '''
                cursor.execute(query, (search_pattern, search_pattern, search_pattern))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'id': row[0],
                    'name': row[1],
                    'category': row[2],
                    'discovered': row[3],
                    'process': row[4],
                    'power': row[5]
                })
            
            conn.close()
            return results
            
        except Exception as e:
            logging.error(f"Failed to search spells: {str(e)}")
            return []

    def analyze_shellcode(self, data, base_address=0):
        """Analyze shellcode data using the built-in detector and disassembler"""
        results = {
            'patterns': self.ShellCodeDetector.detect_shellcode(data) if self.ShellCodeDetector else [],
            'flow_analysis': self.ShellCodeDetector._analyze_execution_flow(data, base_address) if self.ShellCodeDetector else {},
            'disassembly': self.Disassembler.disassemble_bytes(data, base_address),
            'entropy': self._calculate_entropy(data),
            'size': len(data)
        }
        return results
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        import math
        if not data:
            return 0
            
        entropy = 0
        size = len(data)
        # Count byte occurrences
        counts = {}
        for byte in data:
            counts[byte] = counts.get(byte, 0) + 1
            
        # Calculate entropy
        for count in counts.values():
            probability = count / size
            entropy -= probability * math.log(probability, 2)
            
        return entropy
    def get_entries(self, category=None):
        """Get all entries in a category or all categories if None"""
        if category:
            return self.detections.get(category, [])
        return self.detections
    
    def analyze_memory_region(self, memory_content, pid, process_name=None, base_addr=0, region_size=0):
        """
        Analyzes a memory region using the shellcode detector and disassembler
        Returns a list of detection dictionaries
        """
        detections = []
        
        # Skip if content is too small for meaningful analysis
        if not memory_content or len(memory_content) < 32:
            return {'detections': detections}
        
        # Initialize Magic if not already done
        if not hasattr(self, 'Magic'):
            from ShellCodeMagic import ShellcodeDetector
            self.Magic = ShellcodeDetector()
        
        # 1. Run shellcode detector analysis using the corrected scan_for_shellcode method
        try:
            shellcode_results = self.Magic.scan_for_shellcode(
                memory_content,
                base_address=base_addr,  # Fixed: was base_addr_int
                process_info={
                    'name': process_name,
                    'pid': pid,
                    'memory_region': f'Region at {hex(base_addr)}'
                }
            )

            if shellcode_results.get('is_shellcode'):
                detection = {
                    'pid': pid,
                    'process': process_name,
                    'type': 'Shellcode Detection',
                    'details': f"Score: {shellcode_results['shellcode_score']}, Patterns: {len(shellcode_results['patterns_found'])}",
                    'confidence': 'high' if shellcode_results['shellcode_score'] > 40 else 'medium',
                    'location': f'Memory region at {hex(base_addr)}, size: {region_size}',
                    'shellcode_analysis': shellcode_results
                }
                
                # Add the detection
                if hasattr(self, 'add_detection'):
                    self.add_detection(detection)
                detections.append(detection)
                
                # Add individual pattern detections
                for pattern in shellcode_results.get('patterns_found', []):
                    pattern_detection = {
                        'pid': pid,
                        'process': process_name,
                        'type': f'Shellcode Pattern: {pattern["pattern"]}',
                        'details': f'Found at offset {pattern["offset"]}, signature: {pattern["hex_signature"]}',
                        'confidence': 'medium',
                        'location': f'Memory region at {hex(pattern["address"])}'
                    }
                    detections.append(pattern_detection)
                    
        except Exception as e:
            logging.debug(f"Error in shellcode detection: {str(e)}")
        
        # 2. Disassemble the region for deeper analysis
        try:
            if not hasattr(self, 'disassembler'):
                from ShellCodeMagic import CodeDisassembler
                self.disassembler = CodeDisassembler()
                
            # Get disassembly as string and parse it
            disasm_output = self.disassembler.disassemble(memory_content, base_addr)
            
            if disasm_output and not disasm_output.startswith("No valid instructions"):
                # Parse disassembly string into instruction list for analysis
                instructions = []
                for line in disasm_output.split('\n'):
                    if line.strip() and ':' in line:
                        instructions.append(line.strip())
                
                # 3. Analyze disassembly for additional patterns
                if hasattr(self, 'analyze_disassembly'):
                    disasm_findings = self.analyze_disassembly(instructions, base_addr)
                    
                    for finding in disasm_findings:
                        detection = {
                            'pid': pid,
                            'process': process_name,
                            'type': finding["type"],
                            'details': finding["details"],
                            'confidence': finding.get("confidence", "medium"),
                            'location': f'Memory region at {hex(base_addr)}, offset: {finding.get("offset", 0)}',
                            'disassembly': finding.get("context", [])
                        }
                        
                        if hasattr(self, 'add_detection'):
                            self.add_detection(detection)
                        detections.append(detection)
                
                # Add disassembly context to existing shellcode detections
                for detection in detections:
                    if 'shellcode_analysis' in detection:
                        detection['disassembly_preview'] = instructions[:10]  # First 10 instructions
                        
        except Exception as e:
            logging.debug(f"Disassembly failed: {str(e)}")
        
        # 4. Additional heuristic checks
        try:
            # Check for suspicious API patterns in raw bytes
            api_patterns = [
                (b'LoadLibrary', 'LoadLibrary API'),
                (b'GetProcAddress', 'GetProcAddress API'),
                (b'VirtualAlloc', 'VirtualAlloc API'),
                (b'CreateProcess', 'CreateProcess API'),
                (b'WriteProcessMemory', 'WriteProcessMemory API')
            ]
            
            for pattern, description in api_patterns:
                if pattern in memory_content:
                    detection = {
                        'pid': pid,
                        'process': process_name,
                        'type': 'Suspicious API Reference',
                        'details': f'{description} found in memory',
                        'confidence': 'low',
                        'location': f'Memory region at {hex(base_addr)}, size: {region_size}'
                    }
                    detections.append(detection)
            
            # Check for executable characteristics
            if hasattr(self.Magic, 'magic_analyzer'):
                magic_result = self.Magic.magic_analyzer.analyze_memory(memory_content)
                if magic_result and ('executable' in magic_result.lower() or 'shellcode' in magic_result.lower()):
                    detection = {
                        'pid': pid,
                        'process': process_name,
                        'type': 'Executable Content',
                        'details': f'Magic analysis: {magic_result}',
                        'confidence': 'medium',
                        'location': f'Memory region at {hex(base_addr)}, size: {region_size}'
                    }
                    detections.append(detection)
                    
        except Exception as e:
            logging.debug(f"Error in additional heuristic checks: {str(e)}")
        
        return {'detections': detections}
    
    def analyze_disassembly(self, instructions, base_addr):
        """
        Analyzes disassembly for common shellcode patterns
        Returns a list of findings
        """
        findings = []
        
        if not instructions:
            return findings
            
        # Track sequences of instructions for pattern matching
        api_call_seq = []
        stack_string_seq = []
        xor_seq = []
        
        # Analyze instruction patterns
        for i, instr in enumerate(instructions):
            # Look for API call preparation
            if instr.mnemonic in ['push', 'mov'] and i < len(instructions) - 3:
                api_call_seq.append(instr)
                if len(api_call_seq) >= 4 and instructions[i+1].mnemonic == 'call':
                    findings.append({
                        "type": "API Call Sequence",
                        "details": "Possible API call preparation",
                        "confidence": "medium",
                        "offset": instructions[i-3].address - base_addr,
                        "context": instructions[i-3:i+2]
                    })
                    api_call_seq = []
            else:
                api_call_seq = []
                
            # Look for stack string construction
            if instr.mnemonic in ['push', 'mov'] and 'byte ptr' in instr.op_str:
                stack_string_seq.append(instr)
                if len(stack_string_seq) >= 4:
                    findings.append({
                        "type": "Stack String Construction",
                        "details": "String being built on stack",
                        "confidence": "high",
                        "offset": stack_string_seq[0].address - base_addr,
                        "context": stack_string_seq.copy()
                    })
            else:
                stack_string_seq = []
                
            # Look for XOR loops
            if instr.mnemonic == 'xor':
                xor_seq.append(instr)
                if len(xor_seq) >= 2:
                    next_instr = instructions[i+1] if i+1 < len(instructions) else None
                    if next_instr and next_instr.mnemonic in ['inc', 'dec', 'add', 'sub', 'loop', 'jnz']:
                        findings.append({
                            "type": "XOR Encoding",
                            "details": "Possible decryption/encoding loop",
                            "confidence": "medium",
                            "offset": xor_seq[0].address - base_addr,
                            "context": instructions[i-1:i+2]
                        })
            else:
                if len(xor_seq) < 3:  # Only reset if not part of a larger sequence
                    xor_seq = []
                    
            # Detect PEB access
            if 'fs:0x30' in instr.op_str or 'fs:[0x30]' in instr.op_str:
                findings.append({
                    "type": "PEB Access",
                    "details": "Access to Process Environment Block (common shellcode technique)",
                    "confidence": "high",
                    "offset": instr.address - base_addr,
                    "context": instructions[i:i+5] if i+5 < len(instructions) else instructions[i:]
                })
                
            # Detect GetPC techniques (common in position-independent shellcode)
            if instr.mnemonic == 'call' and instructions[i+1].mnemonic == 'pop' and i+1 < len(instructions):
                findings.append({
                    "type": "GetPC Technique",
                    "details": "Self-referencing code (position independent shellcode)",
                    "confidence": "high", 
                    "offset": instr.address - base_addr,
                    "context": instructions[i:i+3] if i+3 < len(instructions) else instructions[i:]
                })
                
            # Detect egg hunters
            if (instr.mnemonic == 'cmp' and i+3 < len(instructions) and 
                instructions[i+1].mnemonic in ['jne', 'jnz'] and
                instructions[i+2].mnemonic == 'cmp'):
                findings.append({
                    "type": "Egg Hunter",
                    "details": "Memory scanning code pattern",
                    "confidence": "medium",
                    "offset": instr.address - base_addr,
                    "context": instructions[i:i+4]
                })
        
        return findings
    
    def add_detection(self, detection):
        """
        Adds a detection to the appropriate category based on its type
        """
        detection_type = detection.get('type', '').lower()
        
        # Map detection type to category
        category = 'shellcode_patterns'  # Default category
        
        if 'api' in detection_type and ('hash' in detection_type or 'call sequence' in detection_type):
            category = 'api_hashing'
        elif 'egg hunter' in detection_type:
            category = 'egg_hunters'
        elif 'injection' in detection_type:
            category = 'process_injection'
        elif 'xor' in detection_type:
            category = 'xor_encoding'
        elif 'stack string' in detection_type:
            category = 'stack_strings'
        elif 'peb access' in detection_type:
            category = 'peb_access'
        elif 'reflective' in detection_type or 'getpc' in detection_type:
            category = 'reflective_loading'
        elif 'rop' in detection_type:
            category = 'rop_chains'
        elif 'rwx' in detection_type.lower():
            category = 'rwx_memory'
        elif 'wx memory' in detection_type.lower():
            category = 'wx_memory'
        elif 'cfg bypass' in detection_type:
            category = 'cfg_bypass'
        elif 'hollowing' in detection_type:
            category = 'process_hollowing'
        elif 'memory protection' in detection_type:
            category = 'suspicious_memory'
        elif 'unsigned' in detection_type:
            category = 'unsigned_modules'
        elif 'registry' in detection_type:
            category = 'suspicious_registry'
        elif 'command line' in detection_type:
            category = 'suspicious_cmdline'
        elif 'yara rule' in detection_type:
            category = 'yara_matches'
        
        # Add detection to the appropriate category
        self.detections[category].append(detection)
        self.total_detections += 1
        
        # Log the detection
        logging.info(f"Added {detection_type} detection to ShellCodeTome: {detection.get('details', '')}")
        
        return category

    # Other existing methods remain the same

class CodeDisassembler:
    def __init__(self):
        self.use_capstone = False
        self.use_distorm = False
        self.cs = None
        self.cs_mode = None
        self.md = None
        
        # Try to initialize Capstone (preferred)
        try:
            import capstone
            self.cs = capstone
            self.cs_mode = {
                '32bit': capstone.CS_MODE_32,
                '64bit': capstone.CS_MODE_64
            }
            self.x86_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.x64_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.x86_md.detail = True
            self.x64_md.detail = True
            self.use_capstone = True
            logging.debug("Initialized Capstone disassembler")
        except ImportError:
            logging.debug("Capstone not available, trying distorm3")
            
            # Try to initialize distorm3 as fallback
            try:
                import distorm3
                self.distorm = distorm3
                self.use_distorm = True
                logging.debug("Initialized distorm3 disassembler")
            except ImportError:
                logging.debug("No disassembly engine available. Limited functionality.")
        
        # Common instruction patterns for analysis
        self.branch_instructions = {
            'x86': [b'\xff\x25', b'\xff\x15', b'\xe8', b'\xe9', b'\xeb', b'\xff\xe0'],  # jmp/call
            'x64': [b'\xff\x25', b'\xff\x15', b'\xe8', b'\xe9', b'\xeb', b'\xff\xe0']   # jmp/call
        }
        
        # Entry point patterns (function prologues, common shellcode starters)
        self.entry_point_patterns = [
            rb'\x55\x8b\xec',           # push ebp; mov ebp, esp (x86 prologue)
            rb'\x55\x48\x89\xe5',       # push rbp; mov rbp, rsp (x64 prologue) 
            rb'\x53\x56\x57',           # push ebx; push esi; push edi
            rb'\x48\x83\xec',           # sub rsp, XX
            rb'\x48\x89\x5c\x24',       # mov [rsp+XX], rbx (x64 prologue)
            rb'\x31\xc0',               # xor eax, eax (common shellcode start)
            rb'\x33\xc0',               # xor eax, eax (alternate)
            rb'\x48\x31\xc0',           # xor rax, rax (x64 version)
            rb'\xeb[\x00-\xff]\xe8',    # jmp short XX; call (common shellcode pattern)
            rb'\x90{5,}[\x00-\xff]{1,2}\x31' # NOP sled followed by code
        ]
    
    def disassemble(self, code_bytes, address=0, architecture='auto', max_instructions=100):
        """
        Disassemble binary code into human-readable assembly
        
        Args:
            code_bytes: The binary code to disassemble
            address: Base address for the code
            architecture: '32bit', '64bit', or 'auto'
            max_instructions: Maximum number of instructions to disassemble
            
        Returns:
            String containing disassembled code or error message
        """
        if not code_bytes:
            return "No code to disassemble"
            
        # Auto-detect architecture if not specified
        if architecture == 'auto':
            architecture = self._detect_architecture(code_bytes)
        
        # Use Capstone if available
        if self.use_capstone:
            return self._disassemble_with_capstone(code_bytes, address, architecture, max_instructions)
        
        # Use distorm3 if available
        elif self.use_distorm:
            return self._disassemble_with_distorm(code_bytes, address, architecture, max_instructions)
        
        # Fallback to simple hex dump with basic pattern matching
        else:
            return self._simple_disassemble(code_bytes, address, max_instructions)
    def disassemble_bytes(self, bytes_data, base_address=0):
        """
        Disassembles a byte array into readable assembly instructions.
        
        Args:
            bytes_data (bytes): The binary data to disassemble
            base_address (int): The starting address for the disassembly
            
        Returns:
            list: List of disassembled instructions
        """
        try:
            # Import capstone here to handle potential import issues gracefully
            import capstone
            
            # Initialize disassembler for x86-64 architecture
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            md.detail = True  # Enable detailed disassembly
            
            # Perform disassembly
            disassembled = []
            for instr in md.disasm(bytes_data, base_address):
                instruction = {
                    'address': f"0x{instr.address:x}",
                    'mnemonic': instr.mnemonic,
                    'op_str': instr.op_str,
                    'bytes': binascii.hexlify(instr.bytes).decode(),
                    'size': instr.size
                }
                disassembled.append(instruction)
            
            return disassembled
        except ImportError:
            logging.warning("Capstone disassembly engine not available")
            return [{"error": "Disassembly engine not available"}]
        except Exception as e:
            logging.error(f"Disassembly error: {str(e)}")
            return [{"error": f"Disassembly failed: {str(e)}"}]
    def _analyze_flow(self, disassembly, base_address=0, memory_data=None):
        """
        Analyze the control flow of disassembled code to identify suspicious patterns
        common in shellcode and malicious code.
        
        Args:
            disassembly (list): Disassembled instructions
            base_address (int): Base memory address of the code
            memory_data (bytes, optional): Original binary data for additional analysis
            
        Returns:
            dict: Analysis results including suspicious flows, API calls, gadgets
        """
        results = {
            'suspicious_flows': [],
            'api_calls': [],
            'rop_gadgets': [],
            'self_modifying_code': False,
            'indirect_calls': [],
            'stack_manipulation': [],
            'register_usage': {},
            'loop_constructs': [],
            'flow_graph': {},
            'flow_score': 0
        }
        
        if not disassembly or len(disassembly) < 5:
            return results
        
        # Track register values and memory accesses
        reg_states = {
            'eax': None, 'ebx': None, 'ecx': None, 'edx': None,
            'esi': None, 'edi': None, 'ebp': None, 'esp': None
        }
        
        # Track jump targets and function calls
        jump_targets = set()
        call_targets = set()
        
        # Track memory writes
        memory_writes = []
        
        # Maps for instruction addresses
        instr_addr_map = {}
        
        # Process each instruction for initial mapping
        for i, instr in enumerate(disassembly):
            # Extract address from disassembly format (expected: "0xADDR: INSTR")
            addr_part = instr.split(':', 1)[0].strip()
            try:
                addr = int(addr_part, 16) if addr_part.startswith('0x') else int(addr_part)
                instr_addr_map[addr] = i
            except (ValueError, IndexError):
                continue  # Skip if not in expected format
        
        # Analyze instruction sequence for flow patterns
        for i, instr in enumerate(disassembly):
            if i >= len(disassembly) - 1:
                break

            # Extract address and instruction parts
            try:
                parts = instr.split(':', 1)
                addr_str = parts[0].strip()
                instr_text = parts[1].strip() if len(parts) > 1 else ""
                
                current_addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
            except (ValueError, IndexError):
                continue

            # Check for CALL instructions
            if 'CALL' in instr_text:
                # Extract call target if it's direct
                target = self._extract_target_address(instr_text, current_addr)
                
                if target is not None:
                    call_targets.add(target)
                    
                    # Check if it's an API call to a known address
                    api_name = self._resolve_api_address(target)
                    if api_name:
                        results['api_calls'].append({
                            'address': current_addr,
                            'target': target,
                            'api': api_name
                        })
                        results['flow_score'] += 5
                else:
                    # Indirect call (e.g., CALL EAX)
                    results['indirect_calls'].append({
                        'address': current_addr,
                        'instruction': instr_text
                    })
                    results['flow_score'] += 10  # Indirect calls are more suspicious
            
            # Check for JMP instructions
            elif instr_text.startswith('JMP'):
                # Extract jump target
                target = self._extract_target_address(instr_text, current_addr)
                
                if target is not None:
                    jump_targets.add(target)
                    
                    # Check for backward jumps (loops)
                    if target < current_addr:
                        results['loop_constructs'].append({
                            'from': current_addr,
                            'to': target,
                            'distance': current_addr - target
                        })
                        results['flow_score'] += 3
                    
                    # Check for far jumps (could be suspicious)
                    jump_dist = abs(target - current_addr)
                    if jump_dist > 1024:
                        results['suspicious_flows'].append({
                            'type': 'far_jump',
                            'from': current_addr,
                            'to': target,
                            'distance': jump_dist
                        })
                        results['flow_score'] += 2
            
            # Check for conditional jumps
            elif any(jcc in instr_text for jcc in ['JE', 'JNE', 'JZ', 'JNZ', 'JG', 'JL', 'JA', 'JB']):
                target = self._extract_target_address(instr_text, current_addr)
                
                if target is not None:
                    jump_targets.add(target)
                    
                    # Add to flow graph
                    if current_addr not in results['flow_graph']:
                        results['flow_graph'][current_addr] = []
                    
                    results['flow_graph'][current_addr].append({
                        'target': target,
                        'type': 'conditional'
                    })
            
            # Check for stack manipulation
            elif 'ESP' in instr_text or 'EBP' in instr_text:
                if any(op in instr_text for op in ['ADD', 'SUB', 'LEA']):
                    results['stack_manipulation'].append({
                        'address': current_addr,
                        'instruction': instr_text
                    })
                    
                    # Large stack adjustments could indicate shellcode
                    if 'SUB ESP' in instr_text:
                        try:
                            # Try to extract immediate value
                            imm_value = int(instr_text.split(',')[1].strip(), 16)
                            if imm_value > 0x1000:  # Large stack allocation
                                results['suspicious_flows'].append({
                                    'type': 'large_stack_allocation',
                                    'address': current_addr,
                                    'size': imm_value
                                })
                                results['flow_score'] += 10
                        except (ValueError, IndexError):
                            pass
            
            # Check for push/pop sequences that could be ROP gadgets
            elif instr_text.startswith('POP') and i > 0 and disassembly[i-1].split(':', 1)[1].strip().startswith('PUSH'):
                results['rop_gadgets'].append({
                    'address': current_addr,
                    'instructions': [disassembly[i-1], instr]
                })
                results['flow_score'] += 1
            
            # Check for memory writes
            elif any(op in instr_text for op in ['MOV', 'STOSB', 'STOSD']):
                # Check for memory destinations (e.g., MOV [address], value)
                if '[' in instr_text and ']' in instr_text:
                    memory_writes.append({
                        'address': current_addr,
                        'instruction': instr_text
                    })
                    
                    # Check for potential self-modifying code
                    # Self-modifying code often writes to a memory address and then jumps to it
                    if i < len(disassembly) - 2:
                        next_instr = disassembly[i+1].split(':', 1)[1].strip()
                        if 'JMP' in next_instr or 'CALL' in next_instr:
                            results['self_modifying_code'] = True
                            results['suspicious_flows'].append({
                                'type': 'self_modifying_code',
                                'address': current_addr,
                                'sequence': [instr, disassembly[i+1]]
                            })
                            results['flow_score'] += 25  # Very suspicious
            
            # Track register usage and values
            for reg in reg_states.keys():
                reg_pattern = f"{reg},"
                if reg_pattern in instr_text:
                    if reg not in results['register_usage']:
                        results['register_usage'][reg] = 0
                    results['register_usage'][reg] += 1
                    
                    # Try to track immediate values assigned to registers
                    if instr_text.startswith(f'MOV {reg},'):
                        try:
                            value_part = instr_text.split(',')[1].strip()
                            if value_part.startswith('0x'):
                                reg_states[reg] = int(value_part, 16)
                        except (ValueError, IndexError):
                            pass
        
        # Analyze potential function prologue/epilogue patterns
        for i, instr in enumerate(disassembly):
            if i >= len(disassembly) - 3:
                break
                
            instr_text = instr.split(':', 1)[1].strip() if ':' in instr else instr
            
            # Check for function prologue (PUSH EBP; MOV EBP, ESP)
            if instr_text == 'PUSH EBP':
                next_instr = disassembly[i+1].split(':', 1)[1].strip() if ':' in disassembly[i+1] else disassembly[i+1]
                if next_instr == 'MOV EBP, ESP':
                    addr_str = instr.split(':', 1)[0].strip()
                    try:
                        func_addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
                        results['flow_graph'][func_addr] = {'type': 'function_entry'}
                    except (ValueError, IndexError):
                        pass
        
        # Identify chains of jumps that could indicate obfuscation
        jump_chain = []
        for addr in sorted(jump_targets):
            if addr in instr_addr_map:
                i = instr_addr_map[addr]
                if i < len(disassembly):
                    instr = disassembly[i]
                    if 'JMP' in instr:
                        jump_chain.append(addr)
        
        if len(jump_chain) > 3:
            results['suspicious_flows'].append({
                'type': 'jump_chain',
                'addresses': jump_chain
            })
            results['flow_score'] += 15  # Jump chains are often used in obfuscation
        
        # Analyze the structure for API resolution patterns
        if memory_data and len(memory_data) > 20:
            # Check for GetProcAddress pattern
            if results['register_usage'].get('eax', 0) > 5 and results['indirect_calls']:
                # Common API resolution pattern using GetProcAddress
                getproc_pattern = False
                for i, instr in enumerate(disassembly):
                    if 'PUSH' in instr and i < len(disassembly) - 3:
                        next_instr = disassembly[i+1]
                        next_next_instr = disassembly[i+2]
                        if 'PUSH' in next_instr and 'CALL' in next_next_instr:
                            getproc_pattern = True
                            break
                
                if getproc_pattern:
                    results['suspicious_flows'].append({
                        'type': 'api_resolution',
                        'method': 'GetProcAddress'
                    })
                    results['flow_score'] += 20  # API resolution is common in shellcode
        
        # Check for PEB access pattern (common in shellcode)
        peb_access = False
        for i, instr in enumerate(disassembly):
            if 'FS:[' in instr and '0x30' in instr:  # PEB access at FS:[0x30]
                peb_access = True
                addr_str = instr.split(':', 1)[0].strip()
                try:
                    peb_addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
                    results['suspicious_flows'].append({
                        'type': 'peb_access',
                        'address': peb_addr
                    })
                    results['flow_score'] += 20  # PEB access is common in shellcode
                except (ValueError, IndexError):
                    pass
        
        # Final score adjustments
        if results['self_modifying_code']:
            results['flow_score'] += 30
        
        if peb_access and results['indirect_calls']:
            results['flow_score'] += 25  # PEB access + indirect calls is highly suspicious
        
        if len(results['stack_manipulation']) > 5:
            results['flow_score'] += 15  # Extensive stack manipulation
        
        # Calculate shellcode likelihood
        results['is_shellcode_flow'] = results['flow_score'] >= 40
        results['flow_confidence'] = min(100, results['flow_score'])
        
        return results

    def _extract_target_address(self, instruction_text, current_address):
        """Extract target address from a jump or call instruction"""
        try:
            parts = instruction_text.split()
            if len(parts) < 2:
                return None
            
            target_str = parts[1].strip()
            
            # Handle direct addresses
            if target_str.startswith('0x'):
                return int(target_str, 16)
            
            # Handle relative offsets
            if '+' in target_str:
                offset_parts = target_str.split('+')
                if len(offset_parts) == 2 and offset_parts[1].startswith('0x'):
                    offset = int(offset_parts[1], 16)
                    return current_address + offset
            
            return None
        except (ValueError, IndexError):
            return None

    def _resolve_api_address(self, address):
        """
        Attempt to resolve an address to a known API name
        This is a placeholder - implement with your actual API resolution logic
        """
        # This would normally use a loaded module database
        # For this example, we'll return None for all addresses
        # In a real implementation, you would check if the address falls within
        # a known DLL's address range and resolve the export name
        
        # Mock implementation for demonstration
        common_api_addresses = {
            0x77e12345: 'kernel32.CreateProcessA',
            0x77e23456: 'kernel32.VirtualAlloc',
            0x77e34567: 'kernel32.GetProcAddress',
            0x77e45678: 'kernel32.LoadLibraryA',
            0x77e56789: 'ntdll.NtAllocateVirtualMemory',
            0x77e67890: 'ntdll.ZwProtectVirtualMemory'
        }
        
        return common_api_addresses.get(address)
    def calculate_entropy(self, data):
        """
        Calculate Shannon entropy of binary data
        
        Args:
            data (bytes): Binary data
            
        Returns:
            float: Entropy value (0.0 to 8.0)
        """
        if not data:
            return 0.0
        
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        
        return entropy

    def detect_api_references(self, data):
        """
        Detect potential API call references in the binary data
        
        Args:
            data (bytes): Binary data to analyze
            
        Returns:
            bool: True if API references are detected
        """
        # Common API call patterns (simplified check)
        api_patterns = [
            b'LoadLibrary', b'GetProc', b'VirtualAlloc', b'CreateThread',
            b'WriteProcess', b'ReadProcess', b'CreateFile', b'WinExec',
            b'ShellExecute', b'socket', b'connect', b'recv', b'send'
        ]
        
        for pattern in api_patterns:
            if pattern in data:
                return True
        
        # Also check for common API call instruction patterns in x86/x64
        # E8 is CALL in x86/x64
        call_offsets = [i for i in range(len(data)-5) if data[i] == 0xE8]
        if len(call_offsets) > 2:  # Multiple CALL instructions may indicate API usage
            return True
        
        return False

    def create_binary_signature(self, data):
        """
        Create a fuzzy signature of the binary data for pattern matching
        
        Args:
            data (bytes): Binary data
            
        Returns:
            str: A signature string that represents the binary pattern
        """
        try:
            import ssdeep
            return ssdeep.hash(data)
        except ImportError:
            # Fallback if ssdeep not available
            return hashlib.md5(data).hexdigest()

    def schedule_pattern_learning(self, detection_id, data_sample):
        """
        Schedule a background task to learn from this shellcode pattern
        
        Args:
            detection_id (str): Unique ID for this detection
            data_sample (bytes): Sample of the detected shellcode
        """
        try:
            if not hasattr(self, 'pattern_learning_queue'):
                self.pattern_learning_queue = queue.Queue()
            
            self.pattern_learning_queue.put({
                'detection_id': detection_id,
                'data_sample': data_sample,
                'timestamp': time.time()
            })
            
            # Start the learning thread if not already running
            if not hasattr(self, 'learning_thread_running') or not self.learning_thread_running:
                self.learning_thread_running = True
                threading.Thread(target=self.process_pattern_learning_queue, daemon=True).start()
        except Exception as e:
            logging.debug(f"Error scheduling pattern learning: {str(e)}")

    def process_pattern_learning_queue(self):
        """
        Background thread to process shellcode patterns for learning
        """
        try:
            while self.learning_thread_running:
                try:
                    # Get item from queue with timeout to allow thread to exit
                    item = self.pattern_learning_queue.get(timeout=1.0)
                    
                    # Process the pattern
                    self.tome = ShellCodeTome()
                    if hasattr(self, 'tome') and self.tome:
                        # Extract features from the sample
                        features = self.extract_shellcode_features(item['data_sample'])
                        
                        # Update the Tome entry with learned features
                        self.tome.update_entry(
                            'shellcode_patterns', 
                            {'detection_id': item['detection_id']},
                            {'features': features, 'last_analyzed': time.time()}
                        )
                    
                    # Mark task as done
                    self.pattern_learning_queue.task_done()
                except queue.Empty:
                    # Queue is empty, just continue
                    continue
                except Exception as e:
                    logging.error(f"Error in pattern learning: {str(e)}")
                    # Mark task as done even if it failed
                    try:
                        self.pattern_learning_queue.task_done()
                    except:
                        pass
        except Exception as e:
            logging.error(f"Pattern learning thread error: {str(e)}")
        finally:
            self.learning_thread_running = False

    def extract_shellcode_features(self, data_sample):
        """
        Extract features from shellcode for machine learning purposes
        
        Args:
            data_sample (bytes): Binary data to analyze
            
        Returns:
            dict: Features extracted from the shellcode
        """
        features = {}
        
        try:
            # Basic statistical features
            features['size'] = len(data_sample)
            features['entropy'] = self.calculate_entropy(data_sample)
            
            # Byte frequency distribution
            byte_freq = {}
            for i in range(256):
                byte_freq[i] = data_sample.count(i)
            features['byte_frequency'] = byte_freq
            
            # Instruction statistics
            disasm = self.disassemble_bytes(data_sample)
            if isinstance(disasm, list) and len(disasm) > 0 and not disasm[0].get('error'):
                # Count instruction types
                instr_types = {}
                for instr in disasm:
                    mnemonic = instr.get('mnemonic', '')
                    instr_types[mnemonic] = instr_types.get(mnemonic, 0) + 1
                
                features['instruction_count'] = len(disasm)
                features['instruction_types'] = instr_types
                
                # Count likely API calls
                call_count = sum(1 for instr in disasm if instr.get('mnemonic') == 'call')
                features['call_count'] = call_count
                
                # Detect JMP/CALL patterns that might indicate obfuscation
                jmp_count = sum(1 for instr in disasm if instr.get('mnemonic') in ('jmp', 'je', 'jne', 'jz', 'jnz'))
                features['jump_count'] = jmp_count
            
            # Calculate potentially obfuscated strings
            features['potential_strings'] = self.detect_obfuscated_strings(data_sample)
        except Exception as e:
            logging.debug(f"Error extracting shellcode features: {str(e)}")
        
        return features

    def detect_obfuscated_strings(self, data):
        """
        Detect potentially obfuscated strings in the binary data
        
        Args:
            data (bytes): Binary data to analyze
            
        Returns:
            list: List of potential string patterns
        """
        results = []
        
        # Check for ASCII strings (at least 4 chars)
        current_string = ""
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII range
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:
                    results.append(current_string)
                current_string = ""
        
        # Add last string if it exists
        if len(current_string) >= 4:
            results.append(current_string)
        
        # Check for potential obfuscated/encoded strings
        # Look for repeating patterns that might be encoded data
        # This is a simplified approach - real implementation would use more advanced heuristics
        potential_patterns = []
        for i in range(len(data) - 8):
            pattern = data[i:i+8]
            # Check if this 8-byte pattern repeats with variations (possible encoding)
            count = 0
            for j in range(i+8, len(data) - 8, 8):
                comparison = data[j:j+8]
                diff_bytes = sum(1 for b1, b2 in zip(pattern, comparison) if b1 != b2)
                if diff_bytes <= 2:
                    count += 1
            if count >= 2:  # Found a repeating pattern with variations
                potential_patterns.append(pattern)
        
        return potential_patterns
    def _detect_architecture(self, code_bytes):   
        if not code_bytes or len(code_bytes) < 4:
            return '32bit'  # Default to 32-bit

        # Look for indicators of 64-bit code (REX prefixes, typical x64 instructions)
        rex_prefixes = [b'\x48', b'\x49', b'\x4A', b'\x4B', b'\x4C', b'\x4D', b'\x4E', b'\x4F']
        for prefix in rex_prefixes:
            if prefix in code_bytes[:20]:  # Check first 20 bytes for REX prefixes
                return '64bit'
                
        # Check for typical x64 function prologues
        x64_prologues = [b'\x55\x48\x89\xe5', b'\x48\x83\xec', b'\x48\x89\x5c\x24']
        for prologue in x64_prologues:
            if code_bytes.startswith(prologue):
                return '64bit'
                
        # Default to 32-bit
        return '32bit'
   
    def _disassemble_with_capstone(self, code_bytes, address, architecture, max_instructions):
        """Use Capstone engine for disassembly"""
        try:
            # Select the appropriate disassembler
            md = self.x64_md if architecture == '64bit' else self.x86_md
            
            # Disassemble the code
            result = []
            for i, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(code_bytes, address)):
                if i >= max_instructions:
                    result.append("... (truncated)")
                    break
                
                # Format the instruction
                instruction = f"0x{address:08x}: {mnemonic} {op_str}"
                result.append(instruction)
                
                # Include hex bytes (up to 10 bytes per instruction)
                hex_bytes = ' '.join(f'{b:02x}' for b in code_bytes[i:i+min(size, 10)])
                if len(hex_bytes) > 0:
                    result.append(f"  [{hex_bytes}]")
            
            if not result:
                return "No valid instructions found"
                
            return '\n'.join(result)
            
        except Exception as e:
            return f"Disassembly error: {str(e)}"
    
    def _disassemble_with_distorm(self, code_bytes, address, architecture, max_instructions):
        """Use distorm3 engine for disassembly"""
        try:
            # Select the appropriate mode
            mode = self.distorm.Decode64Bits if architecture == '64bit' else self.distorm.Decode32Bits
            
            # Disassemble the code
            instructions = self.distorm.Decode(address, code_bytes, mode)
            
            result = []
            
            for i, (offset, size, instruction, hexdump) in enumerate(instructions):
                if i >= max_instructions or size in self.branch_instructions.get(architecture, []):
                    result.append("... (truncated)")
                    break
                    
                # Format the instruction
                instr_line = f"0x{offset:08x}: {instruction}"
                result.append(instr_line)
                
                # Include hex bytes
                result.append(f"  [{hexdump}]")
            
            if not result:
                return "No valid instructions found"
                
            return '\n'.join(result)
            
        except Exception as e:
            return f"Disassembly error: {str(e)}"
    
    def _simple_disassemble(self, code_bytes, address, max_instructions):
        """
        Simple disassembly fallback when no engine is available
        Just shows hex dump with basic pattern recognition
        """
        result = ["Warning: No disassembly engine available. Showing hex dump with basic patterns."]
        
        offset = 0
        seen_instructions = 0
        
        while offset < len(code_bytes) and seen_instructions < max_instructions:
            # Get current address
            current_addr = address + offset
            
            # Get a slice of the remaining bytes (up to 16 bytes)
            remaining = min(16, len(code_bytes) - offset)
            byte_slice = code_bytes[offset:offset+remaining]
            
            # Format hex representation
            hex_str = ' '.join(f'{b:02x}' for b in byte_slice)
            
            # Try to identify common instructions
            instruction = self._identify_simple_instruction(byte_slice)
            
            if instruction:
                result.append(f"0x{current_addr:08x}: {hex_str:<47} ; {instruction}")
                # Move forward by the identified instruction length
                offset += instruction[1]
                seen_instructions += 1
            else:
                # If we can't identify, just show the hex and move forward 1 byte
                result.append(f"0x{current_addr:08x}: {hex_str}")
                offset += 1
        
        return '\n'.join(result)
    
    def _identify_simple_instruction(self, byte_slice):
        """Identify some common x86/x64 instructions without a disassembler"""
        if not byte_slice:
            return None
            
        # Some common instruction patterns with their lengths
        patterns = [
            (b'\x90', 1, "NOP"),
            (b'\xc3', 1, "RET"),
            (b'\x55', 1, "PUSH EBP"),
            (b'\x5d', 1, "POP EBP"),
            (b'\x50', 1, "PUSH EAX"),
            (b'\x51', 1, "PUSH ECX"),
            (b'\x52', 1, "PUSH EDX"),
            (b'\x53', 1, "PUSH EBX"),
            (b'\x56', 1, "PUSH ESI"),
            (b'\x57', 1, "PUSH EDI"),
            (b'\x58', 1, "POP EAX"),
            (b'\x59', 1, "POP ECX"),
            (b'\x5a', 1, "POP EDX"),
            (b'\x5b', 1, "POP EBX"),
            (b'\x5e', 1, "POP ESI"),
            (b'\x5f', 1, "POP EDI"),
            (b'\x31\xc0', 2, "XOR EAX, EAX"),
            (b'\x31\xd2', 2, "XOR EDX, EDX"),
            (b'\x31\xc9', 2, "XOR ECX, ECX"),
            (b'\x31\xdb', 2, "XOR EBX, EBX"),
            (b'\x33\xc0', 2, "XOR EAX, EAX"),
            (b'\x48\x31\xc0', 3, "XOR RAX, RAX"),
            (b'\x48\x89\xe5', 3, "MOV RBP, RSP"),
            (b'\xff\xd0', 2, "CALL EAX"),
            (b'\xff\xd1', 2, "CALL ECX"),
            (b'\xff\xd2', 2, "CALL EDX"),
            (b'\xff\xd3', 2, "CALL EBX"),
            (b'\xff\xe0', 2, "JMP EAX"),
            (b'\xff\xe1', 2, "JMP ECX"),
            (b'\xff\xe2', 2, "JMP EDX"),
            (b'\xff\xe3', 2, "JMP EBX"),
        ]
        
        # Specific handling for call/jmp with offset
        if byte_slice and byte_slice[0] == 0xe8 and len(byte_slice) >= 5:
            offset = int.from_bytes(byte_slice[1:5], byteorder='little', signed=True)
            return (f"CALL {offset:+#x}", 5)
        
        if byte_slice and byte_slice[0] == 0xe9 and len(byte_slice) >= 5:
            offset = int.from_bytes(byte_slice[1:5], byteorder='little', signed=True)
            return (f"JMP {offset:+#x}", 5)
            
        if byte_slice and byte_slice[0] == 0xeb and len(byte_slice) >= 2:
            offset = int.from_bytes(byte_slice[1:2], byteorder='little', signed=True)
            return (f"JMP SHORT {offset:+#x}", 2)
            
        # Check for standard patterns
        for pattern, length, name in patterns:
            if byte_slice.startswith(pattern) and len(byte_slice) >= length:
                return (name, length)
        
        return None
    def find_entry_points(self, code_bytes, base_address=0):
        """
        Find potential code entry points in a memory region
        
        Args:
            code_bytes: The binary code to analyze
            base_address: Base address for the code
            
        Returns:
            List of tuples (entry_address, estimated_size) of potential code entry points
        """
        if not code_bytes or len(code_bytes) < 4:
            return []

        entry_points = []
        
        # Scan for function prologues and shellcode entry patterns
        for pattern in self.entry_point_patterns:
            for match in re.finditer(pattern, code_bytes):
                offset = match.start()
                entry_addr = base_address + offset
                
                # Estimate code size by looking for return instructions or next prologue
                estimated_size = self._estimate_code_size(code_bytes, offset)
                
                entry_points.append((entry_addr, estimated_size))
        
        # If using Capstone or distorm, try to identify more entry points by analyzing code flow
        if self.use_capstone or self.use_distorm:
            flow_entries = self._find_entries_by_flow_analysis(code_bytes, base_address)
            for entry_addr, size in flow_entries:
                if (entry_addr, size) not in entry_points:
                    entry_points.append((entry_addr, size))
        
        return entry_points
    
    def _estimate_code_size(self, code_bytes, start_offset, max_size=1024):
        """
        Estimate the size of a code section starting at offset
        Looks for return instructions (ret, retn) or next function prologue
        """
        if start_offset >= len(code_bytes):
            return 0
            
        # Common return instructions
        ret_instructions = [b'\xc3', b'\xc2', b'\xcb', b'\xca']
        
        # Look for return instructions
        for i in range(start_offset + 1, min(len(code_bytes), start_offset + max_size)):
            # Check for return instructions
            if any(code_bytes[i:i+len(ret)] == ret for ret in ret_instructions):
                return i - start_offset + 1
                
            # Check for next function prologue
            for pattern in [rb'\x55\x8b\xec', rb'\x55\x48\x89\xe5']:
                if i + len(pattern) <= len(code_bytes) and code_bytes[i:i+len(pattern)] == pattern:
                    return i - start_offset
        
        # Couldn't find end, return a reasonable size
        return min(512, len(code_bytes) - start_offset)
    
    def _find_entries_by_flow_analysis(self, code_bytes, base_address):
        """
        Find entry points by analyzing code flow (call/jmp targets)
        More effective with Capstone or distorm available
        """
        entry_points = []
        
        # If Capstone is available
        if self.use_capstone:
            try:
                # Detect architecture
                arch = self._detect_architecture(code_bytes)
                md = self.x64_md if arch == '64bit' else self.x86_md
                
                for insn in md.disasm(code_bytes, base_address):
                    # Look for call/jmp instructions
                    if insn.mnemonic in ('call', 'jmp'):
                        # Check if operand is a direct address within our region
                        for op in insn.operands:
                            if op.type == self.cs.CS_OP_IMM:
                                target = op.imm
                                if target >= base_address and target < base_address + len(code_bytes):
                                    # Found a potential entry point
                                    offset = target - base_address
                                    size = self._estimate_code_size(code_bytes, offset)
                                    entry_points.append((target, size))
            except Exception as e:
                logging.debug(f"Error in flow analysis with Capstone: {str(e)}")
        
        # If distorm is available
        elif self.use_distorm:
            try:
                mode = self.distorm.Decode64Bits if self._detect_architecture(code_bytes) == '64bit' else self.distorm.Decode32Bits
                instructions = self.distorm.Decode(base_address, code_bytes, mode)
                
                for (addr, size, instr_text, hexbytes) in instructions:
                    if 'CALL' in instr_text or 'JMP' in instr_text:
                        # Parse the instruction to get target
                        # This is simplified and may need improvement
                        match = re.search(r'(CALL|JMP)\s+0x([0-9A-Fa-f]+)', instr_text)
                        if match:
                            target = int(match.group(2), 16)
                            if target >= base_address and target < base_address + len(code_bytes):
                                offset = target - base_address
                                size = self._estimate_code_size(code_bytes, offset)
                                entry_points.append((target, size))
            except Exception as e:
                logging.debug(f"Error in flow analysis with distorm: {str(e)}")
        
        # Without Capstone or distorm, use simple pattern matching
        else:
            # Look for call/jmp instructions with direct offsets
            i = 0
            while i < len(code_bytes) - 5:
                # Check for E8/E9 (CALL/JMP) with 32-bit offset
                if code_bytes[i] in (0xE8, 0xE9):
                    offset = int.from_bytes(code_bytes[i+1:i+5], byteorder='little', signed=True)
                    target = base_address + i + 5 + offset  # Current position + instruction size + offset
                    
                    # Check if target is within our buffer
                    if target >= base_address and target < base_address + len(code_bytes):
                        # Found a potential entry point
                        buffer_offset = target - base_address
                        size = self._estimate_code_size(code_bytes, buffer_offset)
                        entry_points.append((target, size))
                
                i += 1
                
        return entry_points
    
    def analyze_suspicious_code(self, code_bytes, base_address=0):
        """
        Perform detailed analysis of suspicious code
        
        Args:
            code_bytes: The binary code to analyze
            base_address: Base address for the code
            
        Returns:
            Dictionary with analysis results
        """
        result = {
            'disassembly': self.disassemble(code_bytes, base_address),
            'entry_points': self.find_entry_points(code_bytes, base_address),
            'api_calls': self._identify_api_calls(code_bytes, base_address),
            'techniques': self._identify_techniques(code_bytes),
            'strings': self._extract_strings(code_bytes),
            'architecture': self._detect_architecture(code_bytes)
        }
        
        return result
    
    def _identify_api_calls(self, code_bytes, base_address):
        """Identify potential API calls in the code"""
        api_calls = []
        
        # Common API calling patterns
        api_patterns = [
            # LoadLibrary/GetProcAddress pattern
            (rb'\x68(.{4})\xff\x15(.{4})', "LoadLibrary"),
            (rb'\x68(.{4})\x50\xff\x15(.{4})', "GetProcAddress"),
            # WinExec/CreateProcess pattern
            (rb'\x6a\x00\x68(.{4})\xff\x15(.{4})', "WinExec/CreateProcess"),
            # Socket API patterns
            (rb'\x6a\x06\x6a\x01\x6a\x02\xff\x15', "socket"),
            (rb'\x68(.{4})\x68(.{4})\xff\x15', "connect"),
            # Memory allocation patterns
            (rb'\x6a\x40\x68(.{4})\x6a\x00\xff\x15', "VirtualAlloc"),
            (rb'\x68(.{4})\x6a\x00\xff\x15', "HeapAlloc")
        ]
        
        for pattern, api_name in api_patterns:
            for match in re.finditer(pattern, code_bytes):
                api_calls.append({
                    'offset': base_address + match.start(),
                    'name': api_name,
                    'pattern': binascii.hexlify(match.group(0)).decode('utf-8')
                })
        
        return api_calls
    
    def _identify_techniques(self, code_bytes):
        """Identify shellcode techniques used"""
        techniques = []
        
        # Technique patterns
        technique_patterns = [
            (rb'\x90{5,}', "NOP sled"),
            (rb'\xeb.\xe8', "JMP/CALL/POP decoder"),
            (rb'\x31\xc9.*\xfe\xc1.*\x80', "XOR decoder loop"),
            (rb'\xac.*\xaa.*\xe2', "MOVSx decoder loop"),
            (rb'\x54\x68\x73\x20\x70\x72\x6f\x67\x72\x61\x6d', "This program cannot be run in DOS mode"),
            (rb'\x64\xa1\x30\x00\x00\x00', "PEB access"),
            (rb'\x64\x8b\x1d\x30\x00\x00\x00', "PEB access (alt)"),
            (rb'\x48\x65\x61\x70', "Heap strings"),
            (rb'\x56\x69\x72\x74\x75\x61\x6c', "Virtual strings"),
            (rb'\x6b\x65\x72\x6e\x65\x6c\x33\x32', "kernel32"),
            (rb'\x6e\x74\x64\x6c\x6c', "ntdll")
        ]
        
        for pattern, name in technique_patterns:
            if re.search(pattern, code_bytes):
                techniques.append(name)
                
        # Check for specific techniques
        # Stack strings
        if self._has_stack_strings(code_bytes):
            techniques.append("Stack strings")
            
        # Position-independent code indicators
        if self._has_pic_indicators(code_bytes):
            techniques.append("Position-independent code")
            
        # API hashing
        if self._has_api_hashing(code_bytes):
            techniques.append("API hashing")
            
        return techniques
    
    def _has_stack_strings(self, code_bytes):
        """Check for stack string building pattern (push sequence of characters)"""
        # Look for sequences of push instructions with ASCII values
        push_sequence = 0
        for i in range(len(code_bytes) - 5):
            if code_bytes[i] == 0x68:  # PUSH imm32
                dword = int.from_bytes(code_bytes[i+1:i+5], byteorder='little')
                # Check if value is printable ASCII
                if all(0x20 <= ((dword >> (8*j)) & 0xFF) <= 0x7E for j in range(4)):
                    push_sequence += 1
                    if push_sequence >= 2:  # At least 2 consecutive string pushes
                        return True
            else:
                push_sequence = 0
                
        return False
    
    def _has_pic_indicators(self, code_bytes):
        """Check for position-independent code indicators"""
        # Common PIC patterns: call-pop sequence
        for i in range(len(code_bytes) - 6):
            if code_bytes[i] == 0xE8 and code_bytes[i+5] == 0x59:  # CALL + POP ECX
                return True
                
        # GetPC patterns
        getpc_patterns = [
            b'\xe8\x00\x00\x00\x00\x58',  # call $+5; pop eax
            b'\xe8\x00\x00\x00\x00\x59',  # call $+5; pop ecx
            b'\xd9\xee\xd9\x74\x24\xf4',  # fldz; fstenv [esp-0xc]
            b'\xeb\x03\x5e\xeb\x05'       # jmp short; pop esi; jmp short
        ]
        
        for pattern in getpc_patterns:
            if pattern in code_bytes:
                return True
                
        return False
    
    def _has_api_hashing(self, code_bytes):
        """Check for API hashing techniques"""
        # Patterns typical in API hashing routines
        hash_patterns = [
            rb'\x33\xc0[\x00-\xff]{0,6}\xac[\x00-\xff]{0,6}\xc1[\x00-\xff]{0,6}\x03',  # xor eax,eax + lodsb + rol + add
            rb'\x31\xc0[\x00-\xff]{0,6}\xac[\x00-\xff]{0,6}\xc1[\x00-\xff]{0,6}\x03',  # xor eax,eax + lodsb + rol + add
            rb'\xb9[\x00-\xff]{4}[\x00-\xff]{0,4}\x31\xc0[\x00-\xff]{0,6}\xac[\x00-\xff]{0,6}\x01\xc2',  # mov ecx + xor eax + lodsb + add edx
            rb'\x66[\x00-\xff]{0,2}\x8b[\x00-\xff]{1,4}\x31\xd2[\x00-\xff]{0,6}\x66[\x00-\xff]{1,6}\xc1'  # mov reg + xor edx + rol
        ]
        
        for pattern in hash_patterns:
            if re.search(pattern, code_bytes):
                return True
                
        # Look for repeated rotate/shift/add/xor sequences (common in hash loops)
        rotate_opcodes = [0xc0, 0xc1, 0xd2, 0xd3]  # ROR/ROL/SHR/SHL opcodes
        hash_loop_count = 0
        
        for i in range(len(code_bytes) - 10):
            # Check for rotate/shift instruction
            if code_bytes[i] in rotate_opcodes:
                # Look for arithmetic op within next few bytes
                for j in range(i+1, min(i+8, len(code_bytes))):
                    if code_bytes[j] in [0x01, 0x03, 0x33]:  # ADD/XOR opcodes
                        hash_loop_count += 1
                        if hash_loop_count >= 2:
                            return True
        
        return False
    
    def _extract_strings(self, code_bytes, min_length=4):
        """Extract ASCII and Unicode strings from code"""
        strings = []
        
        # ASCII strings
        ascii_regex = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        for match in re.finditer(ascii_regex, code_bytes):
            strings.append({
                'type': 'ascii',
                'value': match.group(0).decode('ascii'),
                'offset': match.start()
            })
            
        # Unicode strings (UTF-16LE)
        i = 0
        while i < len(code_bytes) - (min_length * 2):
            # Check for Unicode sequence (ASCII char + null byte repeating)
            if all(0x20 <= code_bytes[i+j*2] <= 0x7E and code_bytes[i+j*2+1] == 0 for j in range(min_length)):
                # Found a potential Unicode string
                end = i
                while end < len(code_bytes) - 1 and 0x20 <= code_bytes[end] <= 0x7E and code_bytes[end+1] == 0:
                    end += 2
                    
                # Extract the string
                unicode_bytes = code_bytes[i:end]
                try:
                    string_value = unicode_bytes.decode('utf-16le')
                    strings.append({
                        'type': 'unicode',
                        'value': string_value,
                        'offset': i
                    })
                except UnicodeDecodeError:
                    pass
                    
                i = end
            else:
                i += 1
                
        return strings
    def update_entry(self, entry_id, new_data):
        """
        Update an existing shellcode entry in the database with comprehensive data handling
        
        Args:
            entry_id: ID of the shellcode entry to update
            new_data: Dictionary containing the updated data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # First check if the entry exists
            cursor.execute('SELECT id FROM shellcode_entries WHERE id = ?', (entry_id,))
            if not cursor.fetchone():
                logging.warning(f"Entry {entry_id} not found for update")
                conn.close()
                return False
            
            # Prepare update data with defaults for missing fields
            update_data = {
                'first_seen': new_data.get('first_seen', datetime.now()),
                'last_seen': new_data.get('last_seen', datetime.now()),
                'seen_count': new_data.get('seen_count', 1),
                'size': new_data.get('size', 0),
                'hash': new_data.get('hash', ''),
                'hex_preview': new_data.get('hex_preview', ''),
                'classification': new_data.get('classification', 'unknown_shellcode'),
                'threat_level': new_data.get('threat_level', 'medium')
            }
            
            # Handle datetime objects
            for field in ['first_seen', 'last_seen']:
                if isinstance(update_data[field], str):
                    try:
                        update_data[field] = datetime.fromisoformat(update_data[field])
                    except ValueError:
                        update_data[field] = datetime.now()
            
            # Update shellcode_entries table
            cursor.execute('''
            UPDATE shellcode_entries
            SET first_seen = ?, last_seen = ?, seen_count = ?, size = ?, 
                hash = ?, hex_preview = ?, classification = ?, threat_level = ?
            WHERE id = ?
            ''', (
                update_data['first_seen'],
                update_data['last_seen'], 
                update_data['seen_count'],
                update_data['size'],
                update_data['hash'],
                update_data['hex_preview'],
                update_data['classification'],
                update_data['threat_level'],
                entry_id
            ))
            
            # Update shellcode_data table if raw data or disassembly provided
            if 'data' in new_data or 'disassembly' in new_data:
                # Check if data entry exists
                cursor.execute('SELECT id FROM shellcode_data WHERE id = ?', (entry_id,))
                data_exists = cursor.fetchone()
                
                if data_exists:
                    # Update existing data entry
                    update_fields = []
                    params = []
                    
                    if 'data' in new_data:
                        update_fields.append('raw_data = ?')
                        params.append(new_data['data'])
                        
                    if 'disassembly' in new_data:
                        update_fields.append('disassembly = ?')
                        params.append(new_data['disassembly'])
                    
                    if update_fields:
                        params.append(entry_id)
                        cursor.execute(f'''
                        UPDATE shellcode_data 
                        SET {', '.join(update_fields)}
                        WHERE id = ?
                        ''', params)
                else:
                    # Create new data entry
                    cursor.execute('''
                    INSERT INTO shellcode_data (id, raw_data, disassembly)
                    VALUES (?, ?, ?)
                    ''', (
                        entry_id,
                        new_data.get('data', b''),
                        new_data.get('disassembly', '')
                    ))
            
            # Update locations if provided
            if 'locations' in new_data:
                # Remove old locations for this shellcode
                cursor.execute('DELETE FROM shellcode_locations WHERE shellcode_id = ?', (entry_id,))
                
                # Add new locations
                for location in new_data['locations']:
                    cursor.execute('''
                    INSERT INTO shellcode_locations 
                    (shellcode_id, process_id, region_name, address, timestamp, detection_method)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        entry_id,
                        location.get('process_id'),
                        location.get('region_name', 'unknown'),
                        str(location.get('address', 0)),
                        location.get('timestamp', datetime.now()),
                        location.get('detection_method', 'unknown')
                    ))
            
            # Update analysis results if provided
            if 'analysis_results' in new_data:
                for analysis in new_data['analysis_results']:
                    cursor.execute('''
                    INSERT INTO analysis_results 
                    (shellcode_id, analysis_type, analysis_result, timestamp)
                    VALUES (?, ?, ?, ?)
                    ''', (
                        entry_id,
                        analysis.get('type', 'unknown'),
                        json.dumps(analysis.get('result', {})) if not isinstance(analysis.get('result'), str) else analysis.get('result'),
                        analysis.get('timestamp', datetime.now())
                    ))
            
            conn.commit()
            conn.close()
            
            logging.info(f"Successfully updated entry {entry_id}")
            return True
            
        except Exception as e:
            logging.error(f"Error updating entry {entry_id}: {str(e)}")
            if 'conn' in locals():
                conn.close()
            return False

    # Add this method to the ShellCodeTome class
    def update_entry(self, category, search_criteria, new_data):
        """
        Update entries in the ShellCodeTome detection categories
        
        Args:
            category: Detection category to update
            search_criteria: Dictionary of criteria to find entries to update
            new_data: Dictionary of new data to merge with existing entries
            
        Returns:
            Number of entries updated
        """
        updated_count = 0
        
        if category not in self.detections:
            logging.warning(f"Category {category} not found in detections")
            return updated_count
        
        try:
            for i, entry in enumerate(self.detections[category]):
                # Check if entry matches search criteria
                matches = True
                for key, value in search_criteria.items():
                    if key not in entry or entry[key] != value:
                        matches = False
                        break
                
                if matches:
                    # Update the entry with new data
                    self.detections[category][i].update(new_data)
                    updated_count += 1
                    
                    logging.debug(f"Updated entry in {category}: {search_criteria}")
            
            return updated_count
            
        except Exception as e:
            logging.error(f"Error updating tome entry in {category}: {str(e)}")
            return updated_count

    # Add this method to the ShellcodeDetector class  
    def update_tome_entry(self, shellcode_id, new_data):
        """
        Update an entry in the shellcode tome
        
        Args:
            shellcode_id: ID of the shellcode to update
            new_data: Dictionary containing updated information
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if shellcode_id not in self.shellcode_tome:
                logging.warning(f"Shellcode {shellcode_id} not found in tome")
                return False
            
            # Update the tome entry
            entry = self.shellcode_tome[shellcode_id]
            
            # Update basic fields
            if 'seen_count' in new_data:
                entry['seen_count'] = new_data['seen_count']
            else:
                entry['seen_count'] = entry.get('seen_count', 0) + 1
                
            if 'last_seen' in new_data:
                entry['last_seen'] = new_data['last_seen']
            
            # Update locations if provided
            if 'new_location' in new_data:
                location = new_data['new_location']
                if location not in entry.get('locations', []):
                    if 'locations' not in entry:
                        entry['locations'] = []
                    entry['locations'].append(location)
            
            # Update sources if provided
            if 'new_source' in new_data:
                source = new_data['new_source']
                if source not in entry.get('sources', []):
                    if 'sources' not in entry:
                        entry['sources'] = []
                    entry['sources'].append(source)
            
            # Update analysis results if provided
            if 'analysis' in new_data:
                entry['analysis'] = new_data['analysis']
            
            # Update classification if provided
            if 'classification' in new_data:
                entry['classification'] = new_data['classification']
            
            # Update threat level if provided  
            if 'threat_level' in new_data:
                entry['threat_level'] = new_data['threat_level']
            
            logging.info(f"Updated tome entry for shellcode {shellcode_id}")
            return True
            
        except Exception as e:
            logging.error(f"Error updating tome entry {shellcode_id}: {str(e)}")
            return False

    # Add this utility method to ShellcodeDetector for bulk updates
    def bulk_update_entries(self, updates):
        """
        Perform bulk updates on multiple shellcode entries
        
        Args:
            updates: List of dictionaries, each containing 'id' and 'data' keys
            
        Returns:
            Dictionary with success/failure counts
        """
        results = {'success': 0, 'failed': 0, 'errors': []}
        
        for update in updates:
            try:
                shellcode_id = update.get('id')
                update_data = update.get('data', {})
                
                if not shellcode_id:
                    results['failed'] += 1
                    results['errors'].append("Missing shellcode ID")
                    continue
                    
                if self.update_tome_entry(shellcode_id, update_data):
                    results['success'] += 1
                else:
                    results['failed'] += 1
                    results['errors'].append(f"Failed to update {shellcode_id}")
                    
            except Exception as e:
                results['failed'] += 1
                results['errors'].append(f"Error updating entry: {str(e)}")
        
        logging.info(f"Bulk update completed: {results['success']} success, {results['failed']} failed")
        return results

class ShellcodeReporter:
    """
    Handles reporting and logging of shellcode analysis results to a separate
    database/file system for long-term storage and analysis.
    """
    
    def __init__(self, db_path="ShellCodeForTomeAndAnalysis.db"):
        """
        Initialize the shellcode reporter with a database path.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._initialize_db()
        
    def _initialize_db(self):
        """Set up the database schema if it doesn't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS shellcode_entries (
            id TEXT PRIMARY KEY,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            seen_count INTEGER,
            size INTEGER,
            hash TEXT,
            hex_preview TEXT,
            classification TEXT,
            threat_level TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS shellcode_data (
            id TEXT PRIMARY KEY,
            raw_data BLOB,
            disassembly TEXT,
            FOREIGN KEY (id) REFERENCES shellcode_entries (id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS shellcode_locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shellcode_id TEXT,
            process_id INTEGER,
            region_name TEXT,
            address TEXT,
            timestamp TIMESTAMP,
            detection_method TEXT,
            FOREIGN KEY (shellcode_id) REFERENCES shellcode_entries (id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shellcode_id TEXT,
            analysis_type TEXT,
            analysis_result TEXT,
            timestamp TIMESTAMP,
            FOREIGN KEY (shellcode_id) REFERENCES shellcode_entries (id)
        )
        ''')
        
        conn.commit()
        conn.close()
        
    def log_shellcode(self, shellcode_entry, process_id=None, detection_method="unknown"):
        """
        Log a detected shellcode to the database.
        
        Args:
            shellcode_entry: Dictionary containing shellcode information
            process_id: ID of the process where shellcode was found (optional)
            detection_method: Method used to detect the shellcode
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            shellcode_id = shellcode_entry.get('id')
            if not shellcode_id:
                # Generate ID if not present
                shellcode_id = hashlib.sha256(shellcode_entry['data']).hexdigest()[:16]
                
            # Check if shellcode exists
            cursor.execute('SELECT seen_count FROM shellcode_entries WHERE id = ?', (shellcode_id,))
            existing = cursor.fetchone()
            
            now = datetime.now()
            
            if existing:
                # Update existing entry
                cursor.execute('''
                UPDATE shellcode_entries 
                SET last_seen = ?, seen_count = seen_count + 1
                WHERE id = ?
                ''', (now, shellcode_id))
            else:
                # Create new entry
                cursor.execute('''
                INSERT INTO shellcode_entries 
                (id, first_seen, last_seen, seen_count, size, hash, hex_preview, classification, threat_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    shellcode_id,
                    now,
                    now,
                    1,
                    shellcode_entry.get('size', len(shellcode_entry.get('data', b''))),
                    hashlib.sha256(shellcode_entry.get('data', b'')).hexdigest(),
                    binascii.hexlify(shellcode_entry.get('data', b'')[:64]).decode('utf-8'),
                    self._classify_shellcode(shellcode_entry),
                    self._determine_threat_level(shellcode_entry)
                ))
                
                # Store raw data and disassembly separately
                cursor.execute('''
                INSERT INTO shellcode_data (id, raw_data, disassembly)
                VALUES (?, ?, ?)
                ''', (
                    shellcode_id,
                    shellcode_entry.get('data', b''),
                    shellcode_entry.get('disassembly', '')
                ))
            
            # Add location information
            cursor.execute('''
            INSERT INTO shellcode_locations 
            (shellcode_id, process_id, region_name, address, timestamp, detection_method)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                shellcode_id,
                process_id,
                shellcode_entry.get('region_name', 'unknown'),
                str(shellcode_entry.get('address', 0)),
                now,
                detection_method or shellcode_entry.get('detection_method', 'unknown')
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error logging shellcode: {str(e)}")
            return False
            
    def log_analysis_result(self, shellcode_id, analysis_type, result):
        """
        Log an analysis result for a specific shellcode.
        
        Args:
            shellcode_id: ID of the shellcode
            analysis_type: Type of analysis performed
            result: Result data (will be JSON serialized)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Store analysis result
            cursor.execute('''
            INSERT INTO analysis_results (shellcode_id, analysis_type, analysis_result, timestamp)
            VALUES (?, ?, ?, ?)
            ''', (
                shellcode_id,
                analysis_type,
                json.dumps(result) if not isinstance(result, str) else result,
                datetime.now()
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error logging analysis result: {str(e)}")
            return False
            
    def get_shellcode(self, shellcode_id):
        """
        Retrieve a shellcode entry and its analysis history.
        
        Args:
            shellcode_id: ID of the shellcode to retrieve
            
        Returns:
            Dictionary containing shellcode data and analysis history
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get shellcode entry
            cursor.execute('''
            SELECT * FROM shellcode_entries WHERE id = ?
            ''', (shellcode_id,))
            entry = dict(cursor.fetchone() or {})
            
            if not entry:
                return None
                
            # Get raw data
            cursor.execute('''
            SELECT raw_data, disassembly FROM shellcode_data WHERE id = ?
            ''', (shellcode_id,))
            data_row = cursor.fetchone()
            
            if data_row:
                entry['data'] = data_row['raw_data']
                entry['disassembly'] = data_row['disassembly']
            
            # Get locations
            cursor.execute('''
            SELECT * FROM shellcode_locations WHERE shellcode_id = ?
            ''', (shellcode_id,))
            entry['locations'] = [dict(row) for row in cursor.fetchall()]
            
            # Get analysis results
            cursor.execute('''
            SELECT * FROM analysis_results WHERE shellcode_id = ? ORDER BY timestamp DESC
            ''', (shellcode_id,))
            entry['analysis'] = [dict(row) for row in cursor.fetchall()]
            
            # Parse JSON in analysis results
            for analysis in entry['analysis']:
                try:
                    analysis['analysis_result'] = json.loads(analysis['analysis_result'])
                except:
                    pass  # Keep as string if not valid JSON
            
            conn.close()
            return entry
            
        except Exception as e:
            print(f"Error retrieving shellcode: {str(e)}")
            return None
            
    def search_shellcode(self, criteria):
        """
        Search for shellcode entries matching the given criteria.
        
        Args:
            criteria: Dictionary of search criteria
            
        Returns:
            List of matching shellcode entries (without raw data)
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = "SELECT id, first_seen, last_seen, seen_count, size, hash, hex_preview, classification, threat_level FROM shellcode_entries WHERE 1=1"
            params = []
            
            if 'classification' in criteria:
                query += " AND classification = ?"
                params.append(criteria['classification'])
                
            if 'threat_level' in criteria:
                query += " AND threat_level = ?"
                params.append(criteria['threat_level'])
                
            if 'min_size' in criteria:
                query += " AND size >= ?"
                params.append(criteria['min_size'])
                
            if 'max_size' in criteria:
                query += " AND size <= ?"
                params.append(criteria['max_size'])
                
            if 'hex_pattern' in criteria:
                query += " AND hex_preview LIKE ?"
                params.append(f"%{criteria['hex_pattern']}%")
                
            if 'first_seen_after' in criteria:
                query += " AND first_seen >= ?"
                params.append(criteria['first_seen_after'])
                
            cursor.execute(query, params)
            results = [dict(row) for row in cursor.fetchall()]
            
            conn.close()
            return results
            
        except Exception as e:
            print(f"Error searching shellcode: {str(e)}")
            return []
            
    def generate_report(self, output_format="json", output_file=None):
        """
        Generate a comprehensive report of shellcode findings.
        
        Args:
            output_format: Format of the report ("json", "html", "csv")
            output_file: Path to save the report (None for stdout)
            
        Returns:
            Path to the generated report or report string
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get statistics
            cursor.execute("SELECT COUNT(*) as total FROM shellcode_entries")
            total_count = cursor.fetchone()['total']
            
            cursor.execute("SELECT classification, COUNT(*) as count FROM shellcode_entries GROUP BY classification")
            classifications = {row['classification']: row['count'] for row in cursor.fetchall()}
            
            cursor.execute("SELECT threat_level, COUNT(*) as count FROM shellcode_entries GROUP BY threat_level")
            threat_levels = {row['threat_level']: row['count'] for row in cursor.fetchall()}
            
            # Get recently detected shellcode
            cursor.execute("""
            SELECT se.*, sl.region_name, sl.detection_method
            FROM shellcode_entries se
            JOIN shellcode_locations sl ON se.id = sl.shellcode_id
            ORDER BY sl.timestamp DESC LIMIT 20
            """)
            recent_detections = [dict(row) for row in cursor.fetchall()]
            
            # Get most frequently seen shellcode
            cursor.execute("SELECT * FROM shellcode_entries ORDER BY seen_count DESC LIMIT 10")
            frequent_shellcode = [dict(row) for row in cursor.fetchall()]
            
            # Compile report data
            report_data = {
                "generated_at": datetime.now().isoformat(),
                "statistics": {
                    "total_shellcode_count": total_count,
                    "classifications": classifications,
                    "threat_levels": threat_levels
                },
                "recent_detections": recent_detections,
                "frequent_shellcode": frequent_shellcode
            }
            
            # Generate report in specified format
            if output_format == "json":
                report = json.dumps(report_data, indent=2, default=str)
            elif output_format == "html":
                report = self._generate_html_report(report_data)
            elif output_format == "csv":
                report = self._generate_csv_report(report_data)
            else:
                report = json.dumps(report_data, indent=2, default=str)
            
            # Save or return report
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(report)
                return output_file
            else:
                return report
                
        except Exception as e:
            print(f"Error generating report: {str(e)}")
            return f"Error generating report: {str(e)}"
    def _generate_html_report(self, shellcode_entries, output_file, detailed=True):
        """Generate a detailed HTML report of detected shellcode"""
        try:
            import datetime, os, base64, binascii, logging, re
            from io import BytesIO
            from collections import Counter
            from math import log2
            
            # Process entries into uniform format
            all_entries = []
            if isinstance(shellcode_entries, dict):
                for region, entries in shellcode_entries.items():
                    for entry in entries:
                        entry['region_name'] = region
                        all_entries.append(entry)
            else:
                all_entries = shellcode_entries
                
            if not all_entries:
                logging.warning("No shellcode entries to report")
                return False
            
            # Basic HTML template
            html = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Shellcode Analysis Report</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background-color: #fff; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #2c3e50; }}
            h1 {{ border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ padding: 12px 15px; border: 1px solid #ddd; text-align: left; }}
            th {{ background-color: #3498db; color: white; }}
            .shellcode-section {{ margin-bottom: 30px; padding: 15px; background-color: #fff; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            .hex-dump {{ font-family: monospace; background-color: #f8f8f8; padding: 10px; overflow-x: auto; white-space: pre-wrap; }}
            .disassembly {{ font-family: monospace; background-color: #282c34; color: #abb2bf; padding: 15px; overflow-x: auto; }}
            .collapsible {{ cursor: pointer; user-select: none; }}
            .content {{ display: none; overflow: hidden; }}
        </style>
        <script>
            document.addEventListener('DOMContentLoaded', function() {{
                var coll = document.getElementsByClassName("collapsible");
                for (var i = 0; i < coll.length; i++) {{
                    coll[i].addEventListener("click", function() {{
                        this.classList.toggle("active");
                        var content = this.nextElementSibling;
                        content.style.display = content.style.display === "block" ? "none" : "block";
                    }});
                }}
            }});
        </script>
    </head>
    <body>
        <div class="container">
            <h1>Shellcode Analysis Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Generated:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Total Shellcode Detected:</strong> {len(all_entries)}</p>
            </div>
    """

            # Add overview table
            html += """
            <h2>Shellcode Overview</h2>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Region</th>
                    <th>Size</th>
                    <th>Address</th>
                    <th>Detection Method</th>
                </tr>
    """
            for i, entry in enumerate(all_entries):
                html += f"""
                <tr>
                    <td>{entry.get('id', f'SC{i}')}</td>
                    <td>{entry.get('region_name', 'Unknown')}</td>
                    <td>{entry.get('size', 0)} bytes</td>
                    <td>0x{entry.get('address', 0):08x}</td>
                    <td>{entry.get('detection_method', entry.get('pattern_matched', 'Unknown'))}</td>
                </tr>
    """
            html += "</table>"

            # Add visualization placeholders (actual visualization code omitted for brevity)
            html += "<h2>Visualizations</h2>"
            html += "<p>Size distribution and detection method charts would appear here if matplotlib is available.</p>"
            
            # Detailed shellcode sections
            html += "<h2>Detailed Analysis</h2>"
            
            for i, entry in enumerate(all_entries):
                shellcode_id = entry.get('id', f'SC{i}')
                region_name = entry.get('region_name', 'Unknown')
                size = entry.get('size', 0)
                address = entry.get('address', 0)
                detection = entry.get('detection_method', entry.get('pattern_matched', 'Unknown'))
                
                # Get shellcode bytes and format hex dump
                shellcode_data = entry.get('data', b'')
                hex_dump = ""
                if shellcode_data:
                    for j in range(0, len(shellcode_data), 16):
                        line_bytes = shellcode_data[j:j+16]
                        hex_line = ' '.join(f'{b:02x}' for b in line_bytes)
                        ascii_line = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_bytes)
                        hex_dump += f"0x{address+j:08x}: {hex_line:<47} | {ascii_line}\n"
                
                html += f"""
                <div class="shellcode-section">
                    <h3>{shellcode_id} - {region_name}</h3>
                    <div>
                        <strong>Address:</strong> 0x{address:08x} | 
                        <strong>Size:</strong> {size} bytes | 
                        <strong>Detection:</strong> {detection}
                    </div>
    """
                
                # Calculate entropy if data available
                if shellcode_data and len(shellcode_data) > 0:
                    try:
                        entropy = 0
                        counter = Counter(shellcode_data)
                        for count in counter.values():
                            p_x = count / len(shellcode_data)
                            entropy += -p_x * log2(p_x)
                        html += f"<div><strong>Entropy:</strong> {entropy:.2f}</div>"
                    except Exception as e:
                        logging.debug(f"Error calculating entropy: {str(e)}")
                
                # Add hex dump (collapsible)
                html += f"""
                    <h4 class="collapsible">Hex Dump</h4>
                    <div class="content hex-dump">
    {hex_dump}
                    </div>
    """

                # Add disassembly if available
                if 'disassembly' in entry and entry['disassembly']:
                    html += f"""
                    <h4 class="collapsible">Disassembly</h4>
                    <div class="content disassembly">
    {entry['disassembly']}
                    </div>
    """
                
                html += """
                </div>
    """
            
            # Close HTML tags
            html += """
        </div>
    </body>
    </html>
    """

            # Write report to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html)
                
            logging.info(f"HTML report generated: {output_file}")
            return True
        
        except Exception as e:
            logging.error(f"Error generating HTML report: {str(e)}")
            return False


    def _generate_csv_report(self, shellcode_entries, output_file):
        """
        Generate a CSV report of detected shellcode
        
        Args:
            shellcode_entries: List of shellcode entries or dictionary of region names to lists
            output_file: Path where the CSV file will be saved
            
        Returns:
            True if report was successfully generated, False otherwise
        """
        try:
            import csv
            import datetime
            import binascii
            import logging
            
            # Process entries into uniform format
            all_entries = []
            if isinstance(shellcode_entries, dict):
                for region, entries in shellcode_entries.items():
                    for entry in entries:
                        entry['region_name'] = region
                        all_entries.append(entry)
            else:
                all_entries = shellcode_entries
                
            if not all_entries:
                logging.warning("No shellcode entries to report")
                return False
            
            # Define CSV fields
            fields = [
                'id', 'region_name', 'address', 'size', 'detection_method', 
                'pattern_matched', 'detection_time', 'hex_preview'
            ]
            
            # Write CSV file
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fields)
                writer.writeheader()
                
                for entry in all_entries:
                    # Prepare row data
                    row = {
                        'id': entry.get('id', 'Unknown'),
                        'region_name': entry.get('region_name', 'Unknown'),
                        'address': f"0x{entry.get('address', 0):08x}",
                        'size': entry.get('size', 0),
                        'detection_method': entry.get('detection_method', 'Unknown'),
                        'pattern_matched': entry.get('pattern_matched', ''),
                        'detection_time': entry.get('detection_time', ''),
                    }
                    
                    # Add hex preview (first 32 bytes)
                    shellcode_data = entry.get('data', b'')
                    if shellcode_data:
                        preview_size = min(32, len(shellcode_data))
                        row['hex_preview'] = binascii.hexlify(shellcode_data[:preview_size]).decode('utf-8')
                    else:
                        row['hex_preview'] = ''
                    
                    writer.writerow(row)
            
            logging.info(f"CSV report generated: {output_file}")
            return True
            
        except Exception as e:
            logging.error(f"Error generating CSV report: {str(e)}")
        return False
    def log_shellcodes_from_tome(self, shellcode_detector):
        """
        Import shellcodes from a ShellcodeDetector tome into the reporting database.
        
        Args:
            shellcode_detector: ShellcodeDetector instance containing shellcode tome
            
        Returns:
            Number of shellcodes imported
        """
        count = 0
        self.shellcode_detector = ShellcodeDetector()
        try:
            for sc_id, sc_data in self.shellcode_detector.shellcode_tome.items():
                # Convert tome entry to reporting format
                for location in sc_data.get('locations', []):
                    shellcode_entry = {
                        'id': sc_id,
                        'data': sc_data.get('data', b''),
                        'size': sc_data.get('size', 0),
                        'address': location.get('address', 0),
                        'region_name': location.get('region_name', 'unknown'),
                        'detection_method': 'imported_from_tome'
                    }
                    
                    if self.log_shellcode(shellcode_entry):
                        count += 1
                        
            return count
            
        except Exception as e:
            print(f"Error importing shellcodes from tome: {str(e)}")
            return count
    
    def _classify_shellcode(self, shellcode_entry):
        """Classify shellcode based on its characteristics"""
        # Get the actual shellcode data bytes
        data = shellcode_entry.get('data', b'')
        detection_method = shellcode_entry.get('detection_method', '')
        
        # Classification logic based on byte patterns
        if b'\x90\x90\x90\x90\x90' in data:
            return "nop_sled_shellcode"
        elif b'\x31\xc0\x50\x68' in data:
            return "api_call_shellcode"
        elif b'\x48\x31\xc0\x50\x68' in data:
            return "x64_api_call_shellcode"
        elif detection_method and 'decoder' in detection_method.lower():
            return "encoder_decoder_shellcode"
        elif detection_method and 'pattern' in detection_method.lower():
            return "pattern_matched_shellcode"
        else:
            return "unknown_shellcode"

    def log_unidentified_shellcode(self, raw_data, source_info=None, address=0, region_name="unknown"):
        """
        Log shellcode that might not be in the standard format or wasn't identified by detection methods
        
        Args:
            raw_data: The raw bytes of the shellcode
            source_info: Information about where the shellcode was found
            address: Memory address where the shellcode was found
            region_name: Name of the memory region
            
        Returns:
            Shellcode ID if successful, None otherwise
        """
        try:
            # Generate a unique ID
            shellcode_id = hashlib.sha256(raw_data).hexdigest()[:16]
            
            # Create a shellcode entry
            shellcode_entry = {
                'id': shellcode_id,
                'data': raw_data,
                'size': len(raw_data),
                'address': address,
                'region_name': region_name,
                'detection_method': "manual_submission",
                'hex': binascii.hexlify(raw_data[:64]).decode('utf-8'),
            }
            
            # Log it to the database
            if self.log_shellcode(shellcode_entry):
                # Add source info as analysis
                if source_info:
                    self.log_analysis_result(
                        shellcode_id, 
                        "source_information", 
                        source_info
                    )
                return shellcode_id
            return None
            
        except Exception as e:
            print(f"Error logging unidentified shellcode: {str(e)}")
            return None

    def _determine_threat_level(self, shellcode_entry):
    
        data = shellcode_entry.get('data', b'')
        detection_method = shellcode_entry.get('detection_method', '')
        pattern_matched = shellcode_entry.get('pattern_matched', '')
        
        # Combine all detection info for comprehensive matching
        all_detection_info = (detection_method + ' ' + pattern_matched).lower()
        
        # Check for dangerous API patterns in binary data
        dangerous_patterns = [
            b'\x68\x33\x32\x00\x00',  # push "32" (WinExec, etc.)
            b'\x68\x73\x41\x00\x00',  # push "As" (CreateProcessA)
            b'\x68\x6C\x6C\x00\x00',  # push "ll" (DLL loading)
            b'\x68\x6F\x63\x00\x00',  # push "oc" (memory allocation)
            b'\x68\x65\x78\x65\x00'   # push "exe"
        ]
        
        # Check for network-related patterns in binary data
        network_patterns = [
            b'\x68\x74\x63\x70\x00',  # push "tcp"
            b'\x68\x73\x6F\x63\x6B',  # push "sock"
            b'\x68\x73\x65\x6E\x64',  # push "send"
            b'\x68\x72\x65\x63\x76'   # push "recv"
        ]
        
        # Categories of keywords for detection methods
        dangerous_keywords = [
            'api', 'dll', 'createprocess', 'win', 'exec', 'process', 
            'kernel', 'memory', 'inject', 'hook', 'loadlibrary', 
            'shellcode', 'malicious', 'exploit', 'code_injection',
            'evasion', 'obfuscated', 'privilege', 'allocation',
            'suspicious', 'execute', 'heap', 'stack', 'vulnerable'
        ]
        
        network_keywords = [
            'network', 'socket', 'connect', 'dns', 'http', 'https', 
            'ftp', 'tcp', 'udp', 'ip', 'icmp', 'recv', 'send', 
            'download', 'upload', 'url', 'web', 'remote', 'connection'
        ]
        
        # Count matched binary patterns
        dangerous_pattern_count = sum(1 for pattern in dangerous_patterns if pattern in data)
        network_pattern_count = sum(1 for pattern in network_patterns if pattern in data)
        
        # Check for keyword matches in detection methods
        dangerous_keyword_match = any(keyword in all_detection_info for keyword in dangerous_keywords)
        network_keyword_match = any(keyword in all_detection_info for keyword in network_keywords)
        
        # Calculate final counts
        dangerous_count = dangerous_pattern_count + (1 if dangerous_keyword_match else 0)
        network_count = network_pattern_count + (1 if network_keyword_match else 0)
        
        # Additional threat indicators from analysis
        has_obfuscation = 'obfuscation' in all_detection_info or 'encoded' in all_detection_info
        has_evasion = 'evasion' in all_detection_info or 'anti_' in all_detection_info
        has_known_exploit = 'exploit' in all_detection_info or 'cve' in all_detection_info
        
        # Determine threat level with enhanced logic
        if (dangerous_count >= 2 or 
            (dangerous_count >= 1 and network_count >= 1) or
            has_known_exploit or
            (has_obfuscation and (dangerous_count >= 1 or network_count >= 1))):
            return "high"
        elif (dangerous_count >= 1 or 
            network_count >= 1 or 
            has_obfuscation or 
            has_evasion):
            return "medium"
        else:
            return "low"
            

if __name__ == "__main__":
    
    # Set up logging first before any logging calls
    def setup_application_logging():

        """Set up centralized application logging"""
        # Create logs directory
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # Configure handlers
        file_handler = logging.FileHandler(str(log_dir / 'scanner.log'))
        file_handler.setLevel(logging.DEBUG)  # Use constant, not function
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)  # Use constant, not function
        
        # Create formatters
        detailed_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
        file_handler.setFormatter(detailed_formatter)
        console_handler.setFormatter(detailed_formatter)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)  # Use constant, not function
        
        # Clear any existing handlers to avoid duplicates
        if root_logger.handlers:
            root_logger.handlers.clear()
            
        # Add handlers
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
        
        return root_logger
    # Initialize logging before any logging calls
    logger = setup_application_logging()
    
    logging.debug("Starting application")

    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception as e:
            logging.error(f"Error checking admin status: {str(e)}")
            return False
    if not is_admin(self):
        logging.debug("Not running as admin, requesting elevation")
        try:
            ctypes.windll.shell32.ShellExecutew(None, "runas", sys.executable, f'"{__file__}"', None, 1)
        except Exception as e:
            logging.error(f"Failed to elevate privileges: {str(e)}")
        sys.exit()
    else:
        logging.debug("Running with admin privileges")
        try:
            logging.debug("Creating root window")
            root = tk.Tk()
            root.geometry("800x600")
            
            # Set icon if available
            try:
                root.iconbitmap("icon.ico")
            except:
                logging.debug("Icon file not found, using default")
            
            logging.debug("Initializing ScannerGUI")
            
            logging.debug("Creating ScannerGUI instance")
            app = ScannerGui(root)
            app.setup_gui()
            root.mainloop()
            # Initialize scanning engine and rules
            try:
                logging.debug("Rules loading started")
            except Exception as e:
                logging.error(f"Error loading rules: {str(e)}")
            
            logging.debug("Starting mainloop")
            
        except Exception as e:
            logging.exception("Fatal error occurred:")
            print(f"\n\nERROR: {str(e)}")
            traceback.print_exc()
            logging.exception("Error in main GUI loop")
            print(f"Error occurred: {str(e)}")
        finally:
            # This ensures the console stays open regardless of success or failure
            print("\nPress Enter to exit...")
            input()  # This keeps the console window open until user presses Enter