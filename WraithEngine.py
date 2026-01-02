"""
WRAITH Engine - Deep Process, Memory, and File Purger
Integrated module for OFSP (Orbital Station File Scanner Protection)
Author: Quellaran // Specter
"""
import os
import psutil
import shutil
import ctypes
import winreg
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """Windows memory information structure for memory scanning"""
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


class WraithEngine:
    """
    WRAITH Engine - Deep Process, Memory, and File Purger
    
    Provides comprehensive malware removal capabilities:
    - Process resolution and termination
    - Memory scanning with YARA rule matching
    - Secure file deletion (shredding)
    - Registry persistence cleanup
    """
    
    # Process access rights
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_OPERATION = 0x0008
    
    # Memory states
    MEM_COMMIT = 0x1000
    
    def __init__(self, mode: str = "aggressive", yara_rules_path: Optional[str] = None):
        """
        Initialize the Wraith Engine.
        
        Args:
            mode: Operation mode - 'aggressive' (default) or 'stealth'
            yara_rules_path: Optional path to custom YARA rules file
        """
        self.mode = mode.lower()
        self.logger = logging.getLogger("WRAITH")
        self.yara_rules_path = yara_rules_path
        self.rules = self._compile_yara_rules()
        self.scan_results: List[Dict[str, Any]] = []
        self.purge_history: List[Dict[str, Any]] = []
        self._progress_callback: Optional[Callable[[int, str], None]] = None
        
    def set_progress_callback(self, callback: Callable[[int, str], None]):
        """Set a callback for progress updates during operations"""
        self._progress_callback = callback
        
    def _emit_progress(self, percent: int, message: str):
        """Emit progress update if callback is set"""
        if self._progress_callback:
            self._progress_callback(percent, message)
        self.logger.info(message)
    
    def _compile_yara_rules(self) -> Optional[Any]:
        """Compile YARA rules for memory scanning"""
        if not YARA_AVAILABLE:
            self.logger.warning("YARA module not available. Memory pattern matching disabled.")
            return None
            
        try:
            if self.yara_rules_path and os.path.exists(self.yara_rules_path):
                return yara.compile(filepath=self.yara_rules_path)
            else:
                return yara.compile(source="""
                    rule SuspiciousCode 
                    {
                        strings:
                            $mz = "MZ"
                            $powershell = "powershell" nocase
                            $cmd = "cmd.exe" nocase
                            $eval = "eval" nocase
                            $shellcode1 = { 55 8B EC 83 EC }
                            $shellcode2 = { E8 00 00 00 00 }
                            $base64_ps = "JABz" 
                        condition:
                            any of them
                    }
                    
                    rule MaliciousShellcode
                    {
                        strings:
                            $api_hash = { 64 A1 30 00 00 00 }
                            $kernel32_hash = { 68 33 32 00 00 68 6B 65 72 6E }
                            $ws2_32 = "ws2_32" nocase
                            $wininet = "wininet" nocase
                        condition:
                            2 of them
                    }
                """)
        except Exception as e:
            self.logger.error(f"Failed to compile YARA rules: {e}")
            return None

    def resolve_process(self, name: Optional[str] = None, pid: Optional[int] = None) -> Optional[psutil.Process]:
        """
        Find a process by name or PID.
        
        Args:
            name: Process name to search for
            pid: Process ID to search for
            
        Returns:
            psutil.Process object if found, None otherwise
        """
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                if pid and proc.pid == pid:
                    return proc
                if name and proc.info['name'] and proc.info['name'].lower() == name.lower():
                    return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None
    
    def get_process_list(self) -> List[Dict[str, Any]]:
        """Get list of all running processes with details"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'memory_info', 'cpu_percent']):
            try:
                info = proc.info
                processes.append({
                    'pid': info['pid'],
                    'name': info['name'] or 'Unknown',
                    'exe': info.get('exe', ''),
                    'cmdline': info.get('cmdline', []),
                    'memory': info.get('memory_info', None),
                    'cpu': info.get('cpu_percent', 0)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

    def scan_memory(self, pid: int) -> List[Dict[str, Any]]:
        """
        Scan process memory for suspicious patterns.
        
        Args:
            pid: Process ID to scan
            
        Returns:
            List of detection results
        """
        self._emit_progress(0, f"Scanning memory for PID: {pid}")
        detections = []
        
        try:
            process_handle = ctypes.windll.kernel32.OpenProcess(
                self.PROCESS_VM_READ | self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_OPERATION,
                False, pid
            )
            if not process_handle:
                self.logger.warning(f"Unable to open process memory for PID {pid}")
                return detections

            mbi = MEMORY_BASIC_INFORMATION()
            address = 0
            region_count = 0
            
            while ctypes.windll.kernel32.VirtualQueryEx(
                process_handle, 
                ctypes.c_void_p(address), 
                ctypes.byref(mbi), 
                ctypes.sizeof(mbi)
            ):
                region_count += 1
                
                if mbi.State == self.MEM_COMMIT and mbi.RegionSize > 0:
                    try:
                        buffer = ctypes.create_string_buffer(min(mbi.RegionSize, 1024 * 1024))
                        bytes_read = ctypes.c_size_t(0)
                        
                        if ctypes.windll.kernel32.ReadProcessMemory(
                            process_handle,
                            ctypes.c_void_p(address),
                            buffer,
                            len(buffer),
                            ctypes.byref(bytes_read)
                        ):
                            region_data = buffer.raw[:bytes_read.value]
                            
                            if len(region_data) >= 2 and region_data[:2] == b"MZ":
                                detection = {
                                    'type': 'PE_HEADER',
                                    'address': hex(address),
                                    'size': mbi.RegionSize,
                                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    'description': 'Possible PE header detected in memory',
                                    'severity': 'High'
                                }
                                detections.append(detection)
                                self.logger.info(f"[!] PE header at {hex(address)} | Size: {mbi.RegionSize}")
                            
                            if self.rules:
                                matches = self.rules.match(data=region_data)
                                if matches:
                                    for match in matches:
                                        detection = {
                                            'type': 'YARA_MATCH',
                                            'rule': match.rule,
                                            'address': hex(address),
                                            'size': mbi.RegionSize,
                                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                            'description': f'YARA rule match: {match.rule}',
                                            'severity': 'Critical' if 'Malicious' in match.rule else 'High'
                                        }
                                        detections.append(detection)
                                        self.logger.warning(f"[YARA HIT] {match.rule} at {hex(address)}")
                    except Exception as e:
                        pass
                
                address += mbi.RegionSize
                if region_count % 100 == 0:
                    self._emit_progress(min(90, region_count // 10), f"Scanned {region_count} memory regions...")
            
            ctypes.windll.kernel32.CloseHandle(process_handle)
            self._emit_progress(100, f"Memory scan complete. Found {len(detections)} detections.")
            
        except Exception as e:
            self.logger.error(f"Memory scan failed: {e}")
            
        self.scan_results.extend(detections)
        return detections

    def scan_all_processes(self) -> List[Dict[str, Any]]:
        """Scan all running processes for suspicious memory patterns"""
        all_detections = []
        processes = list(psutil.process_iter(['pid', 'name']))
        total = len(processes)
        
        for i, proc in enumerate(processes):
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or 'Unknown'
                self._emit_progress(int((i / total) * 100), f"Scanning {name} (PID: {pid})...")
                
                detections = self.scan_memory(pid)
                for det in detections:
                    det['process_name'] = name
                    det['pid'] = pid
                all_detections.extend(detections)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        return all_detections

    def purge(self, name: Optional[str] = None, pid: Optional[int] = None, 
              scan_first: bool = True, clean_registry: bool = True) -> Dict[str, Any]:
        """
        Purge a malicious process completely.
        
        Args:
            name: Process name to purge
            pid: Process ID to purge
            scan_first: Whether to scan memory before killing
            clean_registry: Whether to clean registry persistence
            
        Returns:
            Dict with purge results
        """
        result = {
            'success': False,
            'process': None,
            'actions': [],
            'errors': [],
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        proc = self.resolve_process(name, pid)
        if not proc:
            result['errors'].append("Target process not found.")
            self.logger.warning("Target process not found.")
            return result

        result['process'] = {'name': proc.name(), 'pid': proc.pid}
        self._emit_progress(10, f"Targeting: {proc.name()} (PID {proc.pid})")

        if scan_first:
            self._emit_progress(20, "Scanning memory before purge...")
            detections = self.scan_memory(proc.pid)
            result['memory_detections'] = detections

        try:
            exe_path = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            exe_path = None
            
        try:
            open_files = [f.path for f in proc.open_files()]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            open_files = []

        self._emit_progress(40, "Terminating process...")
        try:
            proc.kill()
            proc.wait(timeout=5)
            result['actions'].append("Process terminated")
            self.logger.info("Process terminated.")
        except Exception as e:
            result['errors'].append(f"Failed to kill process: {e}")
            self.logger.error(f"Failed to kill process: {e}")

        if exe_path and os.path.exists(exe_path):
            self._emit_progress(50, f"Shredding executable: {exe_path}")
            if self.secure_delete(exe_path):
                result['actions'].append(f"Executable shredded: {exe_path}")
            else:
                result['errors'].append(f"Failed to delete executable: {exe_path}")

        self._emit_progress(60, "Cleaning associated files...")
        for f in open_files:
            if os.path.exists(f):
                if self.secure_delete(f):
                    result['actions'].append(f"File shredded: {f}")

        if clean_registry:
            self._emit_progress(80, "Cleaning registry...")
            cleaned = self.clean_registry(proc.name())
            result['registry_cleaned'] = cleaned
            if cleaned:
                result['actions'].append(f"Registry entries cleaned: {len(cleaned)}")

        self._emit_progress(100, "PURGE COMPLETE")
        result['success'] = len(result['errors']) == 0
        self.purge_history.append(result)
        self.logger.info("PURGE COMPLETE.")
        
        return result

    def secure_delete(self, path: str, passes: int = 3) -> bool:
        """
        Securely delete a file by overwriting with random data.
        
        Args:
            path: Path to file or directory to delete
            passes: Number of overwrite passes (default 3)
            
        Returns:
            True if deletion was successful
        """
        try:
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
                self.logger.info(f"Directory removed: {path}")
                return True
            elif os.path.isfile(path):
                file_size = os.path.getsize(path)
                with open(path, 'ba+', buffering=0) as f:
                    for i in range(passes):
                        f.seek(0)
                        f.write(os.urandom(file_size))
                        f.flush()
                        os.fsync(f.fileno())
                os.remove(path)
                self.logger.info(f"File shredded ({passes} passes): {path}")
                return True
        except Exception as e:
            self.logger.warning(f"Secure delete failed for {path}: {e}")
        return False

    def clean_registry(self, process_name: str) -> List[str]:
        """
        Clean registry entries related to a process.
        
        Args:
            process_name: Name of process to clean from registry
            
        Returns:
            List of cleaned registry entries
        """
        cleaned = []
        keys = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Microsoft\Windows\CurrentVersion\RunServices",
            r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            r"System\CurrentControlSet\Services"
        ]
        hives = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
        
        for hive in hives:
            hive_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
            for key_path in keys:
                try:
                    with winreg.OpenKey(hive, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                        i = 0
                        while True:
                            try:
                                value = winreg.EnumValue(key, i)
                                if process_name.lower() in str(value).lower():
                                    winreg.DeleteValue(key, value[0])
                                    entry = f"{hive_name}\\{key_path}\\{value[0]}"
                                    cleaned.append(entry)
                                    self.logger.info(f"Registry cleaned: {entry}")
                                else:
                                    i += 1
                            except OSError:
                                break
                except Exception:
                    continue
                    
        return cleaned
    
    def quarantine_file(self, path: str, quarantine_dir: str = "quarantine") -> Optional[str]:
        """
        Move a file to quarantine instead of deleting.
        
        Args:
            path: Path to file to quarantine
            quarantine_dir: Directory to store quarantined files
            
        Returns:
            Path to quarantined file, or None if failed
        """
        try:
            os.makedirs(quarantine_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.basename(path)
            quarantine_path = os.path.join(quarantine_dir, f"{timestamp}_{filename}.quarantine")
            
            shutil.move(path, quarantine_path)
            self.logger.info(f"File quarantined: {path} -> {quarantine_path}")
            return quarantine_path
        except Exception as e:
            self.logger.error(f"Quarantine failed for {path}: {e}")
            return None
    
    def get_scan_results(self) -> List[Dict[str, Any]]:
        """Get all scan results from this session"""
        return self.scan_results
    
    def get_purge_history(self) -> List[Dict[str, Any]]:
        """Get all purge operations from this session"""
        return self.purge_history
    
    def clear_results(self):
        """Clear scan results and purge history"""
        self.scan_results = []
        self.purge_history = []


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="WRAITH Process Purger")
    parser.add_argument('--target', help='Process name (e.g., evil.exe)')
    parser.add_argument('--pid', type=int, help='PID of process')
    parser.add_argument('--mode', default='aggressive', help='Mode: aggressive | stealth')
    parser.add_argument('--scan-only', action='store_true', help='Only scan, do not purge')
    parser.add_argument('--list', action='store_true', help='List all running processes')

    args = parser.parse_args()

    engine = WraithEngine(mode=args.mode)
    
    if args.list:
        processes = engine.get_process_list()
        print(f"\n{'PID':<8} {'Name':<30} {'Executable'}")
        print("-" * 80)
        for p in processes:
            print(f"{p['pid']:<8} {p['name']:<30} {p['exe'] or 'N/A'}")
    elif args.scan_only and args.pid:
        detections = engine.scan_memory(args.pid)
        print(f"\nFound {len(detections)} detections")
        for d in detections:
            print(f"  [{d['type']}] {d['address']} - {d['description']}")
    elif args.target or args.pid:
        result = engine.purge(name=args.target, pid=args.pid)
        print(f"\nPurge {'successful' if result['success'] else 'failed'}")
        for action in result['actions']:
            print(f"  ✓ {action}")
        for error in result['errors']:
            print(f"  ✗ {error}")
    else:
        parser.print_help()
