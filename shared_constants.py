"""
Shared constants, structures, and imports for the Orbital Station project.
This module contains all the common ctypes structures and constants used across modules.
"""

import ctypes
from ctypes import Structure, wintypes, POINTER, c_char
from ctypes.wintypes import DWORD, HANDLE, LPVOID, LPWSTR, ULONG
import logging
import os
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Windows API Constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400
DEFAULT_PAGE_SIZE = 4096
TH32CS_SNAPTHREAD = 0x00000002
SystemProcessInformation = 5
SystemModuleInformation = 11
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

# Protected processes
PROTECTED_PROCESSES = [
    "Registry", "smss.exe", "csrss.exe", "wininit.exe", 
    "services.exe", "lsass.exe", "winlogon.exe", "System", 
    "System Idle Process"
]

# Ctypes Structures
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_char * 260)
    ]

class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ThreadID", ctypes.c_ulong),
        ("th32OwnerProcessID", ctypes.c_ulong),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong)
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong)
    ]

class GUID(Structure):
    _fields_ = [
        ('Data1', DWORD),
        ('Data2', wintypes.WORD),
        ('Data3', wintypes.WORD),
        ('Data4', c_char * 8)
    ]

class WINTRUST_FILE_INFO(Structure):
    _fields_ = [
        ('cbStruct', DWORD),
        ('pcwszFilePath', LPWSTR),
        ('hFile', HANDLE),
        ('pgKnownSubject', POINTER(GUID))
    ]

class WINTRUST_DATA(Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('pPolicyCallbackData', wintypes.LPVOID),
        ('pSIPClientData', wintypes.LPVOID),
        ('dwUIChoice', wintypes.DWORD),
        ('fdwRevocationChecks', wintypes.DWORD),
        ('dwUnionChoice', wintypes.DWORD),
        ('pFile', POINTER(WINTRUST_FILE_INFO)),
        ('pCatalog', wintypes.LPVOID),
        ('pBlob', wintypes.LPVOID),
        ('pSgnr', wintypes.LPVOID),
        ('pCert', wintypes.LPVOID),
        ('dwStateAction', wintypes.DWORD),
        ('hWVTStateData', wintypes.HANDLE),
        ('pwszURLReference', wintypes.LPCWSTR),
        ('dwProvFlags', wintypes.DWORD),
        ('dwUIContext', wintypes.DWORD),
        ('pSignatureSettings', wintypes.LPVOID)
    ]

class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]

class SYSTEM_MODULE_INFORMATION(Structure):
    _fields_ = [
        ("Reserved", LPVOID * 2),
        ("ImageBase", LPVOID),
        ("ImageSize", ULONG),
        ("Flags", ULONG),
        ("LoadOrderIndex", wintypes.USHORT),
        ("InitOrderIndex", wintypes.USHORT),
        ("LoadCount", wintypes.USHORT),
        ("ModuleNameOffset", wintypes.USHORT),
        ("ImageName", c_char * 256),
    ]

class MIB_TCPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwState", DWORD),
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
        ("dwOwningPid", DWORD),
    ]

class MIB_UDPROW_OWNER_PID(Structure):
    _fields_ = [
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwOwningPid", DWORD),
    ]

class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ("e_magic", ctypes.c_uint16),
        ("e_cblp", ctypes.c_uint16),
        ("e_cp", ctypes.c_uint16),
        ("e_crlc", ctypes.c_uint16),
        ("e_cparhdr", ctypes.c_uint16),
        ("e_minalloc", ctypes.c_uint16),
        ("e_maxalloc", ctypes.c_uint16),
        ("e_ss", ctypes.c_uint16),
        ("e_sp", ctypes.c_uint16),
        ("e_csum", ctypes.c_uint16),
        ("e_ip", ctypes.c_uint16),
        ("e_cs", ctypes.c_uint16),
        ("e_lfarlc", ctypes.c_uint16),
        ("e_ovno", ctypes.c_uint16),
        ("e_res", ctypes.c_uint16 * 4),
        ("e_oemid", ctypes.c_uint16),
        ("e_oeminfo", ctypes.c_uint16),
        ("e_res2", ctypes.c_uint16 * 10),
        ("e_lfanew", ctypes.c_int32)
    ]

class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("VirtualAddress", ctypes.c_uint32),
        ("Size", ctypes.c_uint32)
    ]

class IMAGE_OPTIONAL_HEADER(ctypes.Structure):
    _fields_ = [
        ("Magic", ctypes.c_uint16),
        ("MajorLinkerVersion", ctypes.c_uint8),
        ("MinorLinkerVersion", ctypes.c_uint8),
        ("SizeOfCode", ctypes.c_uint32),
        ("SizeOfInitializedData", ctypes.c_uint32),
        ("SizeOfUninitializedData", ctypes.c_uint32),
        ("AddressOfEntryPoint", ctypes.c_uint32),
        ("BaseOfCode", ctypes.c_uint32),
        ("BaseOfData", ctypes.c_uint32),
        ("ImageBase", ctypes.c_uint32),
        ("SectionAlignment", ctypes.c_uint32),
        ("FileAlignment", ctypes.c_uint32),
        ("MajorOperatingSystemVersion", ctypes.c_uint16),
        ("MinorOperatingSystemVersion", ctypes.c_uint16),
        ("MajorImageVersion", ctypes.c_uint16),
        ("MinorImageVersion", ctypes.c_uint16),
        ("MajorSubsystemVersion", ctypes.c_uint16),
        ("MinorSubsystemVersion", ctypes.c_uint16),
        ("Win32VersionValue", ctypes.c_uint32),
        ("SizeOfImage", ctypes.c_uint32),
        ("SizeOfHeaders", ctypes.c_uint32),
        ("CheckSum", ctypes.c_uint32),
        ("Subsystem", ctypes.c_uint16),
        ("DllCharacteristics", ctypes.c_uint16),
        ("SizeOfStackReserve", ctypes.c_uint32),
        ("SizeOfStackCommit", ctypes.c_uint32),
        ("SizeOfHeapReserve", ctypes.c_uint32),
        ("SizeOfHeapCommit", ctypes.c_uint32),
        ("LoaderFlags", ctypes.c_uint32),
        ("NumberOfRvaAndSizes", ctypes.c_uint32),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * 16)
    ]

class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ("Machine", ctypes.c_uint16),
        ("NumberOfSections", ctypes.c_uint16),
        ("TimeDateStamp", ctypes.c_uint32),
        ("PointerToSymbolTable", ctypes.c_uint32),
        ("NumberOfSymbols", ctypes.c_uint32),
        ("SizeOfOptionalHeader", ctypes.c_uint16),
        ("Characteristics", ctypes.c_uint16)
    ]

class IMAGE_NT_HEADERS(ctypes.Structure):
    _fields_ = [
        ("Signature", ctypes.c_uint32),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER)
    ]

class IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("Characteristics", ctypes.c_uint32),
        ("TimeDateStamp", ctypes.c_uint32),
        ("MajorVersion", ctypes.c_uint16),
        ("MinorVersion", ctypes.c_uint16),
        ("Name", ctypes.c_uint32),
        ("Base", ctypes.c_uint32),
        ("NumberOfFunctions", ctypes.c_uint32),
        ("NumberOfNames", ctypes.c_uint32),
        ("AddressOfFunctions", ctypes.c_uint32),
        ("AddressOfNames", ctypes.c_uint32),
        ("AddressOfNameOrdinals", ctypes.c_uint32)
    ]

# Utility functions
def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception as e:
        logging.error(f"Error checking admin status: {str(e)}")
        return False

def setup_application_logging():
    """Set up centralized application logging"""
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    file_handler = logging.FileHandler(str(log_dir / 'scanner.log'))
    file_handler.setLevel(logging.DEBUG)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    detailed_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    file_handler.setFormatter(detailed_formatter)
    console_handler.setFormatter(detailed_formatter)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    if root_logger.handlers:
        root_logger.handlers.clear()
        
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return root_logger
