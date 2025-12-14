from pathlib import Path
import logging
import os
import sys
import subprocess
import yara
import hashlib
import struct
import base64
import requests
import json
import re
import glob
from datetime import datetime

class YaraRuleManager:
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        # Prevent multiple initialization of singleton
        if hasattr(self, '_initialized') and self._initialized:
            return
            
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.DEBUG)
        
        # Set up rules directory
        self.rules_dir = Path("yara_rules")
        self.rules_directory = self.rules_dir  # For backward compatibility
        
        # Initialize directory structure
        self._create_rule_directories()
        
        # Initialize attributes
        self.compiled_rules = {}
        self.combined_rules = None
        self._rules_loaded = False
        
        # Mark as initialized
        self._initialized = True

    def _create_rule_directories(self):
        """Create the necessary YARA rule directory structure"""
        try:
            # Main rules directory
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            
            # Create subdirectories for different rule categories
            subdirs = [
                "memory_rules",
                "shellcode_rules", 
                "injection_rules",
                "malware_rules",
                "custom_rules",
                "whitelist_rules"
            ]
            
            for subdir in subdirs:
                subdir_path = self.rules_dir / subdir
                subdir_path.mkdir(exist_ok=True)
                
            self.logger.info("YARA rule directories created successfully")
            
        except Exception as e:
            self.logger.error(f"Error creating rule directories: {str(e)}")
        
        # Create injection patterns
        self.injection_patterns = {
            'reflective_loader': rb'\x4D\x5A.{128,1024}?ReflectiveLoader',
            'shellcode_xor': rb'\x48[\x31\x33]\xc0[\x48\x83]\xc0.',
            'api_hashing': rb'[\x33\x35\x8b]\xc9.{1,10}?[\xc1\xd3][\xe0\xe1\xe2].{1,10}?[\x03\x33]\xc1',
            'stack_strings': rb'[\x6a\x68][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff][\x6a\x68]',
            'process_inject': rb'CreateRemoteThread|VirtualAllocEx|WriteProcessMemory',
        }
        
        # Convert rules_dir to a Path object for easier path manipulation
        self.rules_dir = Path(self.rules_dir)
        
        # Create rules directory structure
        os.makedirs(self.rules_dir, exist_ok=True)
        
        # Create category subdirectories
        for subdir in [
            "memory_rules", "shellcode_rules", "injection_rules", 
            "malware_rules", "custom_rules"
        ]:
            os.makedirs(self.rules_dir / subdir, exist_ok=True)
        
        # Define repository sources
        self.repo_sources = {
            "awesome-yara": "https://github.com/InQuest/awesome-yara",
            "cape-sandbox": "https://github.com/kevoreilly/CAPEv2",
            "fireeye": "https://github.com/mandiant/red_team_tool_countermeasures",
            "otx": "https://github.com/xosski/OTX-Python-SDK",
            "neo23x0": "https://github.com/Neo23x0/signature-base"
        }
        
        logging.debug("=== YaraRuleManager Initialization ===")
        logging.debug(f"Rules directory: {self.rules_dir}")
        
        # Simplified initialization - focus on local rules first
        try:
            # Create directories
            self.create_repo_directories()
            
            # Create basic rules that are guaranteed to work
            logging.info("Initializing YARA rules with basic detection patterns...")
            self.create_basic_rules()
            self.create_missing_rules()
            
            # Compile rules
            self.combined_rules = self.compile_combined_rules()
            self._rules_loaded = self.combined_rules is not None
            
            if self._rules_loaded:
                logging.info("YARA rules loaded successfully")
            else:
                logging.warning("YARA rules compilation returned None - using defaults")
                self._create_default_rules()
                self.combined_rules = self.compile_combined_rules()
                self._rules_loaded = self.combined_rules is not None
                
        except Exception as e:
            logging.error(f"Error during rule initialization: {str(e)}")
            self._rules_loaded = False
            self.combined_rules = None           
    def process_yara_files(self, directory: Path):
      
      self.combined_rules = self.compile_combined_rules()
      if not directory.exists():              
            externals = {
                'filepath': '',
                'filename': '',
                'extension': '',
                'filetype': '',
                'file_type': '',
                'file_name': '',
                'file_path': '',
                'md5': '',
                'owner': '',
                'proc_name': '',
                'process_name': '',
                'module_path': '',
                'module_name': '',
                'time_date': 0,
                'currentdir': '',
                'executable': '',
                'compiled': True,
                'source': '',
                'description': '',
                'version': '',
                'fullpath': '',
                'ext': '',
                'path': '',
                'root': '',
                'name': '',
                'type': '',
                'size': 0,
                'sha1': '',
                'sha256': '',
                'signatures': [],
                'filesize': 0
            }
            
            for yara_file in directory.glob('**/*.yar*'):
                try:
                    # Read the rule file content
                    with open(yara_file, 'r') as f:
                        content = f.read()
                    
                    # Add external variable declarations at the start
                    external_declarations = 'global private rule declare_externals { condition: true }\n'
                    for var_name in externals.keys():
                        external_declarations += f'global private rule declare_{var_name} {{ condition: true }}\n'
                    
                    # Combine declarations with original content
                    modified_content = external_declarations + content
                    
                    # Compile the modified rule
                    compiled_rule = yara.compile(source=modified_content)
                    self.combined_rules[yara_file.stem] = compiled_rule
                    logging.info(f"Successfully compiled rule: {yara_file.name}")
                    
                except Exception as e:
                    logging.warning(f"Invalid rule file {yara_file} in category {directory.name}: {str(e)}") 
    def fetch_github_rules(self):
        """Fetch YARA rules from GitHub repositories"""
        # Only fetch if not already initialized
        if hasattr(self, '_github_rules_fetched'):
            for repo_name in self.repo_sources:
                try:
                    import git
                except ImportError:
                    logging.error("Git module not installed. Please install with 'pip install GitPython'")
                return
        
        # Ensure repo_sources is properly defined
        if not hasattr(self, 'repo_sources') or not self.repo_sources:
            # Redefine repo_sources if it's missing
           
            self.repo_sources = {
                "awesome-yara": "https://github.com/InQuest/awesome-yara",
                "cape-sandbox": "https://github.com/kevoreilly/CAPEv2",
                "fireeye": "https://github.com/mandiant/red_team_tool_countermeasures",
                "otx": "https://github.com/xosski/OTX-Python-SDK",
                "neo23x0": "https://github.com/Neo23x0/signature-base"
            }
            logging.info("Repository sources have been restored")
        
        logging.info(f"Fetching rules from {len(self.repo_sources)} repositories...")
        
        # Make sure rules_dir is a Path object
        if isinstance(self.rules_dir, str):
            self.rules_dir = Path(self.rules_dir)
        
        # Create each repo directory explicitly before trying to clone
        for repo_name in self.repo_sources:
            repo_dir = self.rules_dir / repo_name
            os.makedirs(repo_dir, exist_ok=True)
        
        # Now try to clone repositories
        for repo_name, repo_url in self.repo_sources.items():
            if repo_name == 'otx':
                continue  # Skip OTX repository for now
            
            repo_dir = self.rules_dir / repo_name
            logging.info(f"Checking repository: {repo_name} at {repo_url}")
            
            # Clear directory if it exists but is empty
            if repo_dir.exists() and not any(repo_dir.iterdir()):
                try:
                    logging.info(f"Cloning {repo_name} repository from {repo_url}...")
                    git.Repo.clone_from(repo_url, repo_dir, depth=1)
                    logging.info(f"Successfully cloned {repo_name} repository")
                except Exception as e:
                    logging.error(f"Error cloning repository {repo_name}: {str(e)}")
                    
                    # Try using subprocess as fallback
                    try:
                        logging.info(f"Trying alternative cloning method for {repo_name}...")
                        subprocess.run([
                            'git', 'clone',
                            '--depth', '1',
                            repo_url,
                            str(repo_dir)
                        ], check=True)
                        logging.info(f"Successfully cloned {repo_name} using subprocess")
                    except Exception as e2:
                        logging.error(f"All cloning methods failed for {repo_name}: {str(e2)}")
                        continue
            else:
                logging.info(f"Repository {repo_name} already exists at {repo_dir}")
        
        # Process rules from cloned repositories
        try:
            self._process_cloned_rules()
        except Exception as e:
            logging.error(f"Error processing cloned rules: {str(e)}")
        
        # Mark as fetched
        self._github_rules_fetched = True
        logging.info("GitHub rules fetching completed")
    def _process_cloned_rules(self, rules):
        """
        Process and validate cloned Yara rules.
        Returns a list of validated rule objects.
        """
        processed_rules = []
        rules = self.rules_dir.glob('**/*.yar*')
        for rule in rules:
            try:
                # Compile and validate the rule
                compiled_rule = yara.compile(source=rule)
                
                # Add to processed rules if compilation succeeds
                processed_rules.append(compiled_rule)
                
                # Log successful rule processing
                logging.info(f"Successfully processed cloned rule: {rule[:50]}...")
                
            except yara.Error as e:
                # Log invalid rules but continue processing others
                logging.warning(f"Invalid cloned rule detected: {str(e)}")
                continue
                
        return processed_rules
    def fetch_and_process_repo_rules(self):
        """Fetch and process YARA rules from GitHub repositories"""
        print("Fetching and processing repository rules...")
        
        # First make sure GitPython is available
        try:
            import git
        except ImportError:
            print("GitPython not installed. Installing now...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "GitPython"])
            import git
        
        # Ensure repo directories exist
        for repo_name in self.repo_sources:
            repo_dir = self.rules_dir / repo_name
            os.makedirs(repo_dir, exist_ok=True)
        
        # Clone repositories
        for repo_name, repo_url in self.repo_sources.items():
            if repo_name == 'otx':
                continue  # Handle OTX repository separately
            
            repo_dir = self.rules_dir / repo_name
            print(f"Processing repository: {repo_name} from {repo_url}")
            
            # Skip if already contains files (assuming already cloned)
            if repo_dir.exists() and any(repo_dir.iterdir()):
                print(f"Repository {repo_name} already exists and contains files")
            else:
                try:
                    print(f"Cloning {repo_name} repository...")
                    git.Repo.clone_from(repo_url, str(repo_dir), depth=1)
                    print(f"Successfully cloned {repo_name}")
                except Exception as e:
                    print(f"Error cloning with GitPython: {str(e)}")
                    try:
                        # Fallback to subprocess
                        print("Trying alternative cloning method...")
                        subprocess.run([
                            'git', 'clone', '--depth', '1', repo_url, str(repo_dir)
                        ], check=True)
                        print(f"Successfully cloned {repo_name} using subprocess")
                    except Exception as e2:
                        print(f"All cloning methods failed: {str(e2)}")
                        continue
        
        # Process rules from repositories
        rule_count = 0
        
        # This is the corrected loop - we iterate through items() and correctly unpack key/value
        for repo_name, repo_url in self.repo_sources.items():
            if repo_name == 'otx':
                continue
            
            repo_dir = self.rules_dir / repo_name
            if not repo_dir.exists():
                print(f"Repository directory {repo_dir} does not exist")
                continue
            
            # Find all YARA rule files in the repository
            yara_files = []
            for ext in ['*.yar', '*.yara']:
                yara_files.extend(list(repo_dir.glob(f'**/{ext}')))
            
            if not yara_files:
                print(f"No YARA rules found in {repo_name} repository")
                continue
            
            print(f"Found {len(yara_files)} YARA rules in {repo_name} repository")
            
            # Process each rule file
            for yara_file in yara_files:
                try:
                    # Read the rule content
                    with open(yara_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().lower()
                    
                    # Determine appropriate category based on content
                    if 'memory' in content or 'process' in content:
                        dest_dir = self.rules_dir / 'memory_rules'
                    elif 'shellcode' in content:
                        dest_dir = self.rules_dir / 'shellcode_rules'
                    elif 'inject' in content:
                        dest_dir = self.rules_dir / 'injection_rules'
                    elif any(kw in content for kw in ['malware', 'trojan', 'backdoor', 'exploit']):
                        dest_dir = self.rules_dir / 'malware_rules'
                    else:
                        dest_dir = self.rules_dir / 'custom_rules'
                    
                    # Create a unique destination filename
                    dest_file = dest_dir / f"{repo_name}_{yara_file.stem}.yar"
                    
                    # Copy the rule content
                    with open(yara_file, 'r', encoding='utf-8', errors='ignore') as src:
                        with open(dest_file, 'w', encoding='utf-8') as dst:
                            dst.write(f"// From {repo_name} repository: {yara_file.name}\n")
                            dst.write(src.read())
                    
                    rule_count += 1
                    print(f"Processed rule: {dest_file.name}")
                    
                except Exception as e:
                    print(f"Error processing rule {yara_file}: {str(e)}")
        
        print(f"Successfully processed {rule_count} rules from repositories")
        
        # Always create missing basic rules as fallback
        if rule_count == 0:
            self.create_missing_rules()
        
        return rule_count > 0
    def create_missing_rules(self):
        """Create YARA rules for categories that are missing them"""
        print("Creating rules for missing categories...")
        
        # Define the categories to check
        categories = ['injection_rules', 'malware_rules', 'custom_rules']
        
        # Basic rule templates for each category
        templates = {
            'injection_rules': """
    rule injection_basic_detection {
        meta:
            description = "Basic injection detection rule"
            author = "YaraRuleManager"
        strings:
            $api1 = "CreateRemoteThread" nocase
            $api2 = "VirtualAllocEx" nocase
            $api3 = "WriteProcessMemory" nocase
            $hex1 = { 68 ?? ?? ?? ?? }  // PUSH instruction
        condition:
            any of them
    }
    """,
            'malware_rules': """
    rule malware_basic_detection {
        meta:
            description = "Basic malware detection rule"
            author = "YaraRuleManager"
        strings:
            $mz = { 4D 5A }  // PE file header
            $str1 = "cmd.exe /c" nocase
            $str2 = "powershell -e" nocase
        condition:
            any of them
    }
    """,
            'custom_rules': """
    rule custom_basic_detection {
        meta:
            description = "Basic custom detection rule"
            author = "YaraRuleManager"
        strings:
            $str1 = "suspicious" nocase
            $str2 = "backdoor" nocase
            $hex1 = { 00 01 02 03 04 }
        condition:
            any of them
    }
    """,
            'otx_rules': """
    rule otx_basic_detection {
        meta:
            description = "Basic OTX detection rule"
            author = "YaraRuleManager"
        strings:
            $str1 = "otx" nocase
        condition:
            $str1
    }
    """,
            'neo23x0_rules': """
    rule neo23x0_basic_detection {
        meta:
            description = "Basic neo23x0 detection rule"
            author = "YaraRuleManager"
        strings:
            $str1 = "neo23x0" nocase
        condition:
            $str1
    }
    """,
            'fireeye_rules': """
    rule fireeye_basic_detection {
        meta:
            description = "Basic fireeye detection rule"
            author = "YaraRuleManager"
        strings:
            $str1 = "fireeye" nocase
        condition:
            $str1
    }
    """,
            'cape_rules': """
    rule cape_basic_detection {
        meta:
            description = "Basic CAPEv2 detection rule"
            author = "YaraRuleManager"
        strings:
            $str1 = "cape" nocase
        condition:
            $str1
    }
    """,
            'awesome_rules': """
    rule awesome_basic_detection {
        meta:
            description = "Basic awesome-yara detection rule"
            author = "YaraRuleManager"
        strings:
            $str1 = "awesome" nocase
        condition:
            $str1
    }
    """,
        }
        # Check each category and create rule if missing
        for category in categories:
            category_dir = self.rules_dir / category
            rule_files = list(category_dir.glob('*.yar*'))
            
            # If no rules found in this category
            if not rule_files:
                print(f"No rules found in {category} - creating basic rule")
                rule_file = category_dir / "basic_detection.yar"
                try:
                    with open(rule_file, 'w') as f:
                        f.write(templates[category])
                    print(f"Created rule file: {rule_file}")
                except Exception as e:
                    print(f"Error creating rule file {rule_file}: {str(e)}")
        
        print("Missing rules creation complete!")
        return True
    def _create_default_rules(self):
        """Create default YARA rules if no rules were found or processed"""
        logging.info("Creating default YARA rules...")
        
        default_rules = {
            'memory_rules': """
    rule default_memory_detection {
        meta:
            description = "Default rule for memory scanning"
            author = "YaraRuleManager"
        strings:
            $shellcode_pattern = { 55 8B EC }
            $process_injection = "VirtualAlloc"
        condition:
            any of them
    }
    """,
            'shellcode_rules': """
    rule default_shellcode_detection {
        meta:
            description = "Default rule for shellcode detection"
            author = "YaraRuleManager"
        strings:
            $nop_sled = { 90 90 90 90 90 }
            $shellcode = { 55 8B EC }
        condition:
            any of them
    }
    """,
            'injection_rules': """
    rule default_injection_detection {
        meta:
            description = "Default rule for code injection detection"
            author = "YaraRuleManager"
        strings:
            $api1 = "CreateRemoteThread" nocase
            $api2 = "VirtualAllocEx" nocase
            $api3 = "WriteProcessMemory" nocase
        condition:
            any of them
    }
    """,
            'malware_rules': """
    rule default_malware_detection {
        meta:
            description = "Default rule for basic malware detection"
            author = "YaraRuleManager"
        strings:
            $suspicious1 = "cmd.exe /c " nocase
            $suspicious2 = "powershell -e" nocase
            $suspicious3 = { 4D 5A }  // PE file header
        condition:
            any of them
    }
    """,
            'custom_rules': """
    rule default_custom_detection {
        meta:
            description = "Default custom rule"
            author = "YaraRuleManager"
        strings:
            $s1 = "suspicious" nocase
        condition:
            $s1
    }
    """
        }
        
        # Create default rules in each category
        for category, rule_content in default_rules.items():
            category_dir = self.rules_dir / category
            default_file = category_dir / "default_rule.yar"
            
            # Only create if directory is empty
            if not any(category_dir.glob('*.yar*')):
                try:
                    with open(default_file, 'w') as f:
                        f.write(rule_content)
                    logging.info(f"Created default rule in {category}")
                except Exception as e:
                    logging.error(f"Error creating default rule in {category}: {str(e)}")
    def create_repo_directories(self):
        """Explicitly create all repository directories with verbose logging"""
        print("=== Creating Repository Directories ===")
        self.rules_dir = getattr(self, 'rules_dir', Path('yara_rules'))
        # Make sure we're using a Path object
        if isinstance(self.rules_dir, str):
            self.rules_dir = Path(self.rules_dir)
        
        print(f"Base rules directory: {self.rules_dir}")
        
        # Create base directory
        try:
            os.makedirs(self.rules_dir, exist_ok=True)
            print(f"✓ Created base directory: {self.rules_dir}")
        except Exception as e:
            print(f"✗ Error creating base directory: {str(e)}")
        
        # Define repository sources if not already defined
        if not hasattr(self, 'repo_sources') or not self.repo_sources:
            self.repo_sources = {
                "awesome-yara": "https://github.com/InQuest/awesome-yara",
                "cape-sandbox": "https://github.com/kevoreilly/CAPEv2",
                "fireeye": "https://github.com/mandiant/red_team_tool_countermeasures",
                "otx": "https://github.com/xosski/OTX-Python-SDK",
                "neo23x0": "https://github.com/Neo23x0/signature-base"
            }
        
        # Create category directories
        for category in ['memory_rules', 'shellcode_rules', 'injection_rules', 'malware_rules', 'custom_rules']:
            category_dir = self.rules_dir / category
            try:
                os.makedirs(category_dir, exist_ok=True)
                print(f"✓ Created category directory: {category_dir}")
            except Exception as e:
                print(f"✗ Error creating category directory {category}: {str(e)}")
        
        # Create repository directories
        for repo_name, self.repo_url in self.repo_sources.items():
            repo_dir = self.rules_dir / repo_name
            try:
                os.makedirs(repo_dir, exist_ok=True)
                print(f"✓ Created repository directory: {repo_dir}")
                
                # Verify the directory exists
                if repo_dir.exists():
                    print(f"  ✓ Verified directory exists: {repo_dir}")
                else:
                    print(f"  ✗ Directory creation failed, path doesn't exist: {repo_dir}")
            except Exception as e:
                print(f"✗ Error creating repository directory {repo_name}: {str(e)}")
        
        print("=== Repository Directory Creation Complete ===")
        return True
    def create_basic_rules(self):
        """Create basic, guaranteed-to-compile YARA rules in all category directories"""
        print("Creating basic YARA rules for all categories...")
        
        # Basic template for valid YARA rules
        basic_rule_template = """
    rule {category}_basic_detection {{
        meta:
            description = "Basic detection rule for {category}"
            author = "YaraRuleManager"
            created = "{date}"
        
        strings:
            $str1 = "{pattern1}" nocase
            $str2 = "{pattern2}" nocase
            $hex1 = {{ {hex_pattern} }}
        
        condition:
            any of them
    }}
    """

        # Category-specific detection patterns
        patterns = {
            "memory_rules": {
                "pattern1": "VirtualAlloc", 
                "pattern2": "MemoryBasicInformation",
                "hex_pattern": "90 90 90 90 90" # NOP sled
            },
            "shellcode_rules": {
                "pattern1": "shellcode", 
                "pattern2": "payload",
                "hex_pattern": "55 8B EC" # Common x86 prologue
            },
            "injection_rules": {
                "pattern1": "CreateRemoteThread", 
                "pattern2": "WriteProcessMemory",
                "hex_pattern": "68 ?? ?? ?? ??" # PUSH instruction
            },
            "malware_rules": {
                "pattern1": "malware", 
                "pattern2": "trojan",
                "hex_pattern": "4D 5A 90 00" # PE header start
            },
            "custom_rules": {
                "pattern1": "suspicious", 
                "pattern2": "detection",
                "hex_pattern": "00 01 02 03 04" # Simple byte sequence
            }
        }
        
        current_date = datetime.now().strftime("%Y-%m-%d")
        
        # Create rules for each category
        for category, patterns_dict in patterns.items():
            # Ensure the directory exists
            category_dir = self.rules_dir / category
            os.makedirs(category_dir, exist_ok=True)
            
            # Generate rule content
            rule_content = basic_rule_template.format(
                category=category.replace("_rules", ""),
                date=current_date,
                pattern1=patterns_dict["pattern1"],
                pattern2=patterns_dict["pattern2"],
                hex_pattern=patterns_dict["hex_pattern"]
            )
            
            # Write to file
            rule_file = category_dir / "basic_detection.yar"
            try:
                with open(rule_file, "w") as f:
                    f.write(rule_content)
                print(f"Created rule file: {rule_file}")
            except Exception as e:
                print(f"Error creating rule file {rule_file}: {str(e)}")
                
        print("Basic rules creation complete!")
        return True
    def create_steam_whitelist(self):
        """Create YARA rules to whitelist legitimate Steam processes and files"""
        print("Creating Steam whitelist rules...")
        
        # Create whitelist directory if it doesn't exist
        whitelist_dir = self.rules_dir / "whitelist_rules"
        whitelist_dir.mkdir(exist_ok=True)
        
        # Steam whitelist rule content
        steam_whitelist_rule = """
    rule steam_whitelist_processes {
        meta:
            description = "Whitelist legitimate Steam processes and files"
            author = "YaraRuleManager"
            created = "{date}"
            category = "whitelist"
            
        strings:
            // Steam executable paths
            $steam_exe = "\\Steam\\steam.exe" nocase
            $steamclient_dll = "\\Steam\\steamclient.dll" nocase
            $steamclient64_dll = "\\Steam\\steamclient64.dll" nocase
            $steamservice_exe = "\\Steam\\bin\\steamservice.exe" nocase
            $steamwebhelper_exe = "\\Steam\\bin\\cef\\steamwebhelper.exe" nocase
            $steamerrorreporter_exe = "\\Steam\\steamerrorreporter.exe" nocase
            $steamtmp_exe = "\\Steam\\steamtmp.exe" nocase
            
            // Steam game executables and libraries
            $steam_game_path = "\\Steam\\steamapps\\common\\" nocase
            $steam_redistributable = "\\Steam\\steamapps\\redist\\" nocase
            $steam_workshop = "\\Steam\\steamapps\\workshop\\" nocase
            
            // Steam overlay and client components  
            $gameoverlayrenderer = "GameOverlayRenderer.dll" nocase
            $gameoverlayrenderer64 = "GameOverlayRenderer64.dll" nocase
            $steam_api = "steam_api.dll" nocase
            $steam_api64 = "steam_api64.dll" nocase
            
            // Steam update and installation processes
            $steamsetup_exe = "SteamSetup.exe" nocase
            $steam_updater = "\\Steam\\package\\tmp\\" nocase
            
            // Known Steam digital signatures
            $valve_corp_cert = "Valve Corporation" nocase
            $steam_digital_sig = "Steam" nocase and "Valve" nocase
            
        condition:
            any of them
    }

    rule steam_whitelist_network_activity {
        meta:
            description = "Whitelist legitimate Steam network connections"
            author = "YaraRuleManager"
            created = "{date}"
            category = "whitelist"
            
        strings:
            // Steam domain patterns
            $steam_domain1 = "steampowered.com" nocase
            $steam_domain2 = "steamcommunity.com" nocase  
            $steam_domain3 = "steamstatic.com" nocase
            $steam_domain4 = "steamcdn-a.akamaihd.net" nocase
            $steam_domain5 = "steamstore-a.akamaihd.net" nocase
            $steam_domain6 = "steamuserimages-a.akamaihd.net" nocase
            
            // Steam content delivery network
            $steam_cdn = "clientconfig.akamai.steamstatic.com" nocase
            $steam_content = "steamcontent.com" nocase
            
            // Steam API endpoints
            $steam_api_endpoint = "api.steampowered.com" nocase
            $steam_partner_api = "partner.steam-api.com" nocase
            
        condition:
            any of them
    }

    rule steam_whitelist_registry_keys {
        meta:
            description = "Whitelist legitimate Steam registry modifications"
            author = "YaraRuleManager"
            created = "{date}"
            category = "whitelist"
            
        strings:
            // Steam registry paths
            $steam_reg1 = "SOFTWARE\\\\Valve\\\\Steam" nocase
            $steam_reg2 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Steam" nocase
            $steam_reg3 = "SOFTWARE\\\\Classes\\\\steam" nocase
            $steam_reg4 = "SOFTWARE\\\\RegisteredApplications" nocase and "Steam" nocase
            
            // Steam URL protocol handlers
            $steam_protocol = "steam://" nocase
            $steam_url_handler = "URL:Steam Protocol" nocase
            
        condition:
            any of them
    }

    rule steam_whitelist_file_operations {
        meta:
            description = "Whitelist legitimate Steam file operations and locations"
            author = "YaraRuleManager"
            created = "{date}"
            category = "whitelist"
            
        strings:
            // Steam installation directories
            $steam_program_files = "\\\\Program Files\\\\Steam\\\\" nocase
            $steam_program_files_x86 = "\\\\Program Files (x86)\\\\Steam\\\\" nocase
            $steam_custom_path = "\\\\Steam\\\\" nocase
            
            // Steam configuration and data files
            $steam_config = "\\\\Steam\\\\config\\\\" nocase
            $steam_userdata = "\\\\Steam\\\\userdata\\\\" nocase
            $steam_logs = "\\\\Steam\\\\logs\\\\" nocase
            $steam_dumps = "\\\\Steam\\\\dumps\\\\" nocase
            
            // Steam cache and temporary files
            $steam_depotcache = "\\\\Steam\\\\depotcache\\\\" nocase
            $steam_appcache = "\\\\Steam\\\\appcache\\\\" nocase
            $steam_htmlcache = "\\\\Steam\\\\config\\\\htmlcache\\\\" nocase
            
            // Steam game content verification
            $steam_verify = "steam_verify" nocase
            $steam_validation = "steam_validation" nocase
            
        condition:
            any of them
    }

    rule steam_whitelist_processes_extended {
        meta:
            description = "Extended whitelist for Steam-related processes and services"
            author = "YaraRuleManager" 
            created = "{date}"
            category = "whitelist"
            
        strings:
            // Additional Steam processes
            $steam_monitor = "steammonitor.exe" nocase
            $steam_launcher = "steamlauncher.exe" nocase
            $steam_bootstrap = "steambootstrap.exe" nocase
            
            // Steam VR and additional components
            $steam_vr = "\\\\Steam\\\\steamapps\\\\common\\\\SteamVR\\\\" nocase
            $steam_vr_server = "vrserver.exe" nocase
            $steam_vr_monitor = "vrmonitor.exe" nocase
            
            // Steam Input and controller support
            $steam_controller = "steam_controller" nocase
            $steam_input = "steaminput" nocase
            
            // Steam streaming and remote play
            $steam_streaming = "streaming_client.exe" nocase
            $steam_remote_play = "steamremote" nocase
            
        condition:
            any of them
    }
    """.format(date=datetime.now().strftime("%Y-%m-%d"))
        
        # Write the Steam whitelist rule to file
        whitelist_file = whitelist_dir / "steam_whitelist.yar"
        try:
            with open(whitelist_file, 'w') as f:
                f.write(steam_whitelist_rule)
            print(f"Created Steam whitelist rule: {whitelist_file}")
            
            # Also create a companion JSON file with Steam process information
            steam_info_file = whitelist_dir / "steam_process_info.json"
            steam_process_info = {
                "legitimate_steam_processes": [
                    "steam.exe",
                    "steamservice.exe", 
                    "steamwebhelper.exe",
                    "steamerrorreporter.exe",
                    "steamtmp.exe",
                    "steamsetup.exe",
                    "steammonitor.exe",
                    "steamlauncher.exe",
                    "steambootstrap.exe",
                    "vrserver.exe",
                    "vrmonitor.exe",
                    "streaming_client.exe"
                ],
                "legitimate_steam_dlls": [
                    "steamclient.dll",
                    "steamclient64.dll", 
                    "GameOverlayRenderer.dll",
                    "GameOverlayRenderer64.dll",
                    "steam_api.dll",
                    "steam_api64.dll"
                ],
                "legitimate_steam_domains": [
                    "steampowered.com",
                    "steamcommunity.com",
                    "steamstatic.com", 
                    "steamcdn-a.akamaihd.net",
                    "steamstore-a.akamaihd.net",
                    "steamuserimages-a.akamaihd.net",
                    "clientconfig.akamai.steamstatic.com",
                    "steamcontent.com",
                    "api.steampowered.com",
                    "partner.steam-api.com"
                ],
                "legitimate_steam_paths": [
                    "\\Program Files\\Steam\\",
                    "\\Program Files (x86)\\Steam\\",
                    "\\Steam\\steamapps\\common\\",
                    "\\Steam\\steamapps\\redist\\",
                    "\\Steam\\steamapps\\workshop\\",
                    "\\Steam\\config\\",
                    "\\Steam\\userdata\\",
                    "\\Steam\\logs\\",
                    "\\Steam\\dumps\\",
                    "\\Steam\\depotcache\\",
                    "\\Steam\\appcache\\",
                    "\\Steam\\bin\\"
                ],
                "steam_registry_keys": [
                    "HKEY_CURRENT_USER\\SOFTWARE\\Valve\\Steam",
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Valve\\Steam", 
                    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Steam",
                    "HKEY_CLASSES_ROOT\\steam"
                ],
                "created": datetime.now().isoformat(),
                "description": "Whitelist information for legitimate Steam processes and components"
            }
            
            with open(steam_info_file, 'w') as f:
                json.dump(steam_process_info, f, indent=4)
            print(f"Created Steam process info file: {steam_info_file}")
            
            return True
            
        except Exception as e:
            print(f"Error creating Steam whitelist rules: {str(e)}")
            self.logger.error(f"Error creating Steam whitelist rules: {str(e)}")
            return False

    def load_whitelist_rules(self):
        """Load and compile whitelist rules separately from detection rules"""
        try:
            whitelist_dir = self.rules_dir / "whitelist_rules"
            if not whitelist_dir.exists():
                # Create Steam whitelist if it doesn't exist
                self.create_steam_whitelist()
            
            # Find all whitelist rule files
            whitelist_files = list(whitelist_dir.glob('*.yar')) + list(whitelist_dir.glob('*.yara'))
            
            if not whitelist_files:
                print("No whitelist rules found")
                return None
            
            # Compile whitelist rules
            filepaths = {}
            for rule_file in whitelist_files:
                namespace = f"whitelist_{rule_file.stem}"
                filepaths[namespace] = str(rule_file)
            
            # Define external variables for whitelist rules
            externals = {
                'filename': '',
                'filepath': '', 
                'process_name': '',
                'process_path': '',
                'filesize': 0,
                'is_executable': False
            }
            
            whitelist_rules = yara.compile(filepaths=filepaths, externals=externals)
            print(f"Successfully compiled {len(whitelist_files)} whitelist rules")
            
            return whitelist_rules
            
        except Exception as e:
            print(f"Error loading whitelist rules: {str(e)}")
            self.logger.error(f"Error loading whitelist rules: {str(e)}")
            return None

    def is_whitelisted_process(self, process_info):
        """Check if a process matches Steam whitelist criteria"""
        try:
            # Load whitelist rules if not already loaded
            if not hasattr(self, 'whitelist_rules'):
                self.whitelist_rules = self.load_whitelist_rules()
            
            if not self.whitelist_rules:
                return False
            
            # Prepare process data for YARA matching
            process_name = process_info.get('name', '').lower()
            process_path = process_info.get('exe', '') or process_info.get('path', '')
            
            # Create a test string containing process information
            test_data = f"{process_name} {process_path}".encode('utf-8', errors='ignore')
            
            # Set external variables
            externals = {
                'filename': process_name,
                'filepath': process_path,
                'process_name': process_name, 
                'process_path': process_path,
                'filesize': process_info.get('memory_info', {}).get('vms', 0),
                'is_executable': process_path.lower().endswith('.exe')
            }
            
            # Test against whitelist rules
            matches = self.whitelist_rules.match(data=test_data, externals=externals)
            
            if matches:
                print(f"Process {process_name} matched whitelist rules: {[m.rule for m in matches]}")
                return True
            
            return False
            
        except Exception as e:
            print(f"Error checking whitelist for process: {str(e)}")
            return False
    def is_whitelisted_process(self, process_info):
        """Check if a process matches Steam whitelist criteria"""
        try:
            # Load whitelist rules if not already loaded
            if not hasattr(self, 'whitelist_rules'):
                self.whitelist_rules = self.load_whitelist_rules()
            
            if not self.whitelist_rules:
                return False
            
            # Prepare process data for YARA matching
            process_name = process_info.get('name', '').lower()
            process_path = process_info.get('exe', '') or process_info.get('path', '')
            
            # Create a test string containing process information
            test_data = f"{process_name} {process_path}".encode('utf-8', errors='ignore')
            
            # Set external variables
            externals = {
                'filename': process_name,
                'filepath': process_path,
                'process_name': process_name, 
                'process_path': process_path,
                'filesize': process_info.get('memory_info', {}).get('vms', 0),
                'is_executable': process_path.lower().endswith('.exe')
            }
            
            # Test against whitelist rules
            matches = self.whitelist_rules.match(data=test_data, externals=externals)
            
            if matches:
                print(f"Process {process_name} matched whitelist rules: {[m.rule for m in matches]}")
                return True
            
            return False
            
        except Exception as e:
            print(f"Error checking whitelist for process: {str(e)}")
            return False
    def fetch_all_rules(self):
        """Fetch and load all YARA rules."""
        try:
            rules_directory = getattr(self, 'rules_directory', None)
            if not rules_directory:
                rules_directory = getattr(self, 'rules_dir', None)
            
            if not rules_directory:
                rules_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'yara_rules')
                self.rules_directory = rules_directory
                self.rules_dir = rules_directory
            
            # Create necessary subdirectories using os.path.join
            for subdir in ['memory_rules', 'shellcode_rules', 'injection_rules', 'malware_rules', 'custom_rules']:
                subdir_path = os.path.join(rules_directory, subdir)
                if not os.path.exists(subdir_path):
                    os.makedirs(subdir_path)
            
            # Search for existing rules
            rule_count = 0
            for subdir in ['memory_rules', 'shellcode_rules', 'injection_rules', 'malware_rules', 'custom_rules']:
                pattern = os.path.join(rules_directory, subdir, '*.yar')
                matched_files = glob.glob(pattern)
                rule_count += len(matched_files)
            
            # Create default rules if needed
            if rule_count == 0:
                # Create some default rules
                for subdir in ['memory_rules', 'shellcode_rules']:
                    subdir_path = os.path.join(rules_directory, subdir)
                    default_rule_path = os.path.join(subdir_path, 'default_rule.yar')
                    with open(default_rule_path, 'w') as f:
                        f.write("""
                        rule basic_shellcode_detection {
                            strings:
                                $nop_sled = { 90 90 90 90 90 }
                                $shellcode = { 55 8B EC }
                            condition:
                                any of them
                        }
                        """)
            # Skip network-based OTX rules fetch during initialization
            # Can be called manually later if needed
            # try:
            #     self.fetch_otx_rules()
            #     logging.info("OTX rules fetched successfully")
            # except Exception as e:
            #     logging.warning(f"Failed to fetch OTX rules: {str(e)}")
            
            self._rules_loaded = True
            return True
        except Exception as e:
            logging.error(f"Error fetching YARA rules: {str(e)}")
            self._rules_loaded = False
            return False
    def compile_combined_rules(self):
        """Compile all YARA rules from different categories into a single ruleset"""
        print("Compiling combined rules...")
        
        # Create a dictionary for different rule categories
        rule_categories = {
            "memory": os.path.join(self.rules_dir, "memory_rules"),
            "shellcode": os.path.join(self.rules_dir, "shellcode_rules"),
            "injection": os.path.join(self.rules_dir, "injection_rules"),
            "malware": os.path.join(self.rules_dir, "malware_rules"),
            "custom": os.path.join(self.rules_dir, "custom_rules")
        }
        
        # Dictionary to hold filepaths with their namespaces
        filepaths = {}
        total_rules = 0
        
        # Collect rule files from each category
        for category, directory in rule_categories.items():
            if not os.path.exists(directory):
                print(f"Rules directory not found: {directory}")
                continue
                
            print(f"Looking for {category} rules at {directory}/*.yar")
            rule_files = [f for f in glob.glob(os.path.join(directory, "*.yar")) if os.path.isfile(f)]
            
            if rule_files:
                print(f"Found {len(rule_files)} rules in category '{category}'")
                # Add each file with the category as namespace
                for rule_file in rule_files:
                    filename = os.path.basename(rule_file)
                    # Use category_filename as the namespace
                    namespace = f"{category}_{os.path.splitext(filename)[0]}"
                    filepaths[namespace] = rule_file
                    total_rules += 1
            else:
                print(f"No rules found in category '{category}'")
        
        # Compile rules with proper external variables
        if filepaths:
            print(f"\nCompiling {total_rules} YARA rules...")
            
            # Let's identify any external variables in the YARA rules first
            external_vars = set()
            for rule_path in filepaths.values():
                try:
                    with open(rule_path, 'r') as f:
                        content = f.read()
                        # Simple regex to find external variable declarations
                        for match in re.finditer(r'external\s+(\w+)', content):
                            external_vars.add(match.group(1))
                except Exception as e:
                    self.logger.error(f"Error reading rule file {rule_path}: {str(e)}")
            
            if external_vars:
                print(f"Found these external variables in rules: {', '.join(external_vars)}")
            
            try:
                # Define external variables with correct types
                # Include ALL found external variables with appropriate types
                externals = {}
                
                # Common external variables
                common_externals = {
                    'filename': '',      # string
                    'filepath': '',      # string
                    'extension': '',     # string
                    'filesize': 0,       # integer
                    'filepath_1': '',    # string
                    'filepath_2': '',    # string
                    'fullpath': '',      # string
                    'md5': '',           # string
                    'sha1': '',          # string
                    'sha256': '',        # string
                    'env': '',           # string
                    'filetype': '',      # string
                    'mime_type': '',     # string
                    'count': 0,          # integer
                    'offset': 0,         # integer
                    'is_executable': False, # boolean
                    'is_dll': False,     # boolean
                    'is_64bit': False,   # boolean
                    'timestamp': 0.0,    # float
                }
                
                # Add any found external variables to our externals dictionary
                for var in external_vars:
                    if var in common_externals:
                        externals[var] = common_externals[var]
                    else:
                        # Default to empty string for unknown variables
                        externals[var] = ''
                        print(f"Warning: Unknown external variable '{var}' found in rules, defaulting to string type")
                
                # Only include common variables that weren't already added
                for var, value in common_externals.items():
                    if var not in externals:
                        externals[var] = value
                
                # Debug: print all external variables we're using
                print(f"Using these external variables: {externals}")
                
                # Correct syntax for yara.compile with filepaths
                compiled_rules = yara.compile(filepaths=filepaths, externals=externals)
                print("YARA rules compiled successfully!")
                return compiled_rules
                
            except yara.Error as e:
                error_msg = f"Failed to compile YARA rules: {str(e)}"
                print(error_msg)
                self.logger.error(error_msg)
                
                # Try compiling each file individually to find problematic rules
                print("\nTrying to identify problematic rules:")
                valid_filepaths = {}
                for namespace, rule_path in filepaths.items():
                    print(f"Testing rule file: {namespace} ({rule_path})")
                    try:
                        rule_content = ""
                        with open(rule_path, 'r') as f:
                            rule_content = f.read()
                            
                        # Check for include statements that might fail
                        if 'include' in rule_content.lower():
                            # Check if any include statements reference missing files
                            include_matches = re.finditer(r'include\s+"([^"]+)"', rule_content)
                            has_missing_includes = False
                            for match in include_matches:
                                include_path = match.group(1)
                                # Check if it's a relative path
                                if include_path.startswith('./') or not os.path.isabs(include_path):
                                    # Try to resolve relative to the rule file
                                    resolved_path = os.path.join(os.path.dirname(rule_path), include_path)
                                    if not os.path.exists(resolved_path):
                                        print(f"  - SKIPPING: Missing include file {include_path}")
                                        has_missing_includes = True
                                        break
                            
                            if has_missing_includes:
                                continue
                            
                        # Look for external declarations
                        file_externals = set()
                        for match in re.finditer(r'external\s+(\w+)', rule_content):
                            file_externals.add(match.group(1))
                        
                        if file_externals:
                            print(f"  - Contains external variables: {', '.join(file_externals)}")
                        
                        # Try to compile just this rule
                        yara.compile(filepath=rule_path, externals=externals)
                        print(f"  - Rule compiles successfully")
                        valid_filepaths[namespace] = rule_path
                    except Exception as e:
                        print(f"  - ERROR in rule: {str(e)}")
                        self.logger.error(f"Error in rule file '{namespace}' at {rule_path}: {str(e)}")
                
                # Try compiling again with only valid rules
                if valid_filepaths:
                    print(f"\nRecompiling with {len(valid_filepaths)} valid rules...")
                    try:
                        compiled_rules = yara.compile(filepaths=valid_filepaths, externals=externals)
                        print("YARA rules compiled successfully!")
                        return compiled_rules
                    except Exception as e:
                        print(f"Still failed: {str(e)}")
                        return None
                
                return None
        else:
            print("No rules found to compile")
            return None

    def load_yara_rules(self):
        try:
            if isinstance(self.rules_dir, str):
                # Use os.path.join for strings
                self.rule_paths = {
                    'memory': os.path.join(self.rules_dir, 'memory_rules'),
                    'shellcode': os.path.join(self.rules_dir, 'shellcode_rules'),
                    'injection': os.path.join(self.rules_dir, 'injection_rules'),
                    'malware': os.path.join(self.rules_dir, 'malware_rules'),
                    'custom': os.path.join(self.rules_dir, 'custom_rules')
                }
            else:
                # Use / operator for Path objects
                self.rule_paths = {
                    'memory': str(self.rules_dir / 'memory_rules'),
                    'shellcode': str(self.rules_dir / 'shellcode_rules'),
                    'injection': str(self.rules_dir / 'injection_rules'),
                    'malware': str(self.rules_dir / 'malware_rules'),
                    'custom': str(self.rules_dir / 'custom_rules')
                }
            
            
        except Exception as e:
            self.logger.error(f"Error loading YARA rules: {str(e)}")
            print(f"Error loading YARA rules: {str(e)}")
        
        return self.compile_combined_rules()
    def are_rules_loaded(self):
        """Check if YARA rules are actually loaded"""
        if not hasattr(self, 'rules_dir'):
            return False
        
        # Check all category directories for rule files
        rule_count = 0
        for category in ['memory_rules', 'shellcode_rules', 'injection_rules', 'malware_rules', 'custom_rules']:
            category_dir = self.rules_dir / category
            if category_dir.exists():
                rule_files = list(category_dir.glob('*.yar')) + list(category_dir.glob('*.yara'))
                rule_count += len(rule_files)
        
        # Also check if compiled rules exist
        has_compiled = hasattr(self, 'combined_rules') and self.combined_rules is not None
        
        # Set and return the loading status
        self._rules_loaded = rule_count > 0 and has_compiled
        return self._rules_loaded
    def generate_runtime_key(self):
        # Generate puzzle components first
        puzzle_key = self.generate_puzzle_components()
        
        # Enhanced base components with biblical reference
        base_parts = [
            bytes([ord(c) ^ 0x42]) for c in [
                chr(x ^ 0x37) for x in [74, 101, 115, 117, 115, 32, 67, 104, 114, 105, 115, 116]
            ]
        ]
        
        static_parts = [
            int(self.static_hash[i:i+8], 16) ^ 0xF0F0F0F0
            for i in range(0, len(self.static_hash), 8)
        ]
        
        # Incorporate puzzle solution into runtime assembly
        time_seed = sum(map(int, datetime.now().strftime("%H%M%S")))
        runtime_key = sum(static_parts) ^ time_seed ^ int(puzzle_key[:16], 16)
        
        assembled = bytes(x ^ y for x, y in zip(
            b''.join(base_parts),
            runtime_key.to_bytes(32, 'big')
        ))
        
        # Include puzzle verification in final hash
        return hashlib.sha512(assembled + puzzle_key.encode()).hexdigest()
    def fetch_otx_rules(self):
        """Fetch OTX (Open Threat Exchange) YARA rules and threat indicators"""
        try:
            # Convert to pathlib Path if needed
            if isinstance(self.rules_dir, str):
                from pathlib import Path
                rules_dir_path = Path(self.rules_dir)
            else:
                rules_dir_path = self.rules_dir
                
            otx_dir = rules_dir_path / "otx"
            otx_dir.mkdir(exist_ok=True)
            
            # Fetch OTX YARA rules from a proper YARA rules repository
            # Using a community YARA rules repo that includes OTX-style rules
            otx_yara_repo = 'https://github.com/YARA-Rules/rules'
            yara_rules_dir = otx_dir / "yara-rules"
            
            if not (yara_rules_dir / ".git").exists():
                try:
                    subprocess.run([
                        'git', 'clone',
                        '--depth', '1',
                        otx_yara_repo,
                        str(yara_rules_dir)
                    ], check=True, capture_output=True, text=True, timeout=30)
                    logging.info(f"Successfully cloned OTX YARA rules to {yara_rules_dir}")
                except subprocess.TimeoutExpired:
                    logging.warning("OTX YARA rules clone timed out after 30 seconds")
                    return
                except subprocess.CalledProcessError as e:
                    logging.warning(f"Failed to clone OTX YARA rules: {e}")
                    return
            else:
                # Update existing repository
                try:
                    subprocess.run(['git', 'pull'], cwd=str(yara_rules_dir), check=False, capture_output=True, timeout=15)
                    logging.debug("Updated OTX YARA rules repository")
                except subprocess.TimeoutExpired:
                    logging.debug("OTX rules update timed out")
                except Exception as e:
                    logging.debug(f"Failed to update OTX rules: {str(e)}")
            
            # Process YARA files and copy relevant ones to our structure
            if not hasattr(self, '_otx_rules_processed'):
                otx_rules_count = 0
                
                # Look for YARA files in the downloaded repository
                problematic_rules = ['ip.yar']  # Rules with known compilation issues
                
                for yara_file in yara_rules_dir.glob('**/*.yar*'):
                    if yara_file.is_file() and yara_file.stat().st_size > 0:
                        # Skip known problematic rules
                        if yara_file.name in problematic_rules:
                            logging.debug(f"Skipping known problematic rule: {yara_file.name}")
                            continue
                            
                        try:
                            # Test if the rule compiles
                            yara.compile(str(yara_file))
                            
                            # Copy useful rules to our malware_rules directory
                            target_dir = rules_dir_path / "malware_rules"
                            target_dir.mkdir(exist_ok=True)
                            
                            # Use a prefix to identify OTX rules
                            target_file = target_dir / f"otx_{yara_file.name}"
                            
                            # Only copy if not already present
                            if not target_file.exists():
                                import shutil
                                shutil.copy2(yara_file, target_file)
                                otx_rules_count += 1
                                logging.debug(f"Copied OTX YARA rule: {yara_file.name}")
                                
                        except Exception as e:
                            logging.debug(f"Skipping invalid OTX rule file {yara_file}: {str(e)}")
                
                self._otx_rules_processed = True
                logging.info(f"Processed {otx_rules_count} OTX YARA rules")
            
            # Create local threat indicators file with basic IOCs
            self._create_basic_threat_indicators(otx_dir)
            
            # Mark as completed
            if not hasattr(self, '_otx_fetched'):
                self._otx_fetched = True
                
        except Exception as e:
            logging.error(f"Error in fetch_otx_rules: {str(e)}")
            
    def _create_basic_threat_indicators(self, otx_dir):
        """Create basic threat indicators file"""
        try:
            indicators_file = otx_dir / "threat_indicators.json"
            if not indicators_file.exists():
                basic_indicators = [
                    {
                        "type": "hash",
                        "value": "d41d8cd98f00b204e9800998ecf8427e",
                        "description": "Empty file MD5 (suspicious)",
                        "threat_type": "suspicious_file"
                    },
                    {
                        "type": "domain", 
                        "value": "malicious-domain.example",
                        "description": "Example malicious domain",
                        "threat_type": "c2_domain"
                    }
                ]
                
                with open(indicators_file, 'w') as f:
                    json.dump(basic_indicators, f, indent=2)
                    
                logging.debug(f"Created basic threat indicators file: {indicators_file}")
        except Exception as e:
            logging.debug(f"Failed to create threat indicators: {str(e)}")
    def verify_rules_loaded(self):
        """Verify YARA rules are properly loaded and return detailed status"""
        report = {
            "directories_exist": True,
            "rule_files_exist": False,
            "rule_files_count": 0,
            "compilation_success": False,
            "error_message": None
        }
        
        try:
            # Check directories (including OTX)
            categories = ['memory_rules', 'shellcode_rules', 'injection_rules', 'malware_rules', 'custom_rules', 'otx']
            for category in categories:
                if isinstance(self.rules_dir, str):
                    from pathlib import Path
                    rules_dir_path = Path(self.rules_dir)
                else:
                    rules_dir_path = self.rules_dir
                    
                category_dir = rules_dir_path / category
                if not category_dir.exists():
                    report["directories_exist"] = False
                    report["error_message"] = f"Directory missing: {category_dir}"
                    return report
            
            # Check for rule files (including OTX rules)
            rule_count = 0
            for category in ['memory_rules', 'shellcode_rules', 'injection_rules', 'malware_rules', 'custom_rules']:
                category_dir = rules_dir_path / category
                rule_files = list(category_dir.glob('*.yar')) + list(category_dir.glob('*.yara'))
                rule_count += len(rule_files)
                
            # Also count OTX rules
            otx_dir = rules_dir_path / "otx" / "yara-rules"
            if otx_dir.exists():
                otx_rule_files = list(otx_dir.glob('**/*.yar*'))
                rule_count += len(otx_rule_files)
            
            report["rule_files_count"] = rule_count
            report["rule_files_exist"] = rule_count > 0
            
            if rule_count == 0:
                report["error_message"] = "No rule files found in any category"
                return report
            
            # Check compilation
            try:
                self.combined_rules = self.compile_combined_rules()
                report["compilation_success"] = self.combined_rules is not None
                
                if not report["compilation_success"]:
                    report["error_message"] = "Rules compilation failed"
            except Exception as e:
                report["compilation_success"] = False
                report["error_message"] = f"Error during compilation: {str(e)}"
            
            return report
        
        except Exception as e:
            report["error_message"] = f"Error during verification: {str(e)}"
            return report
    def generate_puzzle_components(self):
        # Biblical reference encoded in hex pairs
        biblical_hex = bytes([
            0x4a, 0x6f, 0x68, 0x6e, 0x33, 0x3a, 0x31, 0x36,
            0x52, 0x65, 0x76, 0x32, 0x31, 0x3a, 0x36
        ])
        
        # Mathematical sequence with significance
        sequence = [7, 12, 19, 23, 42, 77, 144, 365]
        
        # Encoded coordinates pointing to meaningful location
        coordinates = [31.7767, 35.2345]
        
        # Time-based rotation using significant dates
        rotation_key = sum(map(int, datetime.now().strftime("%d%m")))
        
        return self.encode_challenge(biblical_hex, sequence, coordinates, rotation_key)

    def encode_challenge(self, biblical, sequence, coords, rotation):
        # Layer 1: Biblical cipher
        layer1 = bytes([b ^ (rotation % 256) for b in biblical])
        
        # Layer 2: Mathematical progression with proper byte range
        layer2 = bytes([
            ((s * rotation) ^ (i * 0x42)) % 256
            for i, s in enumerate(sequence)
        ])
        
        # Layer 3: Geographic coordinates
        layer3 = struct.pack('dd', *coords)
        
        combined = hashlib.sha512(layer1 + layer2 + layer3).digest()
        
        key_parts = []
        for i in range(8):
            part = hashlib.sha256(combined[i*8:(i+1)*8]).hexdigest()[:8]
            key_parts.append(part)
        
        return ''.join(key_parts)

    def verify_solution(attempt, challenge):
        # Verification steps for each layer
        verification = hashlib.sha512(attempt.encode()).hexdigest()
        if verification.startswith(challenge[:32]):
            # Generate API key from verified solution
            key_base = hashlib.sha512(verification.encode()).digest()
            return base64.b85encode(key_base).decode()[:64]
        return None
    def test_otx_connection(self):
        try:
            headers = {
                'X-OTX-API-KEY': 'Insert API Key',
                'Accept': 'application/json'
            }
            threat_url = "https://otx.alienvault.com/api/v1/pulses/6733cb23929b42dfad4f5712"
            
            logging.debug("Testing OTX API connection with correct endpoint...")
            response = requests.get(threat_url,headers=headers)
            
            if response.status_code == 200:
                logging.debug("OTX API connection successful with valid response")
                return True
            else:
                logging.debug(f"OTX API connection failed - Status: {response.status_code}")
                logging.debug(f"Response content: {response.text}")
                return False
        except Exception as e:
            logging.debug(f"OTX API connection error: {str(e)}")
            return False
    
    def analyze_threat_indicators(self, activity):
        """Process threat indicators from OTX activity data"""
        indicators_dir = self.rules_dir / "threat_indicators"
        indicators_dir.mkdir(exist_ok=True)
        
        threat_types = {
            'FileHash-MD5': 'hashes',
            'FileHash-SHA1': 'hashes',
            'FileHash-SHA256': 'hashes',
            'URL': 'urls',
            'Domain': 'domains',
            'IPv4': 'ips',
            'IPv6': 'ips',
            'YARA': 'yara'
        }
        
        for indicator in activity.get('indicators', []):
            indicator_type = indicator.get('type')
            if indicator_type in threat_types:
                category = threat_types[indicator_type]
                indicator_file = indicators_dir / f"{category}.txt"
                
                with open(indicator_file, 'a') as f:
                    if category == 'yara':
                        f.write(f"# {activity['name']}\n{indicator['content']}\n\n")
                    else:
                        f.write(f"{indicator['indicator']}\n")
                
                print(f"Added {indicator_type} indicator from: {activity['name']}")