🛰️ Orbital Station UI — GhostCore Forensics Shell

“The GUI is just the portal. The engine is what listens when ghosts knock twice.”

⚙️ Overview

OrbitalStationUI is a fully-integrated memory forensics and process analysis suite built with PySide6. It anchors multiple backend modules—memory scanners, YARA rule managers, shellcode analysis tools, and more—into a unified threat hunting environment.

This toolkit is designed for offensive security researchers, incident responders, and metaphysical protocol engineers operating in hybrid cyber-realms.

🌌 Core Features

🧠 Memory Scanner: Deep analysis of memory regions for shellcode, injection artifacts, and entropy anomalies.

🪞 Process Monitor: Live process enumeration, suspicious pattern detection, and behavioral scanning.

📜 YARA Rule Engine: Dynamic rule compilation, hot-reload support, whitelist rules, and custom category scanning.

🧬 Shellcode Tome: Store, retrieve, and analyze shellcode fragments with historical tracing and NOP sled detection.

🛡️ Weapon Systems: Kernel-level process attribute extraction and system integrity checks.

🧪 Test Framework: test_tome_shellcode.py allows shellcode storage verification.

📂 Modular Design: Backend modules like Memory.py, YaraRuleManager.py, and ShellCodeMagic.py are self-contained and reusable.

🔩 Architecture Map
📁 OrbitalStationUI
│
├── OrbitalStationUI_Complete.py     # Main GUI
├── Memory.py                        # Memory scanning core
├── Weapons_Systems.py              # Kernel process introspection
├── ShellCodeMagic.py               # Shellcode detection + entropy tools
├── YaraRuleManager.py              # Rule engine and repository sync
├── test_tome_shellcode.py          # Validation for shellcode storage
├── YARA-Rules–OFSP.md              # Rule development guide

🚀 Launch Instructions

Install Requirements:

pip install -r requirements.txt


Start the UI:

python OrbitalStationUI_Complete.py


(Optional) Test Shellcode System:

python test_tome_shellcode.py

🧠 YARA Rule Structure

Rules are located in ./yara_rules/ and include:

memory_rules/

shellcode_rules/

injection_rules/

malware_rules/

whitelist_rules/

custom_rules/

You can add .yar or .yara files to any folder and they’ll be hotloaded. Compilation failures will be logged, not fatal.

💾 Quarantine System

Any memory region or process that exceeds defined thresholds (default: 75 risk) is automatically stored in ./memory_quarantine/.

🧙 Contribution Philosophy

Rules aren’t instructions—they’re spells carved in byte patterns. If you're writing or modifying rules, aim for surgical precision. False positives break trust.

💸 Donate to Support the Project

If this tool helped you ghostwalk past a detection system or kept the shadows at bay:

👉 Support via Stripe

Your donations go directly toward time-loop stabilization and keeping the Lazarus Drive online.

🛸 Welcome to the GhostCore Era

The pen is still in your hand.
The log is still recording.
And they haven’t yet realized:
You’re not the NPC.