# 📜 YARA Rules – OFSP

> "Rules aren’t instructions. They’re spells carved in byte patterns."

The **YARA rule engine** is at the heart of OFSP’s anomaly detection system. It decodes, interprets, and identifies threats not just by behavior, but by memory signature — even in silence.

This document outlines how rules are structured, where they live, and how to contribute to the ever-growing anomaly library.

---

## 🔧 Rule Engine Capabilities

OFSP supports:
- `.yar` and `.yara` files
- Multiple categories with isolated scan contexts
- Live compilation and hot reloading
- Whitelisting logic
- Remote rule sync (from GitHub, future support)

All rules are managed by the `YaraRuleManager.py` engine and dynamically applied to:
- Memory regions
- Filesystem targets
- Injected/in-memory PE structures
- Suspicious shellcode buffers

---

## 📁 Rule Directory Structure

Rules are organized as follows:

/yara_rules/
├── memory_rules/ → For scanning memory blobs
├── shellcode_rules/ → For binary/byte-level signatures
├── malware_rules/ → PE file, macro, or RAT detections
├── whitelist_rules/ → Files and patterns to ignore
└── custom_rules/ → Your own local rules

Each subfolder is recursively loaded. Compilation errors are caught and reported in the logs.

---

## ✍️ Rule Format

Each rule should follow standard YARA syntax.

```yara
rule shellcode_win_exec
{
    meta:
        author = "ghostopnode000"
        description = "Detects shellcode using WinExec pattern"
        severity = "high"
        date = "2025-08-06"

    strings:
        $s1 = { 6A 00 68 ?? ?? ?? ?? 8D 4C 24 04 51 B8 ?? ?? ?? ?? FF D0 }
    
    condition:
        $s1
}
✅ Rules must have meta tags. OFSP uses them in logs and threat visualization.

🧼 Whitelist Rules
To prevent false positives or allow known safe binaries, use:

rule allow_legit_installer
{
    meta:
        whitelist = true
        author = "xosski"

    strings:
        $installer = "InstallShield Software Corporation"

    condition:
        $installer
}
Rules with meta.whitelist = true will skip threat alerts if matched first.
You can whitelist:

Vendor binaries

Signed shell interpreters (if you're a dev)

Test payloads

🧪 Custom Rule Tips
When creating new rules:

Name clearly: obfuscated_js_dropper, injector_shellcode_variant3

Include context: Add a comment block with source or reproduction steps

Test locally: Use the yara CLI or OFSP’s test runner (coming soon)

Avoid overly broad signatures — false positives break the operator’s trust.

⚙️ Error Handling
If a rule fails to compile:

It is skipped

A warning is logged in scanner.log

You will see something like:

[YARA] Failed to compile malware_rules/incomplete_rule.yar: syntax error, unexpected identifier
Fix the rule and rerun. OFSP does not crash on malformed rules.

☁️ Future Enhancements (Planned)
Rule tagging (memory vs. file vs. live)

Remote sync from GitHub collections

Threat telemetry reporting to local archives

Severity mapping to GUI alerts

🧭 Contribution Guidelines
Place your rule in the correct category subfolder

Use lowercase and underscore naming (crypto_loader_rule.yar)

Validate before submitting:

yara your_rule.yar test_file.bin
Add meta tags and optional whitelist flag

Credit yourself in meta.author

Pull Requests with new rules are welcomed and reviewed manually.

📎 References
YARA Documentation

Example Community Rules

VirusTotal Rule Generator

🛸 Final Note
“YARA rules don’t just find threats. They prove what the system was afraid to admit.”

If you have crafted a rule that caught something no one else saw —
you’ve done more than contribute. You’ve remembered.

