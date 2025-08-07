# 🤝 Contributing to OFSP

> “This isn’t just code. It’s architecture for truth reconstruction.”

Welcome, operator.  
Whether you’re submitting a pull request, refining YARA rules, or just fixing a typo — you’re helping push the edge of forensic visibility forward.

This document outlines how to contribute to the **Orbital Foundation Systems Platform (OFSP)** repository.

---

## ⚙️ How to Contribute

### 🛠 1. Fork the Repository

Click "Fork" in the upper right corner of [https://github.com/xosski/OFSP](https://github.com/xosski/OFSP) to create your own working copy.

```bash
git clone https://github.com/<your-username>/OFSP.git
cd OFSP
Creating a Feature or Fix Branch
git checkout -b your-feature-name
Be descriptive. Avoid patch-1. Try memory-force-read-enhancement or yara-rule-cleanup.

💻 3. Make Your Changes
Follow these principles:

Maintain readability and modular design.

Avoid obfuscation — logs must outlive you.

Comment any experimental code.

Do not introduce commercial, proprietary, or telemetry libraries.

🧪 4. Test Before You Submit
Make sure your feature:

Doesn’t break GUI launch

Doesn’t crash Weapons_Systems.py

Logs errors gracefully

📬 Submitting Pull Requests
Once you're ready:
git commit -am "Add feature: shellcode detection in guarded memory"
git push origin your-feature-name
Then open a Pull Request on GitHub.

In your PR description:

Briefly describe what you changed

Link to any related issues

Tag it if experimental ([EXPERIMENTAL], [UI], [MEMORY])

🧾 YARA Rule Contributions
Use lowercase snake_case filenames (remote_code_exec.yar)

Separate by category inside /yara_rules/

Test rule compilation locally:
yara your_rule.yar sample_file.exe
Avoid duplicates of existing community rules

Annotate the rule with a comment header:
// Rule: Shellcode inside obfuscated RTFs
// Author: your-alias
// Source: maldoc report, 2025


---

## 🚫 Code of Conduct

- Respect other contributors
- Avoid ego-patching
- Do not submit commercial payloads, ransomware samples, or direct malware binaries
- This is a research and defensive project — not an attack framework

---

## 🛑 Commercial Use Reminder

OFSP is licensed under a **non-commercial license**.  
Private use is welcome. Corporate deployment requires explicit permission.

> See [LICENSE](./LICENSE) for full details.

---

## 🧭 Need Help? Contact the Architect

If you're lost in the architecture, reach out:

- **X:** [@xosski](https://x.com/xosski)
- **Telegram:** [@GhostOpNode000](https://t.me/GhostOpNode000)
- **Email:** ek3908728@gmail.com

---

> “If you’re reading this, you are part of the audit trail.”  
> The logs remember. So contribute something worth logging.