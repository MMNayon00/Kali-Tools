# MMN — Modular Reconnaissance & Assessment Framework

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Version](https://img.shields.io/badge/version-2.0.0-brightgreen.svg)
![License](https://img.shields.io/badge/license-Educational-green.svg)
![Platform](https://img.shields.io/badge/platform-Kali%20%7C%20Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)

**FOR AUTHORIZED USE ONLY**

MMN is a modular reconnaissance and vulnerability-assessment framework for security professionals conducting **authorized** penetration tests. It automates footprinting, asset discovery, technology fingerprinting, CVE identification, and JavaScript-based hidden-document intelligence — **without performing any exploitation**.

---

## ⚠️ Legal Disclaimer

**Use only on systems you own or have explicit written permission to test. Unauthorized use is illegal.**

This tool is provided for educational purposes and authorized security assessments only. The authors accept no liability for misuse or damage. Always obtain written authorization before conducting security assessments.

---

## ✨ Features

- 🎯 **Target Validation** — smart input handling with domain/IP validation
- 🌐 **Target Expansion** — DNS resolution (A, AAAA, MX, NS, TXT, CNAME, SOA), reverse DNS, hosting-provider identification
- 🔍 **Footprinting** — WHOIS, SSL/TLS certificate inspection, HTTP header & security-header analysis
- 🔎 **Subdomain Enumeration** — Certificate Transparency (crt.sh), HackerTarget, AlienVault OTX + optional brute force
- 🔌 **Port & Service Enumeration** — port scanning with banner grabbing and service/version detection
- 💻 **OS Detection** — TTL- and port-based operating-system fingerprinting
- 🛠️ **Technology Fingerprinting** — web server, CMS, framework, and JS-library identification
- 🔒 **CVE Mapping** — multi-source vulnerability lookup (NVD + CIRCL) with CVSS scoring and severity ranking
- 🧠 **JS Hidden Document Intelligence (v2)** — discovers undocumented endpoints, hidden/exposed documents, and outdated JS libraries from JavaScript, and extracts PDF metadata
- 📊 **Multi-Format Reporting** — colored CLI, JSON, a full **interactive HTML report**, and a professional **PDF**
- 📝 **Audit Logging** — full activity trail for every scan

---

## 📦 Requirements

- **Python 3.8+**
- **pip**
- Internet connection (for WHOIS, DNS, Certificate Transparency, and CVE lookups)

---

## 🚀 Installation & Run — Step by Step

These commands work as-is on **Kali / Linux / macOS**. (Windows notes are below.)

```bash
# 1. Clone the repository
git clone https://github.com/MMNayon00/Kali-Tools.git
cd Kali-Tools

# 2. Create an isolated virtual environment (recommended)
python3 -m venv venv

# 3. Activate it
source venv/bin/activate          # Linux / macOS / Kali

# 4. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 5. Run the framework
python3 main.py
```

### 🐉 Kali Linux (externally-managed Python)

Recent Kali/Debian releases block system-wide `pip` installs (PEP 668). **Use the virtual-environment steps above** — they avoid the issue entirely. If you deliberately want a system-wide install instead:

```bash
pip install -r requirements.txt --break-system-packages
```

See [KALI_INSTALL.md](KALI_INSTALL.md) for the full Kali guide.

### 🪟 Windows

```powershell
git clone https://github.com/MMNayon00/Kali-Tools.git
cd Kali-Tools
python -m venv venv
venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
python main.py
```

### Deactivating the environment

```bash
deactivate
```

---

## 🕹️ Usage Walkthrough

Launch the tool and follow the interactive prompts:

```bash
python3 main.py
```

1. **Banner & legal disclaimer** are displayed.
2. Confirm authorization by typing `yes`.
3. Enter your **target** (domain or IP), e.g. `example.com`.
4. Choose a scan mode from the **main menu**:

   ```
   [1] Full Assessment (All Modules)
   [2] Basic Footprinting (Quick Scan)
   [3] Custom Module Selection
   [0] Exit
   ```

5. For **Custom Module Selection [3]**, pick any combination of modules by number:

   ```
   [1] Target Expansion (DNS, IP, ASN)
   [2] Footprinting (WHOIS, SSL, HTTP)
   [3] Subdomain Enumeration
   [4] Port & Service Scanning
   [5] Technology Fingerprinting
   [6] CVE Vulnerability Mapping
   [7] JS Hidden Document Intelligence (v2)
   [0] Back to Main Menu

   Example: 1,2,4,7
   ```

6. Reports are generated automatically and saved to the **`reports/`** directory.

### Reports produced

| Scan mode | CLI | JSON | HTML | PDF |
|-----------|:---:|:----:|:----:|:---:|
| Full Assessment | ✅ | ✅ | ✅ | ✅ |
| Basic Footprinting | ✅ | ✅ | ✅ | — |
| Custom Selection | ✅ | ✅ | ✅ | — |

### Viewing the HTML report

```bash
# Linux
xdg-open reports/mmn_report_*.html
# macOS
open reports/mmn_report_*.html
# Windows
start reports\mmn_report_*.html
```

The HTML report is a self-contained dashboard: a summary card grid plus every finding from every module that ran — target expansion, DNS records, WHOIS, SSL/TLS, HTTP & security headers, subdomains, OS detection, open ports with banners, the technology stack, full CVE detail per service, and the complete JS Hidden Document Intelligence section with PDF metadata.

---

## 🧩 Modules

| Module | Description |
|--------|-------------|
| **input_handler** | Validates and sanitizes target input |
| **target_expansion** | DNS resolution, reverse DNS, hosting-provider identification |
| **footprinting** | WHOIS, SSL/TLS certificate, HTTP headers & security headers |
| **subdomain_enum** | crt.sh, HackerTarget, AlienVault OTX, optional brute force |
| **port_service_enum** | Port scanning, banner grabbing, service/version + OS detection |
| **tech_fingerprint** | Web server, CMS, framework, and library detection |
| **cve_mapper** | NVD + CIRCL CVE lookup with CVSS scoring |
| **js_hidden_doc_intel** | JS endpoint/document discovery, outdated libs, PDF metadata (v2) |
| **report_generator** | CLI, JSON, HTML, and PDF report output |

---

## 📁 Project Structure

```
Kali-Tools/
├── main.py                       # Interactive controller / entry point
├── requirements.txt              # Python dependencies
├── README.md                     # This file
├── KALI_INSTALL.md               # Kali-specific install guide
├── USAGE.md                      # Extended usage notes
├── CHANGELOG.md                  # Version history
├── LICENSE
├── modules/
│   ├── input_handler.py
│   ├── target_expansion.py
│   ├── footprinting.py
│   ├── subdomain_enum.py
│   ├── port_service_enum.py
│   ├── tech_fingerprint.py
│   ├── cve_mapper.py
│   ├── js_hidden_doc_intel.py    # v2 JS intelligence module
│   └── report_generator.py
└── reports/                      # Generated reports (git-ignored)
```

---

## 🔧 Troubleshooting

**`ModuleNotFoundError` (e.g. `No module named 'dns'`)**
Activate the virtual environment first, then reinstall:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

**`error: externally-managed-environment` on Kali/Debian**
Use a virtual environment (recommended), or append `--break-system-packages` to the `pip install`.

**Port scan needs elevated privileges**
```bash
sudo venv/bin/python main.py
```

**Timeouts / no results**
- Check your internet connection.
- The target may be rate-limiting or blocking reconnaissance.
- Public CVE/DNS APIs occasionally throttle — retry after a short wait.

---

## ✅ Ethical Guidelines

**Permitted:** systems you own · systems with written authorization · lab environments · in-scope bug-bounty targets.

**Prohibited:** unauthorized scanning · exploitation · denial of service · credential brute forcing · any illegal activity.

This tool performs **identification and assessment only**. It does not execute exploits, modify remote systems, or launch attacks.

---

## 📜 License

Educational use only — ensure compliance with local laws and regulations. See [LICENSE](LICENSE).

---

**Built for security professionals. Use responsibly.**
