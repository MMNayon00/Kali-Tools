# MMN Quick Start Guide

## Installation

1. **Install Dependencies**
   ```bash
   # Create virtual environment (recommended)
   python3 -m venv venv
   source venv/bin/activate  # On macOS/Linux
   # or
   venv\Scripts\activate  # On Windows
   
   # Install required packages
   pip install -r requirements.txt
   ```

2. **Verify Installation**
   ```bash
   python3 main.py
   ```

## Usage

### Basic Execution
```bash
python3 main.py
```

Upon startup, you will see:
1. **MMN Banner** - Large ASCII art logo
2. **Legal Disclaimer** - Authorization warning
3. **Authorization Prompt** - Confirm you have permission
4. **Target Input** - Enter IP or domain to scan

### Main Menu Options

**[1] Full Assessment**
- Runs all modules in sequence
- Most comprehensive scan
- Generates complete reports
- Recommended for thorough reconnaissance

**[2] Basic Footprinting**
- Quick target analysis
- Target expansion + footprinting only
- Fast results for initial assessment

**[3] Custom Module Selection**
- Choose specific modules to run
- Enter comma-separated numbers (e.g., 1,2,4)
- Flexible for targeted reconnaissance

**[0] Exit**
- Safely exit the program

### Module Descriptions

| # | Module | Description |
|---|--------|-------------|
| 1 | Target Expansion | DNS resolution, IP discovery, ASN identification |
| 2 | Footprinting | WHOIS, SSL/TLS certificates, HTTP headers |
| 3 | Subdomain Enumeration | Certificate Transparency, passive discovery |
| 4 | Port & Service Scanning | Rate-limited port scan with service detection |
| 5 | Technology Fingerprinting | Web server, CMS, framework identification |
| 6 | CVE Mapping | Vulnerability database lookup with CVSS scores |

## Example Session

```
$ python3 main.py

███╗   ███╗███╗   ███╗███╗   ██╗
████╗ ████║████╗ ████║████╗  ██║
██╔████╔██║██╔████╔██║██╔██╗ ██║
██║╚██╔╝██║██║╚██╔╝██║██║╚██╗██║
██║ ╚═╝ ██║██║ ╚═╝ ██║██║ ╚████║
╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝

════════════════════════════════════════
⚠️  AUTHORIZATION WARNING ⚠️
════════════════════════════════════════
Use only on systems you own or have 
explicit permission to test.

Do you have authorization? (yes/no): yes

[?] Enter target (IP or domain): example.com
[✓] Valid domain: example.com

════════════════════════════════════════
              MAIN MENU
════════════════════════════════════════
[1] Full Assessment (All Modules)
[2] Basic Footprinting (Quick Scan)
[3] Custom Module Selection
[0] Exit

Select option: 1

[Starting reconnaissance...]
```

## Output & Reports

### Console Output
- Color-coded results
- Real-time progress indicators
- CVE findings with severity levels

### Report Files
Generated in `reports/` directory:

1. **JSON Report** (`mmn_report_<target>_<timestamp>.json`)
   - Machine-readable format
   - Complete data structure
   - Easy to parse programmatically

2. **HTML Report** (`mmn_report_<target>_<timestamp>.html`)
   - Human-friendly format
   - Styled with dark theme
   - Open in any web browser

## Port Scanning Settings

Default scan: **Common ports** (21, 22, 80, 443, etc.)
- Rate limited to prevent network disruption
- Banner grabbing for service identification
- Version detection when possible

## CVE Database

- Uses CIRCL CVE Search API
- Displays CVE ID, CVSS score, severity
- Provides vulnerability summaries
- **NO EXPLOIT CODE** - identification only

## Troubleshooting

**Import errors:**
```bash
pip install -r requirements.txt
```

**Permission denied (port scanning):**
```bash
sudo python3 main.py  # Use with caution
```

**Target resolution fails:**
- Check internet connection
- Verify target domain/IP is correct
- Some targets may block reconnaissance

**API timeouts:**
- Increase timeout in module code
- Some APIs have rate limits
- Retry after a few minutes

## Legal Reminder

✅ **Use only with authorization**
✅ **Educational purposes**
✅ **Owned systems**
✅ **Written permission**

❌ **Never scan without permission**
❌ **No unauthorized access**
❌ **No exploitation**

## Tips for Best Results

1. **Full Assessment** - Most thorough, takes longest
2. **Start with Basic Footprinting** - Quick overview
3. **Custom Modules** - Target specific information needs
4. **Save Reports** - All findings saved to `reports/`
5. **Review CVEs** - Check vendor patches and updates
6. **Verify Manually** - Automated tools may have false positives

## Project Structure
```
MMN/
├── main.py                    # Main controller (START HERE)
├── requirements.txt           # Dependencies
├── README.md                  # Full documentation
├── USAGE.md                   # This file
├── LICENSE                    # Legal terms
├── modules/                   # Core functionality
│   ├── input_handler.py       # Input validation
│   ├── target_expansion.py    # DNS/IP resolution
│   ├── footprinting.py        # WHOIS/SSL/HTTP
│   ├── subdomain_enum.py      # Subdomain discovery
│   ├── port_service_enum.py   # Port scanning
│   ├── tech_fingerprint.py    # Technology detection
│   ├── cve_mapper.py          # Vulnerability lookup
│   └── report_generator.py    # Report creation
├── reports/                   # Generated reports (auto-created)
└── logs/                      # Activity logs (auto-created)
```

## Support

For issues or questions:
- Review README.md for detailed documentation
- Check module source code for implementation details
- Ensure all dependencies are installed
- Verify Python 3.8+ is being used

---

**Remember: Stay legal, stay ethical, get authorization!**
