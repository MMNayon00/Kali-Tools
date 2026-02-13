# MMN - Modular Reconnaissance & Assessment Framework

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-Educational-green.svg)

**FOR AUTHORIZED USE ONLY**

MMN is a modular reconnaissance and vulnerability assessment framework designed for security professionals conducting authorized penetration tests. This tool automates footprinting, asset discovery, and CVE identification without performing exploitation.

## ⚠️ Legal Disclaimer

**Use only on systems you own or have explicit permission to test. Unauthorized use is illegal.**

This tool is provided for educational purposes and authorized security assessments only. The authors accept no liability for misuse or damage caused by this program. Always obtain written authorization before conducting security assessments.

## Features

- 🎯 **Target Validation** - Smart input handling with domain/IP validation
- 🔍 **Footprinting** - WHOIS, DNS enumeration, SSL/TLS inspection, HTTP header analysis
- 🌐 **Asset Discovery** - Subdomain enumeration via Certificate Transparency and passive sources
- 🔌 **Service Enumeration** - Rate-limited port scanning with service detection
- 🛠️ **Technology Fingerprinting** - Web server, CMS, framework identification
- 🔒 **CVE Mapping** - Automated vulnerability database lookups with CVSS scoring
- 📊 **Reporting** - Structured CLI output with optional HTML reports
- 📝 **Activity Logging** - Full audit trail of reconnaissance activities

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Internet connection for external lookups

### Setup

```bash
# Clone or download the repository
cd MMN

# Install dependencies
pip3 install -r requirements.txt

# Run the tool
python3 main.py
```

## Usage

### Basic Execution

```bash
python3 main.py
```

Upon launch, you will see:
1. **MMN ASCII Banner** - Displayed at the top
2. **Legal Disclaimer** - Authorization warning
3. **Target Input** - Enter IP or domain
4. **Module Selection** - Choose which modules to run
5. **Execution** - Automated reconnaissance
6. **Results** - Formatted output with findings

### Module Overview

| Module | Description |
|--------|-------------|
| **Input Handler** | Validates and sanitizes target input |
| **Target Expansion** | DNS resolution, ASN identification |
| **Footprinting** | WHOIS, DNS records, SSL/TLS, HTTP headers |
| **Subdomain Enum** | Certificate Transparency, passive discovery |
| **Port/Service Enum** | Rate-limited scanning with version detection |
| **Tech Fingerprint** | Web technology stack identification |
| **CVE Mapper** | Vulnerability database lookup |
| **Report Generator** | Structured output and HTML reports |

### Example Workflow

```
[MMN Banner Displayed]

⚠️  AUTHORIZATION WARNING
Use only on systems you own or have explicit permission to test.

Enter target (IP or domain): example.com

Select modules to run:
[1] Full Assessment (All Modules)
[2] Basic Footprinting
[3] Custom Module Selection
[0] Exit

Choice: 1

[Executing reconnaissance...]
[Results displayed with severity ratings]
[Report saved to reports/]
```

## Project Structure

```
MMN/
├── main.py                      # Main controller
├── requirements.txt             # Python dependencies
├── README.md                    # Documentation
├── modules/
│   ├── input_handler.py         # Target validation
│   ├── target_expansion.py      # DNS & IP resolution
│   ├── footprinting.py          # WHOIS, DNS, SSL, HTTP
│   ├── subdomain_enum.py        # Subdomain discovery
│   ├── port_service_enum.py     # Port scanning
│   ├── tech_fingerprint.py      # Technology detection
│   ├── cve_mapper.py            # Vulnerability lookup
│   └── report_generator.py      # Output formatting
└── reports/                     # Generated reports
```

## Ethical Guidelines

✅ **Permitted Use:**
- Systems you own
- Systems with written authorization
- Educational lab environments
- Bug bounty programs (within scope)

❌ **Prohibited:**
- Unauthorized scanning
- Exploitation attempts
- Denial of service attacks
- Credential brute forcing
- Any illegal activity

## Technical Details

- **Port Scanning:** Rate-limited to avoid detection/disruption
- **Data Sources:** Public APIs (WHOIS, DNS, Certificate Transparency)
- **CVE Lookup:** CIRCL.LU CVE Search API
- **Logging:** All actions logged to `reports/` directory

## Troubleshooting

**"Module not found" errors:**
```bash
pip3 install -r requirements.txt
```

**Permission denied:**
```bash
sudo python3 main.py  # Only if port scanning requires privileges
```

**Timeout errors:**
- Check internet connection
- Target may be blocking reconnaissance
- Try with a different target

## Contributing

This project is maintained for educational purposes. Contributions that enhance reconnaissance capabilities (without exploitation) are welcome.

## Disclaimer

This tool performs **identification and assessment only**. It does not:
- Execute exploits
- Modify remote systems
- Perform brute force attacks
- Launch denial of service

Always conduct security assessments responsibly and legally.

## License

Educational Use Only - Ensure compliance with local laws and regulations.

---

**Built for security professionals. Use responsibly.**
