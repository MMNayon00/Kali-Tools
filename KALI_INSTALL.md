# MMN Framework - Kali Linux Installation Guide

## 📥 Download & Setup on Kali Linux

### Option 1: Direct Download (If you have the files)

If you have the project folder on another machine, transfer it to Kali:

```bash
# Using SCP (from your Mac to Kali)
scp -r "/Users/md.mostofanayon/Desktop/Kali Tools" kali@<KALI_IP>:~/

# Or using a USB drive, cloud storage, etc.
```

### Option 2: From GitHub (Recommended)

Once you upload this to GitHub, you can clone it directly on Kali:

```bash
# Clone the repository
cd ~
git clone https://github.com/YOUR_USERNAME/MMN-Framework.git
cd MMN-Framework
```

### Option 3: Manual File Creation on Kali

If you need to manually create the project on Kali, follow these steps.

---

## 🔧 Installation on Kali Linux

### Step 1: Update Kali Linux

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Python3 and pip (if not already installed)

Kali Linux usually comes with Python3, but verify:

```bash
# Check Python version
python3 --version

# Install pip if needed
sudo apt install python3-pip python3-venv -y
```

### Step 3: Navigate to Project Directory

```bash
cd ~/MMN-Framework
# or wherever you placed the files
```

### Step 4: Create Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Your prompt should change to show (venv)
```

### Step 5: Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# Verify installation
pip list | grep -E "colorama|requests|dns|whois|beautifulsoup"
```

You should see:
- colorama==0.4.6
- requests==2.31.0
- dnspython==2.4.2
- python-whois==0.8.0
- beautifulsoup4==4.12.2

---

## 🚀 Running the Tool

### Basic Execution

```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Run the tool
python3 main.py
```

### Alternative: Direct Execution

```bash
# Run with virtual environment Python directly
./venv/bin/python3 main.py
```

### Make it Executable (Optional)

```bash
# Add shebang and make executable
chmod +x main.py

# Then run with
./main.py
```

---

## 🎯 First Run Example

```bash
┌──(kali㉿kali)-[~/MMN-Framework]
└─$ source venv/bin/activate

(venv) ┌──(kali㉿kali)-[~/MMN-Framework]
└─$ python3 main.py

███╗   ███╗███╗   ███╗███╗   ██╗
████╗ ████║████╗ ████║████╗  ██║
██╔████╔██║██╔████╔██║██╔██╗ ██║
██║╚██╔╝██║██║╚██╔╝██║██║╚██╗██║
██║ ╚═╝ ██║██║ ╚═╝ ██║██║ ╚████║
╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝

Modular Reconnaissance & Assessment Framework
Version 1.0.0 | For Authorized Use Only

================================================================================
⚠️  AUTHORIZATION WARNING ⚠️
================================================================================
Use only on systems you own or have explicit permission to test.
Unauthorized access to computer systems is illegal.
The authors accept no liability for misuse of this tool.
================================================================================

Do you have authorization to test the target? (yes/no): yes

[?] Enter target (IP or domain): scanme.nmap.org
[✓] Valid domain: scanme.nmap.org

============================================================
                      MAIN MENU
============================================================
[1] Full Assessment (All Modules)
[2] Basic Footprinting (Quick Scan)
[3] Custom Module Selection
[0] Exit

Select option: 1

[Starting full assessment...]
```

---

## 🛠️ Kali-Specific Tips

### Port Scanning Permissions

Some port scanning operations may require root privileges:

```bash
# Run with sudo if needed
sudo ./venv/bin/python3 main.py

# Or
sudo su
source venv/bin/activate
python3 main.py
```

### Network Configuration

Ensure your Kali VM has network access:

```bash
# Check internet connectivity
ping -c 3 google.com

# Check DNS resolution
nslookup example.com

# If using VM, ensure network adapter is set to NAT or Bridged
```

### Firewall Issues

If you encounter connection issues:

```bash
# Check firewall status
sudo ufw status

# Temporarily disable if testing (re-enable after)
sudo ufw disable
```

---

## 📁 Project Structure After Setup

```
~/MMN-Framework/
├── main.py                 # Main entry point
├── requirements.txt        # Dependencies
├── README.md              # Documentation
├── USAGE.md               # Usage guide
├── LICENSE                # Legal terms
├── modules/               # Core modules (8 files)
├── reports/               # Generated reports (auto-created)
├── logs/                  # Activity logs (auto-created)
└── venv/                  # Virtual environment (created by you)
```

---

## 🧪 Quick Test

Test if everything works:

```bash
# Activate venv
source venv/bin/activate

# Test imports
python3 -c "from modules import input_handler; print('✓ Imports work')"

# Quick syntax check
python3 -m py_compile main.py && echo "✓ No syntax errors"

# Run the tool
python3 main.py
```

---

## 🔍 Common Issues & Solutions

### Issue 1: "Module not found" errors

```bash
# Solution: Ensure venv is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue 2: "Permission denied" during port scanning

```bash
# Solution: Run with sudo
sudo ./venv/bin/python3 main.py
```

### Issue 3: API timeouts or connection errors

```bash
# Check internet connection
ping -c 3 8.8.8.8

# Check DNS
nslookup crt.sh

# Some APIs may have rate limits - wait and retry
```

### Issue 4: Python version issues

```bash
# Kali should have Python 3.9+
python3 --version

# If too old, update Kali:
sudo apt update && sudo apt upgrade -y
```

### Issue 5: Virtual environment activation fails

```bash
# Ensure python3-venv is installed
sudo apt install python3-venv -y

# Recreate venv
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📊 Expected Behavior

When running correctly, you should see:

1. ✅ MMN ASCII banner displays immediately
2. ✅ Legal disclaimer appears
3. ✅ Authorization prompt (type "yes")
4. ✅ Target input prompt
5. ✅ Color-coded menu options
6. ✅ Real-time scan progress
7. ✅ Reports saved to `reports/` directory

---

## 🎓 Recommended Test Target

For initial testing, use authorized targets:

```bash
# Safe test targets (have permission for scanning)
scanme.nmap.org
testphp.vulnweb.com (intentionally vulnerable test site)
```

**Never scan targets without authorization!**

---

## 📝 Deactivating Virtual Environment

When done:

```bash
# Deactivate virtual environment
deactivate

# Your prompt returns to normal
```

---

## 🔒 Security Notes for Kali

- Always run as standard user first (not root)
- Only use sudo when necessary (port scanning < 1024)
- Keep Kali Linux updated: `sudo apt update && sudo apt upgrade`
- Store reports securely (they contain sensitive recon data)
- Follow engagement rules and obtain written authorization

---

## 💡 Pro Tips

1. **Create an alias** for quick access:
   ```bash
   echo "alias mmn='cd ~/MMN-Framework && source venv/bin/activate && python3 main.py'" >> ~/.bashrc
   source ~/.bashrc
   
   # Now just type:
   mmn
   ```

2. **Run in tmux** for persistent sessions:
   ```bash
   tmux new -s recon
   cd ~/MMN-Framework
   source venv/bin/activate
   python3 main.py
   
   # Detach: Ctrl+B, then D
   # Reattach: tmux attach -t recon
   ```

3. **Redirect output** to a file:
   ```bash
   python3 main.py | tee scan_output.txt
   ```

---

## 📚 Additional Resources

- **Kali Linux Documentation**: https://www.kali.org/docs/
- **Python Virtual Environments**: https://docs.python.org/3/library/venv.html
- **Ethical Hacking Guidelines**: Always follow OWASP and PTES standards

---

## ✅ Verification Checklist

Before running scans:

- [ ] Kali Linux is updated
- [ ] Python 3.8+ installed
- [ ] Virtual environment created and activated
- [ ] All dependencies installed (5 packages)
- [ ] Network connectivity verified
- [ ] Written authorization obtained for target
- [ ] Reports directory writable
- [ ] Tool runs and displays banner

---

## 🆘 Getting Help

If you encounter issues:

1. Check this guide's troubleshooting section
2. Review README.md for detailed documentation
3. Verify all dependencies are installed: `pip list`
4. Check Python version: `python3 --version`
5. Ensure virtual environment is activated

---

**You're ready to go! Stay legal, stay ethical, get authorization!** 🛡️
