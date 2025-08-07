# MITM-X Virtual Environment Troubleshooting Guide

## Common Issues and Solutions

### 1. Virtual Environment Not Activating

**Problem**: Virtual environment scripts don't work or show errors.

**Solutions**:
- **Windows**: Run Command Prompt or PowerShell as Administrator
- **Linux**: Ensure you have permission to execute: `chmod +x activate_mitm.sh`
- **Manual activation**:
  - Windows: `venv\Scripts\activate`
  - Linux: `source venv/bin/activate`

### 2. Package Installation Failures

**Problem**: Some packages fail to install in virtual environment.

**Solutions**:
- **Upgrade pip first**: `python -m pip install --upgrade pip`
- **Install packages individually**:
  ```bash
  pip install scapy
  pip install flask
  pip install requests
  pip install beautifulsoup4
  ```
- **Linux-specific packages**: Some packages like `netfilterqueue` only work on Linux
- **Windows users**: Some features will be limited, this is expected

### 3. "Module not found" Errors

**Problem**: Python can't find the MITM-X modules.

**Solutions**:
- **Check virtual environment**: Make sure you activated it (should see `(venv)` in prompt)
- **Check directory**: Run commands from the MITM-X project root directory
- **Verify installation**: Run `python setup_venv.py` again

### 4. Permission Errors (Linux)

**Problem**: "Permission denied" or network access errors.

**Solutions**:
- **Use sudo**: Most network operations require root privileges
- **After activating venv**: `sudo python3 mitm_x.py`
- **Check capabilities**: Some features require specific system capabilities

### 5. Windows-Specific Issues

**Problem**: Limited functionality on Windows.

**Solutions**:
- **Use WSL**: Install Windows Subsystem for Linux for better compatibility
- **Virtual Machine**: Run Kali Linux in a VM for full functionality
- **Accept limitations**: Some features like ARP spoofing work differently on Windows

### 6. Network Interface Issues

**Problem**: Can't find network interface or "No such device" errors.

**Solutions**:
- **List interfaces**: `ip addr` (Linux) or `ipconfig` (Windows)
- **Update config**: Edit `config/settings.json` with correct interface name
- **Windows**: Use interface names like "Wi-Fi" or "Ethernet"
- **Linux**: Use names like "eth0", "wlan0", "enp0s3"

### 7. Dependencies Not Installing

**Problem**: Some packages show compilation errors.

**Solutions**:
- **Install build tools**:
  - Windows: Install Visual Studio Build Tools
  - Linux: `sudo apt install build-essential python3-dev`
- **Use system packages** (Linux):
  ```bash
  sudo apt install python3-netfilterqueue
  ```
- **Skip problematic packages**: Framework will work with partial functionality

## Verification Steps

### Check Virtual Environment
```bash
# Should show path to venv/Scripts/python (Windows) or venv/bin/python (Linux)
which python
# or
where python
```

### Check Package Installation
```bash
python -c "import scapy; print('Scapy OK')"
python -c "import flask; print('Flask OK')"
python -c "import requests; print('Requests OK')"
```

### Check Framework
```bash
python -c "import sys; print(sys.path)"  # Should include your project directory
```

## Manual Installation Steps

If automated setup fails, follow these manual steps:

### 1. Create Virtual Environment
```bash
# Windows
python -m venv venv

# Linux
python3 -m venv venv
```

### 2. Activate Environment
```bash
# Windows
venv\Scripts\activate

# Linux
source venv/bin/activate
```

### 3. Upgrade pip
```bash
python -m pip install --upgrade pip
```

### 4. Install Core Packages
```bash
pip install scapy flask requests beautifulsoup4 colorama psutil websockets
```

### 5. Install Optional Packages (Linux)
```bash
pip install netfilterqueue dnslib mitmproxy
```

### 6. Test Installation
```bash
python -c "import scapy, flask, requests; print('Core packages OK')"
```

## Getting Help

1. **Check logs**: Look in `logs/` directory for error details
2. **Run with verbose**: Add `--verbose` flag to see detailed output  
3. **Check configuration**: Verify `config/settings.json` has correct settings
4. **System requirements**: Ensure you meet minimum requirements for your OS

## Resetting Environment

If everything fails, reset and start over:

```bash
# Remove virtual environment
rmdir /s venv      # Windows
rm -rf venv        # Linux

# Run setup again
python setup_venv.py
```
