# MITM-X Framework

## 🚨 LEGAL DISCLAIMER

This tool is designed for educational purposes and authorized penetration testing only. The developers are not responsible for any misuse of this software. Only use this tool on networks you own or have explicit written permission to test.

**Unauthorized access to computer networks is illegal and may result in criminal charges.**

## Overview

MITM-X is an advanced Man-in-the-Middle (MITM) interception and injection framework designed for Kali Linux. It provides a comprehensive suite of tools for network security testing and red team operations.

## Features

- **ARP Spoofing**: Poison target ARP tables to redirect traffic
- **DNS Spoofing**: Intercept and modify DNS responses
- **Packet Sniffing**: Monitor and log network traffic
- **SSL Strip**: Downgrade HTTPS to HTTP connections
- **Payload Injection**: Inject JavaScript into HTTP responses
- **Web Cloning**: Clone and host fake login pages
- **Live Dashboard**: Real-time monitoring via web interface
- **Command Line Interface**: Interactive menu system
- **Auto Setup**: Automated dependency and system configuration

## Requirements

- Kali Linux (or similar Debian-based distribution)
- Python 3.7+
- Root privileges
- Network interface with monitor mode capability

### Python Dependencies

```bash
pip3 install scapy netfilterqueue dnslib flask beautifulsoup4 requests mitmproxy websockets
```

### System Dependencies

```bash
sudo apt update
sudo apt install python3-netfilterqueue iptables-persistent
```

## Installation

### Option 1: Quick Setup (Recommended for Virtual Environment)

**For Windows:**
1. Download or clone the MITM-X framework
2. Open Command Prompt or PowerShell as Administrator
3. Navigate to the project directory
4. Run the setup:
   ```batch
   python setup_venv.py
   ```
   Or double-click `run_setup.bat`

**For Linux/Kali:**
1. Clone or download the MITM-X framework
2. Navigate to the project directory
3. Run the setup with sudo:
   ```bash
   sudo python3 setup_venv.py
   ```

This will automatically:
- Create a virtual environment in the `venv/` folder
- Install all Python dependencies in the virtual environment
- Install system packages (Linux only)
- Create configuration files
- Set up convenience scripts for activation

### Option 2: Manual Setup

1. Create virtual environment:
   ```bash
   # Windows
   python -m venv venv
   
   # Linux
   python3 -m venv venv
   ```

2. Activate virtual environment:
   ```bash
   # Windows
   venv\Scripts\activate
   
   # Linux
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install system dependencies (Linux only):
   ```bash
   sudo apt update
   sudo apt install python3-netfilterqueue iptables-persistent dsniff ettercap-text-only
   ```

### Virtual Environment Usage

After setup, you need to activate the virtual environment before running MITM-X:

**Windows:**
- Double-click `activate_mitm.bat`, OR
- Run `activate_mitm.ps1` in PowerShell, OR
- Manually: `venv\Scripts\activate`

**Linux:**
- Run `./activate_mitm.sh`, OR
- Manually: `source venv/bin/activate`

Once activated, your command prompt will show `(venv)` prefix, indicating you're in the virtual environment.

## Usage

### Quick Start

1. **Activate Virtual Environment** (Required):
   ```bash
   # Windows
   activate_mitm.bat
   # OR for PowerShell
   .\activate_mitm.ps1
   
   # Linux
   ./activate_mitm.sh
   # OR manually
   source venv/bin/activate
   ```

2. **Run the Framework**:
   ```bash
   # Windows (after activation)
   python mitm_x.py
   
   # Linux (after activation, with sudo)
   sudo python3 mitm_x.py
   ```

This will launch the interactive command-line interface where you can select and configure different modules.

### Individual Module Usage

**Note: Activate virtual environment first!**

#### ARP Spoofing
```bash
python modules/arp_spoofer.py --target 192.168.1.100 --gateway 192.168.1.1 --interface eth0
```

#### DNS Spoofing
```bash
python modules/dns_spoofer.py --domain facebook.com --redirect 192.168.1.50
```

#### Packet Sniffing
```bash
python modules/packet_sniffer.py --interface eth0 --output logs/
```

#### SSL Strip
```bash
python modules/ssl_strip.py --port 8080
```

#### Payload Injection
```bash
python modules/payload_injector.py --payload "alert('Hacked!')" --port 8080
```

#### Web Cloner
```bash
python modules/web_cloner.py --url https://facebook.com --output cloned_sites/
```

### Dashboard Access

The live dashboard is accessible at `http://localhost:5000` when running the framework.

## Project Structure

```
MITM-X/
├── mitm_x.py              # Main CLI interface
├── setup.py               # Auto setup script
├── requirements.txt       # Python dependencies
├── config/
│   └── settings.json      # Configuration file
├── modules/
│   ├── __init__.py
│   ├── arp_spoofer.py     # ARP spoofing module
│   ├── dns_spoofer.py     # DNS spoofing module
│   ├── packet_sniffer.py  # Packet sniffing module
│   ├── ssl_strip.py       # SSL stripping module
│   ├── payload_injector.py # Payload injection module
│   ├── web_cloner.py      # Web cloning module
│   └── dashboard.py       # Live dashboard module
├── logs/                  # Log files directory
├── cloned_sites/          # Cloned websites directory
└── payloads/              # Payload scripts directory
```

## Configuration

Edit `config/settings.json` to customize default settings:

```json
{
    "interface": "eth0",
    "gateway": "192.168.1.1",
    "dns_server": "8.8.8.8",
    "dashboard_port": 5000,
    "proxy_port": 8080,
    "log_level": "INFO"
}
```

## Modules Documentation

### ARP Spoofer
Performs ARP cache poisoning to redirect target traffic through the attacker's machine.

### DNS Spoofer
Intercepts DNS queries and provides malicious responses for specified domains.

### Packet Sniffer
Captures and analyzes network traffic, extracting URLs, cookies, and form data.

### SSL Strip
Downgrades HTTPS connections to HTTP by removing SSL/TLS encryption.

### Payload Injector
Injects custom JavaScript payloads into HTTP responses for client-side attacks.

### Web Cloner
Creates local copies of websites for phishing and social engineering attacks.

## Best Practices

1. Always obtain proper authorization before testing
2. Use in isolated lab environments when possible
3. Document all testing activities
4. Follow responsible disclosure for any findings
5. Keep the framework updated with latest security patches

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure you're running with sudo privileges
2. **Module Import Errors**: Install required dependencies with pip3
3. **Network Interface Issues**: Verify interface name and monitor mode support
4. **Iptables Rules**: Check if firewall rules are blocking traffic

### Support

For issues and bug reports, please check the documentation or create an issue in the project repository.

## Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch
3. Commit your changes with clear messages
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Ethical Guidelines

This framework is intended for:
- Authorized penetration testing
- Security research in controlled environments
- Educational purposes in cybersecurity training
- Red team exercises with proper authorization

**Never use this tool for:**
- Unauthorized network access
- Criminal activities
- Attacking systems without permission
- Causing harm or damage to systems or data

## Version History

- v1.0.0 - Initial release with core modules
- Features planned for future releases:
  - Advanced evasion techniques
  - Mobile device targeting
  - Wireless attack vectors
  - Integration with popular security frameworks
