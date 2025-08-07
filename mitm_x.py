#!/usr/bin/env python3
"""
MITM-X Framework - Main Command Line Interface
Advanced Man-in-the-Middle Framework for Penetration Testing
"""

import os
import sys
import json
import time
import signal
import threading
import argparse
import logging
from datetime import datetime

# Add modules directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

try:
    from colorama import init, Fore, Back, Style
    init()  # Initialize colorama for Windows compatibility
except ImportError:
    # Create dummy color classes if colorama not available
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        DIM = NORMAL = BRIGHT = RESET_ALL = ""

# Import modules
try:
    from arp_spoofer import ARPSpoofer
    from dns_spoofer import DNSSpoofer
    from packet_sniffer import PacketSniffer
    from ssl_strip import SSLStrip
    from payload_injector import PayloadInjector
    from web_cloner import WebCloner
    from dashboard import Dashboard
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please run setup.py first: sudo python3 setup.py")
    sys.exit(1)

class MITMFramework:
    """
    Main MITM Framework class
    """
    
    def __init__(self):
        """
        Initialize MITM Framework
        """
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.config = self.load_config()
        
        # Initialize modules
        self.modules = {}
        self.running_modules = {}
        
        # Dashboard
        self.dashboard = None
        
        # Signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def load_config(self):
        """
        Load configuration from file
        
        Returns:
            dict: Configuration data
        """
        config_file = "config/settings.json"
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            self.logger.info("Configuration loaded successfully")
            return config
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return self.get_default_config()
    
    def get_default_config(self):
        """
        Get default configuration
        
        Returns:
            dict: Default configuration
        """
        return {
            "interface": "eth0",
            "gateway": "192.168.1.1",
            "dashboard_port": 5000,
            "proxy_port": 8080
        }
    
    def signal_handler(self, sig, frame):
        """
        Handle signals for graceful shutdown
        """
        print(f"\n{Fore.YELLOW}Received signal {sig}. Shutting down gracefully...{Style.RESET_ALL}")
        self.stop_all_modules()
        sys.exit(0)
    
    def print_banner(self):
        """
        Print framework banner
        """
        banner = f"""
{Fore.RED}
███╗   ███╗██╗████████╗███╗   ███╗      ██╗  ██╗
████╗ ████║██║╚══██╔══╝████╗ ████║      ╚██╗██╔╝
██╔████╔██║██║   ██║   ██╔████╔██║       ╚███╔╝ 
██║╚██╔╝██║██║   ██║   ██║╚██╔╝██║       ██╔██╗ 
██║ ╚═╝ ██║██║   ██║   ██║ ╚═╝ ██║      ██╔╝ ██╗
╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝     ╚═╝      ╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.CYAN}Advanced Man-in-the-Middle Framework v1.0{Style.RESET_ALL}
{Fore.YELLOW}⚠️  For Educational and Authorized Testing Only ⚠️{Style.RESET_ALL}
{Fore.WHITE}Developed for Cybersecurity Research and Penetration Testing{Style.RESET_ALL}
        """
        print(banner)
    
    def print_menu(self):
        """
        Print main menu
        """
        menu = f"""
{Fore.GREEN}┌─────────────────────────────────────────────────────┐
│                   MITM-X MAIN MENU                    │
├─────────────────────────────────────────────────────┤{Style.RESET_ALL}
{Fore.WHITE}│ 1.  ARP Spoofer        │ 8.  Web Cloner           │
│ 2.  DNS Spoofer        │ 9.  Dashboard            │
│ 3.  Packet Sniffer     │ 10. Module Status        │
│ 4.  SSL Strip          │ 11. Configuration        │
│ 5.  Payload Injector   │ 12. Logs Viewer          │
│ 6.  Credential Capture │ 13. Stop All Modules     │
│ 7.  Network Scanner    │ 0.  Exit Framework       │{Style.RESET_ALL}
{Fore.GREEN}└─────────────────────────────────────────────────────┘{Style.RESET_ALL}
        """
        print(menu)
    
    def get_user_input(self, prompt, input_type=str, default=None):
        """
        Get user input with type validation
        
        Args:
            prompt (str): Input prompt
            input_type: Expected input type
            default: Default value
            
        Returns:
            User input
        """
        while True:
            try:
                if default is not None:
                    user_input = input(f"{prompt} [{default}]: ").strip()
                    if not user_input:
                        return default
                else:
                    user_input = input(f"{prompt}: ").strip()
                
                if input_type == int:
                    return int(user_input)
                elif input_type == float:
                    return float(user_input)
                else:
                    return user_input
            except ValueError:
                print(f"{Fore.RED}Invalid input. Please enter a valid {input_type.__name__}.{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Operation cancelled.{Style.RESET_ALL}")
                return None
    
    def start_arp_spoofer(self):
        """
        Start ARP Spoofer module
        """
        print(f"\n{Fore.CYAN}=== ARP Spoofer Configuration ==={Style.RESET_ALL}")
        
        target_ip = self.get_user_input("Target IP address")
        if not target_ip:
            return
        
        gateway_ip = self.get_user_input("Gateway IP address", default=self.config.get("gateway", "192.168.1.1"))
        interface = self.get_user_input("Network interface", default=self.config.get("interface", "eth0"))
        
        try:
            spoofer = ARPSpoofer(target_ip, gateway_ip, interface)
            
            # Start in separate thread
            def run_spoofer():
                spoofer.start_spoofing()
            
            thread = threading.Thread(target=run_spoofer)
            thread.daemon = True
            thread.start()
            
            self.running_modules['arp_spoofer'] = {
                'module': spoofer,
                'thread': thread,
                'config': {'target_ip': target_ip, 'gateway_ip': gateway_ip, 'interface': interface}
            }
            
            print(f"{Fore.GREEN}✓ ARP Spoofer started successfully{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error starting ARP Spoofer: {e}{Style.RESET_ALL}")
    
    def start_dns_spoofer(self):
        """
        Start DNS Spoofer module
        """
        print(f"\n{Fore.CYAN}=== DNS Spoofer Configuration ==={Style.RESET_ALL}")
        
        redirect_ip = self.get_user_input("Redirect IP address", default="192.168.1.100")
        
        # Get domains to spoof
        domains = {}
        while True:
            domain = self.get_user_input("Domain to spoof (empty to finish)")
            if not domain:
                break
            
            ip = self.get_user_input(f"IP for {domain}", default=redirect_ip)
            domains[domain] = ip
        
        if not domains:
            domains = {"facebook.com": redirect_ip, "google.com": redirect_ip}
            print(f"{Fore.YELLOW}Using default domains: {list(domains.keys())}{Style.RESET_ALL}")
        
        try:
            spoofer = DNSSpoofer(redirect_ip, domains)
            
            # Start in separate thread
            def run_spoofer():
                spoofer.start_spoofing()
            
            thread = threading.Thread(target=run_spoofer)
            thread.daemon = True
            thread.start()
            
            self.running_modules['dns_spoofer'] = {
                'module': spoofer,
                'thread': thread,
                'config': {'redirect_ip': redirect_ip, 'domains': domains}
            }
            
            print(f"{Fore.GREEN}✓ DNS Spoofer started successfully{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error starting DNS Spoofer: {e}{Style.RESET_ALL}")
    
    def start_packet_sniffer(self):
        """
        Start Packet Sniffer module
        """
        print(f"\n{Fore.CYAN}=== Packet Sniffer Configuration ==={Style.RESET_ALL}")
        
        interface = self.get_user_input("Network interface", default=self.config.get("interface", "eth0"))
        output_dir = self.get_user_input("Output directory", default="logs/")
        filter_str = self.get_user_input("BPF filter (optional)", default="")
        
        try:
            sniffer = PacketSniffer(interface, output_dir)
            
            # Start in separate thread
            def run_sniffer():
                sniffer.start_sniffing(filter_str)
            
            thread = threading.Thread(target=run_sniffer)
            thread.daemon = True
            thread.start()
            
            self.running_modules['packet_sniffer'] = {
                'module': sniffer,
                'thread': thread,
                'config': {'interface': interface, 'output_dir': output_dir}
            }
            
            print(f"{Fore.GREEN}✓ Packet Sniffer started successfully{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error starting Packet Sniffer: {e}{Style.RESET_ALL}")
    
    def start_ssl_strip(self):
        """
        Start SSL Strip module
        """
        print(f"\n{Fore.CYAN}=== SSL Strip Configuration ==={Style.RESET_ALL}")
        
        port = self.get_user_input("Proxy port", int, default=self.config.get("proxy_port", 8080))
        interface = self.get_user_input("Interface", default="0.0.0.0")
        
        try:
            ssl_strip = SSLStrip(port, interface)
            
            # Start in separate thread
            def run_ssl_strip():
                ssl_strip.start_proxy()
            
            thread = threading.Thread(target=run_ssl_strip)
            thread.daemon = True
            thread.start()
            
            self.running_modules['ssl_strip'] = {
                'module': ssl_strip,
                'thread': thread,
                'config': {'port': port, 'interface': interface}
            }
            
            print(f"{Fore.GREEN}✓ SSL Strip started on port {port}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error starting SSL Strip: {e}{Style.RESET_ALL}")
    
    def start_payload_injector(self):
        """
        Start Payload Injector module
        """
        print(f"\n{Fore.CYAN}=== Payload Injector Configuration ==={Style.RESET_ALL}")
        
        port = self.get_user_input("Proxy port", int, default=self.config.get("proxy_port", 8080))
        
        # Show available payloads
        print("\nAvailable payloads:")
        payloads = ["alert", "keylogger", "form_hijack", "cookie_stealer", "reverse_shell"]
        for i, payload in enumerate(payloads, 1):
            print(f"  {i}. {payload}")
        
        payload_choice = self.get_user_input("Select payload (1-5)", int, default=1)
        if payload_choice < 1 or payload_choice > len(payloads):
            payload_choice = 1
        
        selected_payload = payloads[payload_choice - 1]
        
        try:
            injector = PayloadInjector(port)
            injector.set_payload(selected_payload)
            
            # Start in separate thread
            def run_injector():
                injector.start_injector()
            
            thread = threading.Thread(target=run_injector)
            thread.daemon = True
            thread.start()
            
            self.running_modules['payload_injector'] = {
                'module': injector,
                'thread': thread,
                'config': {'port': port, 'payload': selected_payload}
            }
            
            print(f"{Fore.GREEN}✓ Payload Injector started with {selected_payload} payload{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error starting Payload Injector: {e}{Style.RESET_ALL}")
    
    def start_web_cloner(self):
        """
        Start Web Cloner module
        """
        print(f"\n{Fore.CYAN}=== Web Cloner Configuration ==={Style.RESET_ALL}")
        
        url = self.get_user_input("URL to clone")
        if not url:
            return
        
        output_dir = self.get_user_input("Output directory", default="cloned_sites/")
        site_name = self.get_user_input("Site name (optional)")
        server_port = self.get_user_input("Server port", int, default=8000)
        
        try:
            cloner = WebCloner(output_dir, server_port)
            
            # Clone the website
            print(f"{Fore.YELLOW}Cloning website...{Style.RESET_ALL}")
            site_path = cloner.clone_website(url, site_name)
            
            if site_path:
                print(f"{Fore.GREEN}✓ Website cloned to: {site_path}{Style.RESET_ALL}")
                
                # Start server
                def run_server():
                    cloner.start_server()
                
                thread = threading.Thread(target=run_server)
                thread.daemon = True
                thread.start()
                
                self.running_modules['web_cloner'] = {
                    'module': cloner,
                    'thread': thread,
                    'config': {'url': url, 'output_dir': output_dir, 'server_port': server_port}
                }
                
                print(f"{Fore.GREEN}✓ Web server started on port {server_port}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Access cloned site at: http://localhost:{server_port}/site/{site_name or 'default'}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ Failed to clone website{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}✗ Error with Web Cloner: {e}{Style.RESET_ALL}")
    
    def start_dashboard(self):
        """
        Start Dashboard module
        """
        print(f"\n{Fore.CYAN}=== Dashboard Configuration ==={Style.RESET_ALL}")
        
        port = self.get_user_input("Dashboard port", int, default=self.config.get("dashboard_port", 5000))
        host = self.get_user_input("Host", default="0.0.0.0")
        
        try:
            self.dashboard = Dashboard(port, port + 1, host)
            
            # Start in separate thread
            def run_dashboard():
                self.dashboard.start_dashboard()
            
            thread = threading.Thread(target=run_dashboard)
            thread.daemon = True
            thread.start()
            
            self.running_modules['dashboard'] = {
                'module': self.dashboard,
                'thread': thread,
                'config': {'port': port, 'host': host}
            }
            
            print(f"{Fore.GREEN}✓ Dashboard started on http://{host}:{port}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}✗ Error starting Dashboard: {e}{Style.RESET_ALL}")
    
    def show_module_status(self):
        """
        Show status of running modules
        """
        print(f"\n{Fore.CYAN}=== Module Status ==={Style.RESET_ALL}")
        
        if not self.running_modules:
            print(f"{Fore.YELLOW}No modules currently running{Style.RESET_ALL}")
            return
        
        for module_name, info in self.running_modules.items():
            status = "Running" if info['thread'].is_alive() else "Stopped"
            color = Fore.GREEN if status == "Running" else Fore.RED
            
            print(f"{color}● {module_name.replace('_', ' ').title()}: {status}{Style.RESET_ALL}")
            
            # Show configuration
            config = info.get('config', {})
            for key, value in config.items():
                print(f"  {key}: {value}")
    
    def view_logs(self):
        """
        View log files
        """
        print(f"\n{Fore.CYAN}=== Log Viewer ==={Style.RESET_ALL}")
        
        log_dir = "logs"
        if not os.path.exists(log_dir):
            print(f"{Fore.YELLOW}No logs directory found{Style.RESET_ALL}")
            return
        
        log_files = [f for f in os.listdir(log_dir) if f.endswith('.log')]
        
        if not log_files:
            print(f"{Fore.YELLOW}No log files found{Style.RESET_ALL}")
            return
        
        print("Available log files:")
        for i, log_file in enumerate(log_files, 1):
            print(f"  {i}. {log_file}")
        
        choice = self.get_user_input("Select log file (1-{})".format(len(log_files)), int)
        if not choice or choice < 1 or choice > len(log_files):
            return
        
        selected_log = log_files[choice - 1]
        log_path = os.path.join(log_dir, selected_log)
        
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
            
            print(f"\n{Fore.GREEN}=== {selected_log} ==={Style.RESET_ALL}")
            
            # Show last 50 lines
            for line in lines[-50:]:
                print(line.strip())
                
        except Exception as e:
            print(f"{Fore.RED}Error reading log file: {e}{Style.RESET_ALL}")
    
    def edit_configuration(self):
        """
        Edit configuration settings
        """
        print(f"\n{Fore.CYAN}=== Configuration Editor ==={Style.RESET_ALL}")
        
        print("Current configuration:")
        for key, value in self.config.items():
            print(f"  {key}: {value}")
        
        print("\nWhat would you like to modify?")
        print("1. Interface")
        print("2. Gateway")
        print("3. Dashboard Port")
        print("4. Proxy Port")
        print("5. Save and Exit")
        
        choice = self.get_user_input("Select option (1-5)", int)
        
        if choice == 1:
            new_interface = self.get_user_input("New interface", default=self.config.get("interface"))
            if new_interface:
                self.config["interface"] = new_interface
        elif choice == 2:
            new_gateway = self.get_user_input("New gateway", default=self.config.get("gateway"))
            if new_gateway:
                self.config["gateway"] = new_gateway
        elif choice == 3:
            new_port = self.get_user_input("New dashboard port", int, default=self.config.get("dashboard_port"))
            if new_port:
                self.config["dashboard_port"] = new_port
        elif choice == 4:
            new_port = self.get_user_input("New proxy port", int, default=self.config.get("proxy_port"))
            if new_port:
                self.config["proxy_port"] = new_port
        elif choice == 5:
            # Save configuration
            try:
                with open("config/settings.json", 'w') as f:
                    json.dump(self.config, f, indent=4)
                print(f"{Fore.GREEN}✓ Configuration saved{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}✗ Error saving configuration: {e}{Style.RESET_ALL}")
    
    def stop_all_modules(self):
        """
        Stop all running modules
        """
        print(f"\n{Fore.YELLOW}Stopping all modules...{Style.RESET_ALL}")
        
        for module_name, info in self.running_modules.items():
            try:
                module = info['module']
                
                # Call appropriate stop method
                if hasattr(module, 'stop_spoofing'):
                    module.stop_spoofing()
                elif hasattr(module, 'stop_sniffing'):
                    module.stop_sniffing()
                elif hasattr(module, 'stop_proxy'):
                    module.stop_proxy()
                elif hasattr(module, 'stop_injector'):
                    module.stop_injector()
                elif hasattr(module, 'stop_server'):
                    module.stop_server()
                elif hasattr(module, 'stop_dashboard'):
                    module.stop_dashboard()
                
                print(f"{Fore.GREEN}✓ {module_name} stopped{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}✗ Error stopping {module_name}: {e}{Style.RESET_ALL}")
        
        self.running_modules.clear()
        print(f"{Fore.GREEN}All modules stopped{Style.RESET_ALL}")
    
    def run_interactive_mode(self):
        """
        Run interactive command-line interface
        """
        self.print_banner()
        
        while True:
            self.print_menu()
            
            try:
                choice = self.get_user_input(f"\n{Fore.WHITE}Select option", int)
                
                if choice == 1:
                    self.start_arp_spoofer()
                elif choice == 2:
                    self.start_dns_spoofer()
                elif choice == 3:
                    self.start_packet_sniffer()
                elif choice == 4:
                    self.start_ssl_strip()
                elif choice == 5:
                    self.start_payload_injector()
                elif choice == 6:
                    print(f"{Fore.YELLOW}Use Web Cloner (option 8) for credential capture{Style.RESET_ALL}")
                elif choice == 7:
                    print(f"{Fore.YELLOW}Network scanner coming in future version{Style.RESET_ALL}")
                elif choice == 8:
                    self.start_web_cloner()
                elif choice == 9:
                    self.start_dashboard()
                elif choice == 10:
                    self.show_module_status()
                elif choice == 11:
                    self.edit_configuration()
                elif choice == 12:
                    self.view_logs()
                elif choice == 13:
                    self.stop_all_modules()
                elif choice == 0:
                    print(f"{Fore.YELLOW}Exiting MITM-X Framework...{Style.RESET_ALL}")
                    self.stop_all_modules()
                    break
                else:
                    print(f"{Fore.RED}Invalid option. Please try again.{Style.RESET_ALL}")
                
                # Pause before showing menu again
                if choice != 0:
                    input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Fore.YELLOW}Exiting MITM-X Framework...{Style.RESET_ALL}")
                self.stop_all_modules()
                break

def main():
    """
    Main function
    """
    parser = argparse.ArgumentParser(description="MITM-X Framework")
    parser.add_argument("--config", "-c", help="Configuration file path")
    parser.add_argument("--dashboard-only", action="store_true", help="Start only dashboard")
    parser.add_argument("--batch", "-b", help="Batch mode configuration file")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print(f"{Fore.RED}This framework requires root privileges!{Style.RESET_ALL}")
        print("Please run with: sudo python3 mitm_x.py")
        sys.exit(1)
    
    # Create framework instance
    framework = MITMFramework()
    
    if args.dashboard_only:
        # Start only dashboard
        print("Starting dashboard only...")
        framework.start_dashboard()
        try:
            # Keep running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            framework.stop_all_modules()
    else:
        # Run interactive mode
        framework.run_interactive_mode()

if __name__ == "__main__":
    main()
