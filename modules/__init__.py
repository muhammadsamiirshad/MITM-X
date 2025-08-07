"""
MITM-X Framework - Core Module Initialization
Author: Security Research Team
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"
__description__ = "Advanced MITM Framework for Penetration Testing"

# Import all modules for easy access
from .arp_spoofer import ARPSpoofer
from .dns_spoofer import DNSSpoofer
from .packet_sniffer import PacketSniffer
from .ssl_strip import SSLStrip
from .payload_injector import PayloadInjector
from .web_cloner import WebCloner
from .dashboard import Dashboard

__all__ = [
    'ARPSpoofer',
    'DNSSpoofer', 
    'PacketSniffer',
    'SSLStrip',
    'PayloadInjector',
    'WebCloner',
    'Dashboard'
]
