# channel.py — Two-laptop version

import socket
import struct
import time
from common.constants import *

class NetworkChannel:
    def __init__(self, role, verbose=True):
        """
        role: 'provisioner' or 'device'
        Automatically binds to correct IP and port based on role.
        """
        self.role    = role
        self.verbose = verbose
        self.intercepted = []
        
        self.sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )
        
        # Allow port reuse — important for demo restarts
        self.sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR, 1
        )
        
        if role == 'provisioner':
            # Provisioner binds on its own IP
            self.my_ip       = PROVISIONER_IP
            self.my_port     = PROVISIONER_PORT
            self.target_ip   = DEVICE_IP
            self.target_port = DEVICE_PORT
            
        elif role == 'device':
            # Device binds on its own IP
            self.my_ip       = DEVICE_IP
            self.my_port     = DEVICE_PORT
            self.target_ip   = PROVISIONER_IP
            self.target_port = PROVISIONER_PORT
        
        # Bind to 0.0.0.0 so it accepts from any interface
        self.sock.bind(('0.0.0.0', self.my_port))
        self.sock.settimeout(30.0)   # 30s timeout for demo
        
        print(f"[NET] {role.upper()} bound to port {self.my_port}")
        print(f"[NET] Will communicate with {self.target_ip}:{self.target_port}")
    
    def send(self, *args):
        """Send packet to the other laptop"""
        if len(args) >= 3:
            packet = args[2]
            label = ""
        elif len(args) == 2:
            packet = args[0]
            label = args[1]
        else:
            packet = args[0]
            label = ""
            
        self.sock.sendto(packet, (self.target_ip, self.target_port))
        self.intercepted.append(packet)
        
        if self.verbose:
            tag = f"[{label}]" if label else ""
            print(f"\n[NET:{self.role}→{self.target_ip}] "
                  f"{tag} {len(packet)} bytes sent")
            print(f"  Hex: {packet.hex()[:48]}...")
    
    def receive(self):
        """Receive packet from the other laptop"""
        data, addr = self.sock.recvfrom(4096)
        
        if self.verbose:
            print(f"\n[NET:{self.role}←{addr[0]}:{addr[1]}] "
                  f"{len(data)} bytes received")
        
        return data
    
    def close(self):
        self.sock.close()
