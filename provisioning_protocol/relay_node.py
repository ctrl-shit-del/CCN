import socket
import struct
from .common.packets import parse_network_header, add_network_header
import time
from .topology_display import print_topology

class RelayNode:
    """
    Simulates a Bluetooth Mesh relay node.
    """
    
    def __init__(self, node_addr=0xAAAA, listen_port=5003, provisioner_port=5001, device_port=5002):
        self.node_addr    = node_addr
        self.listen_port  = listen_port
        self.provisioner_port = provisioner_port
        self.device_port  = device_port
        self.seq_cache    = set()
        self.relay_count  = 0
        self.drop_count   = 0
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', listen_port))
        print(f"[RELAY 0x{node_addr:04X}] Listening on port {listen_port}")
    
    def run(self):
        while True:
            data, addr = self.sock.recvfrom(4096)
            self._process(data, addr)
    
    def _process(self, data, addr):
        net = parse_network_header(data)
        
        seq = net['seq']
        ttl = net['ttl']
        
        if seq in self.seq_cache:
            self.drop_count += 1
            print(f"[RELAY 0x{self.node_addr:04X}] DROP duplicate SEQ={seq}")
            return
        
        if ttl <= 1:
            self.drop_count += 1
            print(f"[RELAY 0x{self.node_addr:04X}] DROP TTL expired SEQ={seq}")
            return
        
        self.seq_cache.add(seq)
        
        new_ttl = ttl - 1
        forwarded = add_network_header(
            net['payload'],
            src_addr = net['src'],
            dst_addr = net['dst'],
            ttl      = new_ttl
        )
        
        # Naive routing: If src is 0x0001 (provisioner), send to device. Else send to provisioner.
        if net['src'] == 0x0001:
            dest_port = self.device_port
        else:
            dest_port = self.provisioner_port
            
        # Determine for topology display
        app_msg = forwarded[9:]
        msg_type = app_msg[0] if len(app_msg) > 0 else 0xFF
        
        if msg_type == 0x01: # BEACON
            print_topology('beacon_relay', f"Relay routing Beacon (TTL {new_ttl}) to Provisioner")
        elif msg_type == 0x02: # CHALLENGE
            print_topology('challenge', f"Relay routing Challenge (TTL {new_ttl}) to Device")
        elif msg_type == 0x05: # ACK
            print_topology('complete', f"Relay routing ACK (TTL {new_ttl}) to complete session!")
            
        self.sock.sendto(
            forwarded,
            ('127.0.0.1', dest_port)
        )
        self.relay_count += 1
        
        print(f"[RELAY 0x{self.node_addr:04X}] FWD SEQ={seq} TTL {ttl}→{new_ttl} ({len(data)}B) → port {dest_port}")

if __name__ == "__main__":
    relay = RelayNode()
    relay.run()
