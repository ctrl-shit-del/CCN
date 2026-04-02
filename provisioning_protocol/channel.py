import socket
import threading
import time
from .common.packets import add_network_header, parse_network_header

_MSG_BEACON       = 0x01
_MSG_CHALLENGE    = 0x02
_MSG_RESPONSE     = 0x03
_MSG_CONFIRMATION = 0x04
_MSG_ACK          = 0x05

_MSG_NAMES = {
    _MSG_BEACON:       "Beacon",
    _MSG_CHALLENGE:    "Challenge",
    _MSG_RESPONSE:     "Response",
    _MSG_CONFIRMATION: "Confirmation",
    _MSG_ACK:          "ACK",
}

class NetworkChannel:
    """
    Simulates Bluetooth Mesh provisioning bearer
    using UDP sockets over localhost.
    Each entity binds to a real port — packets
    actually traverse the OS network stack.
    """
    
    PROVISIONER_PORT = 5001
    DEVICE_PORT      = 5002
    HOST             = '127.0.0.1'

    def __init__(self, role='provisioner', verbose=True, delay: float = 0.0):   
        """
        role: 'provisioner' or 'device'
        """
        self.role = role
        self.verbose = verbose
        self.delay = delay
        self.intercepted = []

        self.buffer = []
        self._session_start = None
        self._timestamps = {}
        self._total_bytes = 0
        self._packet_sizes = []

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if role == 'provisioner':
            self.bind_port  = self.PROVISIONER_PORT
            self.send_port  = 5003 # route to relay
        else:
            self.bind_port  = self.DEVICE_PORT
            self.send_port  = 5003 # route to relay

        self.sock.bind((self.HOST, self.bind_port))
        self.sock.settimeout(300.0)

    def send(self, sender_name, receiver_name, packet):
        now = time.perf_counter()
        if self.delay:
            time.sleep(self.delay)

        # Wrap in network layer
        src_addr = 0x0001 if self.role == 'provisioner' else 0x1001
        dst_addr = 0x1001 if self.role == 'provisioner' else 0x0001
        
        network_packet = add_network_header(packet, src_addr, dst_addr)

        self.sock.sendto(network_packet, (self.HOST, self.send_port))
        self.intercepted.append(network_packet)

        msg_type = packet[0] if len(packet) > 0 else 0xFF
        if msg_type not in self._timestamps:
            self._timestamps[msg_type] = now
        if self._session_start is None:
            self._session_start = now

        self._total_bytes += len(network_packet)
        self._packet_sizes.append(len(network_packet))

        if self.verbose:
            label = _MSG_NAMES.get(msg_type, f"0x{msg_type:02X}")
            print(f"\n[CHANNEL:{self.role}] Sent {len(network_packet)} bytes "
                  f"→ port {self.send_port} | {network_packet.hex()[:32]}...")
    
    def receive(self):
        try:
            data, addr = self.sock.recvfrom(4096)
            net_hdr = parse_network_header(data)
            payload = net_hdr['payload']
            
            if self.verbose:
                print(f"[CHANNEL:{self.role}] Recv {len(data)} bytes (TTL={net_hdr['ttl']}, SEQ={net_hdr['seq']}) "
                      f"← port {addr[1]}")
            return payload
        except socket.timeout:
            return None

    def close(self):
        self.sock.close()

    def get_session_metrics(self) -> dict:
        ts = self._timestamps
        def delta_ms(a, b):
            if a in ts and b in ts:
                return max(0.0, (ts[b] - ts[a]) * 1000)
            return 0.0

        sizes = self._packet_sizes
        n     = len(sizes)
        mean  = sum(sizes) / n if n else 0
        variance = sum((s - mean) ** 2 for s in sizes) / n if n else 0

        return {
            "beacon_to_challenge_ms":      delta_ms(_MSG_BEACON,       _MSG_CHALLENGE),
            "challenge_to_response_ms":    delta_ms(_MSG_CHALLENGE,    _MSG_RESPONSE),
            "response_to_confirmation_ms": delta_ms(_MSG_RESPONSE,     _MSG_CONFIRMATION),
            "confirmation_to_ack_ms":      delta_ms(_MSG_CONFIRMATION, _MSG_ACK),
            "end_to_end_ms":               delta_ms(_MSG_BEACON,       _MSG_ACK),
            "total_bytes":                 self._total_bytes,
            "num_packets":                 n,
            "packet_size_variance":        round(variance, 4),
        }

    def reset(self):
        self.intercepted.clear()
        self._session_start = None
        self._timestamps.clear()
        self._total_bytes   = 0
        self._packet_sizes  = []
