# constants.py — Network configuration

import socket

# ── Change these to match your actual laptop IPs ──────────────
PROVISIONER_IP   = '10.90.175.28'   # Laptop 1 IP
DEVICE_IP        = '10.90.175.179'   # Laptop 2 IP

# If you add a relay laptop later:
RELAY_IP         = '192.168.1.20'   # Laptop 3 IP (optional)

# Ports — these stay the same on both laptops
PROVISIONER_PORT = 5001
DEVICE_PORT      = 5002
RELAY_PORT       = 5003

# Helper — auto detect which laptop you're running on
def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

# Message Type Codes
MSG_BEACON       = 0x01
MSG_CHALLENGE    = 0x02
MSG_RESPONSE     = 0x03
MSG_CONFIRMATION = 0x04
MSG_ACK          = 0x05

# Field sizes in bytes
DEVICE_ID_SIZE   = 4
NONCE_SIZE       = 16
HASH_SIZE        = 32
TIMESTAMP_SIZE   = 8
ADDRESS_SIZE     = 2

# Status codes
STATUS_SUCCESS   = 0x00
STATUS_FAILURE   = 0x01
