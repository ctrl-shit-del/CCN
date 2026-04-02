import struct
from .constants import *

def build_beacon(device_id, nonce_d, capabilities=0x0001):
    """
    Message 1: Device → Provisioner
    Format: [MsgType(1)] [DeviceID(4)] [Capabilities(2)] [NonceD(16)]
    """
    packet = struct.pack('!B', MSG_BEACON)
    packet += device_id                          # 4 bytes
    packet += struct.pack('!H', capabilities)    # 2 bytes
    packet += nonce_d                            # 16 bytes
    return packet

def parse_beacon(packet):
    msg_type = packet[0]
    device_id = packet[1:5]
    capabilities = struct.unpack('!H', packet[5:7])[0]
    nonce_d = packet[7:23]
    return {'type': msg_type, 'device_id': device_id,
            'capabilities': capabilities, 'nonce_d': nonce_d}

def build_challenge(provisioner_id, nonce_p, timestamp):
    """
    Message 2: Provisioner → Device
    Format: [MsgType(1)] [ProvisionerID(4)] [NonceP(16)] [Timestamp(8)]
    """
    packet = struct.pack('!B', MSG_CHALLENGE)
    packet += provisioner_id                     # 4 bytes
    packet += nonce_p                            # 16 bytes
    packet += timestamp                          # 8 bytes
    return packet

def parse_challenge(packet):
    msg_type = packet[0]
    provisioner_id = packet[1:5]
    nonce_p = packet[5:21]
    timestamp = packet[21:29]
    return {'type': msg_type, 'provisioner_id': provisioner_id,
            'nonce_p': nonce_p, 'timestamp': timestamp}

def build_response(device_id, auth_token, transcript_hash, nonce_d):
    """
    Message 3: Device → Provisioner
    Format: [MsgType(1)] [DeviceID(4)] [AuthToken(16)] [Hash(32)] [NonceD(16)]
    """
    packet = struct.pack('!B', MSG_RESPONSE)
    packet += device_id                          # 4 bytes
    packet += auth_token                         # 16 bytes
    packet += transcript_hash                    # 32 bytes
    packet += nonce_d                            # 16 bytes
    return packet

def parse_response(packet):
    msg_type = packet[0]
    device_id = packet[1:5]
    auth_token = packet[5:21]
    transcript_hash = packet[21:53]
    nonce_d = packet[53:69]
    return {'type': msg_type, 'device_id': device_id,
            'auth_token': auth_token, 'transcript_hash': transcript_hash,
            'nonce_d': nonce_d}

def build_confirmation(assigned_address, session_key_id, confirm_token):
    """
    Message 4: Provisioner → Device
    Format: [MsgType(1)] [Address(2)] [SessionKeyID(4)] [ConfirmToken(16)]
    """
    packet = struct.pack('!B', MSG_CONFIRMATION)
    packet += struct.pack('!H', assigned_address)  # 2 bytes
    packet += struct.pack('!I', session_key_id)    # 4 bytes
    packet += confirm_token                         # 16 bytes
    return packet

def parse_confirmation(packet):
    msg_type = packet[0]
    assigned_address = struct.unpack('!H', packet[1:3])[0]
    session_key_id = struct.unpack('!I', packet[3:7])[0]
    confirm_token = packet[7:23]
    return {'type': msg_type, 'assigned_address': assigned_address,
            'session_key_id': session_key_id, 'confirm_token': confirm_token}

def build_ack(device_id, status=STATUS_SUCCESS):
    """
    Message 5: Device → Provisioner
    Format: [MsgType(1)] [DeviceID(4)] [Status(1)]
    """
    packet = struct.pack('!B', MSG_ACK)
    packet += device_id
    packet += struct.pack('!B', status)
    return packet

def parse_ack(packet):
    msg_type = packet[0]
    device_id = packet[1:5]
    status = packet[5]
    return {'type': msg_type, 'device_id': device_id, 'status': status}
# ==============================================================================
# NETWORK LAYER ENCAPSULATION
# ==============================================================================

def add_network_header(payload, src_addr, dst_addr, ttl=7):
    """
    Wraps any provisioning message in a network-layer header.
    Mirrors Bluetooth Mesh network PDU structure.
    
    Network Header Format:
    | TTL (1B) | Seq (4B) | Src Addr (2B) | Dst Addr (2B) | Payload |
    """
    header = struct.pack('!B I H H',
        ttl,           # 1 byte  — Time To Live
        next_seq(),    # 4 bytes — Sequence number
        src_addr,      # 2 bytes — Source unicast address
        dst_addr       # 2 bytes — Destination address
    )
    return header + payload

def parse_network_header(packet):
    ttl, seq, src, dst = struct.unpack('!B I H H', packet[:9])
    payload = packet[9:]
    return {
        'ttl'    : ttl,
        'seq'    : seq,
        'src'    : src,
        'dst'    : dst,
        'payload': payload
    }

_seq_counter = 0
def next_seq():
    global _seq_counter
    _seq_counter += 1
    return _seq_counter
