from .common.crypto import *
from .common.packets import *
from .common.constants import *

class Device:
    def __init__(self, device_id, k_device, verbose=True):
        self.device_id = device_id
        self.k_device = k_device
        self.verbose = verbose
        self.session_key = None
        self.assigned_address = None
        self.nonce_d = generate_nonce()

    def _log(self, msg):
        if self.verbose:
            print(msg)

    def send_beacon(self, channel):
        """Step 1: Broadcast beacon"""
        beacon = build_beacon(self.device_id, self.nonce_d)
        channel.send("Device", "Provisioner", beacon)
        self._log(f"\n[DEVICE] Beacon sent. DeviceID: {self.device_id.hex()}")

    def handle_challenge(self, channel):
        """Step 2: Receive challenge, compute and send response"""
        raw = channel.receive()
        challenge = parse_challenge(raw)

        self.provisioner_id = challenge['provisioner_id']
        self.nonce_p = challenge['nonce_p']
        self.timestamp = challenge['timestamp']

        self._log(f"\n[DEVICE] Challenge received. NonceP: {self.nonce_p.hex()}")

        # Compute context-bound transcript hash
        transcript_hash = compute_transcript_hash(
            self.device_id,
            self.provisioner_id,
            self.nonce_p,
            self.nonce_d,
            self.timestamp
        )

        # Compute auth token using own secret key
        auth_token = compute_auth_token(self.k_device, transcript_hash)

        response = build_response(
            self.device_id,
            auth_token,
            transcript_hash,
            self.nonce_d
        )
        channel.send("Device", "Provisioner", response)
        self._log("[DEVICE] Response sent with context-bound Auth Token")

    def handle_confirmation(self, channel):
        """Step 3: Receive confirmation, derive session key, send ACK"""
        raw = channel.receive()
        confirmation = parse_confirmation(raw)

        self.assigned_address = confirmation['assigned_address']
        self._log(f"\n[DEVICE] Confirmation received. Assigned address: {self.assigned_address}")

        # Derive session key independently
        self.session_key = derive_session_key(
            self.k_device,
            self.nonce_p,
            self.nonce_d
        )
        self._log(f"[DEVICE] Session key derived: {self.session_key.hex()}")

        ack = build_ack(self.device_id, STATUS_SUCCESS)
        channel.send("Device", "Provisioner", ack)
        self._log("[DEVICE] ACK sent — Provisioning COMPLETE ✓")