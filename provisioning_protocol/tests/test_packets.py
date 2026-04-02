"""
test_packets.py
Unit tests for provisioning_protocol/common/packets.py  (PRD §6.3, FR-1)

Validates:
  - Correct byte sizes for every message type
  - Build → parse round-trips (all fields survive serialisation)
  - Correct message type byte in each packet
  - Field-offset integrity (no off-by-one in struct parsing)

Run:
    python -m pytest provisioning_protocol/tests/test_packets.py -v
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from provisioning_protocol.common.packets import (
    build_beacon,      parse_beacon,
    build_challenge,   parse_challenge,
    build_response,    parse_response,
    build_confirmation, parse_confirmation,
    build_ack,         parse_ack,
)
from provisioning_protocol.common.constants import (
    MSG_BEACON, MSG_CHALLENGE, MSG_RESPONSE, MSG_CONFIRMATION, MSG_ACK,
    STATUS_SUCCESS, STATUS_FAILURE,
)


# ── Fixed test values ───────────────────────────────────────────────────

DEVICE_ID      = b'\xDE\xAD\xBE\xEF'
PROVISIONER_ID = b'\x50\x52\x4F\x56'
NONCE_D        = bytes(range(16))
NONCE_P        = bytes(range(16, 32))
TIMESTAMP      = bytes(range(8))
AUTH_TOKEN     = bytes(range(32, 48))         # 16 bytes
TRANSCRIPT     = bytes(range(64, 96))         # 32 bytes
CONFIRM_TOKEN  = bytes(range(48, 64))         # 16 bytes
ADDRESS        = 0x1001
SESSION_KEY_ID = 0xABCD1234
CAPABILITIES   = 0x0001


# ══════════════════════════════════════════════════════════════════════
# Message 1 — Beacon  (1+4+2+16 = 23 bytes)
# ══════════════════════════════════════════════════════════════════════

class TestBeacon(unittest.TestCase):

    def setUp(self):
        self.pkt = build_beacon(DEVICE_ID, NONCE_D, capabilities=CAPABILITIES)

    def test_packet_size(self):
        """Beacon must be exactly 23 bytes (PRD §6.3 Message 1)."""
        self.assertEqual(len(self.pkt), 23)

    def test_msg_type_byte(self):
        self.assertEqual(self.pkt[0], MSG_BEACON)

    def test_round_trip_device_id(self):
        parsed = parse_beacon(self.pkt)
        self.assertEqual(parsed["device_id"], DEVICE_ID)

    def test_round_trip_nonce_d(self):
        parsed = parse_beacon(self.pkt)
        self.assertEqual(parsed["nonce_d"], NONCE_D)

    def test_round_trip_capabilities(self):
        parsed = parse_beacon(self.pkt)
        self.assertEqual(parsed["capabilities"], CAPABILITIES)

    def test_msg_type_in_parsed_dict(self):
        parsed = parse_beacon(self.pkt)
        self.assertEqual(parsed["type"], MSG_BEACON)

    def test_nonce_d_length(self):
        """NonceD must occupy 16 bytes in the packet (PRD field size)."""
        parsed = parse_beacon(self.pkt)
        self.assertEqual(len(parsed["nonce_d"]), 16)


# ══════════════════════════════════════════════════════════════════════
# Message 2 — Challenge  (1+4+16+8 = 29 bytes)
# ══════════════════════════════════════════════════════════════════════

class TestChallenge(unittest.TestCase):

    def setUp(self):
        self.pkt = build_challenge(PROVISIONER_ID, NONCE_P, TIMESTAMP)

    def test_packet_size(self):
        """Challenge must be exactly 29 bytes (PRD §6.3 Message 2)."""
        self.assertEqual(len(self.pkt), 29)

    def test_msg_type_byte(self):
        self.assertEqual(self.pkt[0], MSG_CHALLENGE)

    def test_round_trip_provisioner_id(self):
        parsed = parse_challenge(self.pkt)
        self.assertEqual(parsed["provisioner_id"], PROVISIONER_ID)

    def test_round_trip_nonce_p(self):
        parsed = parse_challenge(self.pkt)
        self.assertEqual(parsed["nonce_p"], NONCE_P)

    def test_round_trip_timestamp(self):
        parsed = parse_challenge(self.pkt)
        self.assertEqual(parsed["timestamp"], TIMESTAMP)

    def test_nonce_p_length(self):
        parsed = parse_challenge(self.pkt)
        self.assertEqual(len(parsed["nonce_p"]), 16)

    def test_timestamp_length(self):
        parsed = parse_challenge(self.pkt)
        self.assertEqual(len(parsed["timestamp"]), 8)


# ══════════════════════════════════════════════════════════════════════
# Message 3 — Response  (1+4+16+32+16 = 69 bytes)
# ══════════════════════════════════════════════════════════════════════

class TestResponse(unittest.TestCase):

    def setUp(self):
        self.pkt = build_response(DEVICE_ID, AUTH_TOKEN, TRANSCRIPT, NONCE_D)

    def test_packet_size(self):
        """Response must be exactly 69 bytes (PRD §6.3 Message 3)."""
        self.assertEqual(len(self.pkt), 69)

    def test_msg_type_byte(self):
        self.assertEqual(self.pkt[0], MSG_RESPONSE)

    def test_round_trip_device_id(self):
        parsed = parse_response(self.pkt)
        self.assertEqual(parsed["device_id"], DEVICE_ID)

    def test_round_trip_auth_token(self):
        parsed = parse_response(self.pkt)
        self.assertEqual(parsed["auth_token"], AUTH_TOKEN)

    def test_round_trip_transcript_hash(self):
        parsed = parse_response(self.pkt)
        self.assertEqual(parsed["transcript_hash"], TRANSCRIPT)

    def test_round_trip_nonce_d(self):
        parsed = parse_response(self.pkt)
        self.assertEqual(parsed["nonce_d"], NONCE_D)

    def test_auth_token_length(self):
        parsed = parse_response(self.pkt)
        self.assertEqual(len(parsed["auth_token"]), 16)

    def test_transcript_hash_length(self):
        """Transcript hash must be 32 bytes — SHA-256 output (PRD §6.4)."""
        parsed = parse_response(self.pkt)
        self.assertEqual(len(parsed["transcript_hash"]), 32)


# ══════════════════════════════════════════════════════════════════════
# Message 4 — Confirmation  (1+2+4+16 = 23 bytes)
# ══════════════════════════════════════════════════════════════════════

class TestConfirmation(unittest.TestCase):

    def setUp(self):
        self.pkt = build_confirmation(ADDRESS, SESSION_KEY_ID, CONFIRM_TOKEN)

    def test_packet_size(self):
        """Confirmation must be exactly 23 bytes (PRD §6.3 Message 4)."""
        self.assertEqual(len(self.pkt), 23)

    def test_msg_type_byte(self):
        self.assertEqual(self.pkt[0], MSG_CONFIRMATION)

    def test_round_trip_address(self):
        parsed = parse_confirmation(self.pkt)
        self.assertEqual(parsed["assigned_address"], ADDRESS)

    def test_round_trip_session_key_id(self):
        parsed = parse_confirmation(self.pkt)
        self.assertEqual(parsed["session_key_id"], SESSION_KEY_ID)

    def test_round_trip_confirm_token(self):
        parsed = parse_confirmation(self.pkt)
        self.assertEqual(parsed["confirm_token"], CONFIRM_TOKEN)

    def test_confirm_token_length(self):
        parsed = parse_confirmation(self.pkt)
        self.assertEqual(len(parsed["confirm_token"]), 16)


# ══════════════════════════════════════════════════════════════════════
# Message 5 — ACK  (1+4+1 = 6 bytes)
# ══════════════════════════════════════════════════════════════════════

class TestAck(unittest.TestCase):

    def test_packet_size_success(self):
        """ACK must be exactly 6 bytes (PRD §6.3 Message 5)."""
        pkt = build_ack(DEVICE_ID, STATUS_SUCCESS)
        self.assertEqual(len(pkt), 6)

    def test_msg_type_byte(self):
        pkt = build_ack(DEVICE_ID)
        self.assertEqual(pkt[0], MSG_ACK)

    def test_round_trip_device_id(self):
        pkt    = build_ack(DEVICE_ID, STATUS_SUCCESS)
        parsed = parse_ack(pkt)
        self.assertEqual(parsed["device_id"], DEVICE_ID)

    def test_round_trip_status_success(self):
        pkt    = build_ack(DEVICE_ID, STATUS_SUCCESS)
        parsed = parse_ack(pkt)
        self.assertEqual(parsed["status"], STATUS_SUCCESS)

    def test_round_trip_status_failure(self):
        pkt    = build_ack(DEVICE_ID, STATUS_FAILURE)
        parsed = parse_ack(pkt)
        self.assertEqual(parsed["status"], STATUS_FAILURE)


# ══════════════════════════════════════════════════════════════════════
# Cross-message: total bytes per provisioning session = 150
# (PRD §13 Evaluation Metrics — "Total bytes per provisioning session")
# ══════════════════════════════════════════════════════════════════════

class TestSessionTotalBytes(unittest.TestCase):

    def test_total_session_bytes(self):
        """Sum of all 5 message sizes must equal 150 bytes (PRD §6.3 tables)."""
        sizes = [
            len(build_beacon(DEVICE_ID, NONCE_D)),
            len(build_challenge(PROVISIONER_ID, NONCE_P, TIMESTAMP)),
            len(build_response(DEVICE_ID, AUTH_TOKEN, TRANSCRIPT, NONCE_D)),
            len(build_confirmation(ADDRESS, SESSION_KEY_ID, CONFIRM_TOKEN)),
            len(build_ack(DEVICE_ID)),
        ]
        self.assertEqual(sum(sizes), 150)
        self.assertEqual(sizes, [23, 29, 69, 23, 6])


if __name__ == "__main__":
    unittest.main(verbosity=2)
