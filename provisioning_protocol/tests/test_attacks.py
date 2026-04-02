"""
test_attacks.py
Integration tests for all three attack scenarios  (PRD §7.2, FR-5, FR-6)

Each test runs a real provisioning session via the actual modules,
then executes the attack and asserts the provisioner returns False
and enters the ERROR state.

Run:
    python -m pytest provisioning_protocol/tests/test_attacks.py -v
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from provisioning_protocol.provisioner import Provisioner
from provisioning_protocol.device      import Device
from provisioning_protocol.channel     import NetworkChannel
from provisioning_protocol.attacker    import Attacker


# ── Shared setup helpers ────────────────────────────────────────────────

PROVISIONER_ID   = b'\x50\x52\x4F\x56'
DEVICE_ID_A      = b'\xDE\xAD\xBE\xEF'
DEVICE_ID_B      = b'\xCA\xFE\xF0\x0D'
FAKE_PROV_ID     = b'\xFA\xCE\xCA\xFE'


def _fresh_keys():
    """Return (k_a, k_b) fresh random device keys."""
    return os.urandom(16), os.urandom(16)


def _run_full_session(device_id, k_device, device_db, verbose=False):
    """Run a complete normal 5-message session and return (provisioner, device, channel)."""
    ch   = NetworkChannel(verbose=verbose)
    prov = Provisioner(PROVISIONER_ID, device_db)
    dev  = Device(device_id, k_device)

    dev.send_beacon(ch)
    prov.handle_beacon(ch)
    dev.handle_challenge(ch)
    prov.handle_response(ch)
    dev.handle_confirmation(ch)
    prov.handle_ack(ch)
    return prov, dev, ch


# ══════════════════════════════════════════════════════════════════════
# Normal provisioning — sanity baseline
# ══════════════════════════════════════════════════════════════════════

class TestNormalProvisioning(unittest.TestCase):

    def setUp(self):
        self.k_a, _ = _fresh_keys()
        self.db     = {DEVICE_ID_A: self.k_a}

    def test_handshake_completes(self):
        """Full 5-message handshake must reach COMPLETE state."""
        prov, dev, _ = _run_full_session(DEVICE_ID_A, self.k_a, self.db)
        self.assertEqual(prov.state, "COMPLETE")

    def test_session_keys_match(self):
        """Provisioner and device must independently derive the same session key (FR-4)."""
        prov, dev, _ = _run_full_session(DEVICE_ID_A, self.k_a, self.db)
        self.assertIsNotNone(prov.session_key)
        self.assertIsNotNone(dev.session_key)
        self.assertEqual(prov.session_key, dev.session_key)

    def test_device_receives_address(self):
        """Device must receive a non-zero unicast address after provisioning."""
        _, dev, _ = _run_full_session(DEVICE_ID_A, self.k_a, self.db)
        self.assertIsNotNone(dev.assigned_address)
        self.assertGreater(dev.assigned_address, 0)


# ══════════════════════════════════════════════════════════════════════
# Replay attack  (PRD §7.2 row 1)
# ══════════════════════════════════════════════════════════════════════

class TestReplayAttack(unittest.TestCase):
    """
    Scenario: attacker captures a valid Response from Session 1 and
    replays it in Session 2 where the provisioner has issued a fresh NonceP.
    The Auth Token is bound to the old NonceP → mismatch → rejected.
    """

    def setUp(self):
        self.k_a, _ = _fresh_keys()
        self.db     = {DEVICE_ID_A: self.k_a}

    def test_replayed_response_rejected(self):
        # ── Session 1: capture a legitimate Response ──────────────────
        ch1   = NetworkChannel(verbose=False)
        prov1 = Provisioner(PROVISIONER_ID, self.db)
        dev1  = Device(DEVICE_ID_A, self.k_a)
        dev1.send_beacon(ch1)
        prov1.handle_beacon(ch1)
        dev1.handle_challenge(ch1)
        # Response is now in ch1.buffer; also visible via intercepted
        att1  = Attacker(ch1)
        att1.capture_all()

        old_response = next(
            (p for p in att1.captured_packets if p[0] == 0x03), None
        )
        self.assertIsNotNone(old_response, "No Response captured from Session 1")

        # ── Session 2: fresh nonces ────────────────────────────────────
        ch2   = NetworkChannel(verbose=False)
        prov2 = Provisioner(PROVISIONER_ID, self.db)
        dev2  = Device(DEVICE_ID_A, self.k_a)
        dev2.send_beacon(ch2)
        prov2.handle_beacon(ch2)
        # Discard dev2's fresh response; inject old one instead
        ch2.buffer.clear()
        ch2.buffer.append(old_response)

        result = prov2.handle_response(ch2)
        self.assertFalse(result,  "Provisioner must reject a replayed Response")
        self.assertEqual(prov2.state, "ERROR",
                         "Provisioner must enter ERROR state after replay")

    def test_fresh_session_still_succeeds(self):
        """Control: a legitimate second session must succeed even after a replay attempt."""
        prov, dev, _ = _run_full_session(DEVICE_ID_A, self.k_a, self.db)
        self.assertEqual(prov.state, "COMPLETE")


# ══════════════════════════════════════════════════════════════════════
# Relay attack  (PRD §7.2 row 2)
# ══════════════════════════════════════════════════════════════════════

class TestRelayAttack(unittest.TestCase):
    """
    Scenario: attacker intercepts the Challenge and substitutes a fake
    ProvisionerID before forwarding to the device.  The device binds its
    Auth Token to the fake ID; the provisioner recomputes with the real ID
    → transcript hash mismatch → rejected.
    """

    def setUp(self):
        self.k_a, _ = _fresh_keys()
        self.db     = {DEVICE_ID_A: self.k_a}

    def test_tampered_challenge_rejected(self):
        ch   = NetworkChannel(verbose=False)
        prov = Provisioner(PROVISIONER_ID, self.db)
        dev  = Device(DEVICE_ID_A, self.k_a)
        att  = Attacker(ch)

        dev.send_beacon(ch)
        prov.handle_beacon(ch)

        # Attacker intercepts the Challenge before the device reads it
        real_challenge = ch.buffer.pop(0)
        tampered = att.craft_relayed_challenge(real_challenge, FAKE_PROV_ID)
        ch.buffer.insert(0, tampered)

        dev.handle_challenge(ch)            # device receives tampered version
        result = prov.handle_response(ch)   # provisioner recomputes with real ID

        self.assertFalse(result, "Provisioner must reject relay-tampered Response")
        self.assertEqual(prov.state, "ERROR")

    def test_without_tampering_succeeds(self):
        """Control: session without relay MUST still complete successfully."""
        prov, dev, _ = _run_full_session(DEVICE_ID_A, self.k_a, self.db)
        self.assertEqual(prov.state, "COMPLETE")


# ══════════════════════════════════════════════════════════════════════
# Misbinding attack  (PRD §7.2 row 3)
# ══════════════════════════════════════════════════════════════════════

class TestMisbindingAttack(unittest.TestCase):
    """
    Scenario: attacker captures Device A's valid Response and replaces
    the DeviceID field with Device B's identity.  The provisioner detects
    the beacon/response DeviceID mismatch immediately before any crypto.
    """

    def setUp(self):
        self.k_a, self.k_b = _fresh_keys()
        self.db = {DEVICE_ID_A: self.k_a, DEVICE_ID_B: self.k_b}

    def test_spoofed_device_id_rejected(self):
        # Run Device A's session up to (and including) the Response
        ch   = NetworkChannel(verbose=False)
        prov = Provisioner(PROVISIONER_ID, self.db)
        dev  = Device(DEVICE_ID_A, self.k_a)
        att  = Attacker(ch)

        dev.send_beacon(ch)
        prov.handle_beacon(ch)
        dev.handle_challenge(ch)
        att.capture_all()

        # Remove legitimate Response; inject misbinding tampered one
        ch.buffer.clear()
        att.misbinding_attack(ch, DEVICE_ID_B)

        result = prov.handle_response(ch)
        self.assertFalse(result, "Provisioner must reject spoofed DeviceID")
        self.assertEqual(prov.state, "ERROR")

    def test_error_message_identifies_misbinding(self):
        """Provisioner must detect the beacon↔response DeviceID mismatch."""
        ch   = NetworkChannel(verbose=False)
        prov = Provisioner(PROVISIONER_ID, self.db)
        dev  = Device(DEVICE_ID_A, self.k_a)
        att  = Attacker(ch)

        dev.send_beacon(ch)
        prov.handle_beacon(ch)
        dev.handle_challenge(ch)
        att.capture_all()
        ch.buffer.clear()
        att.misbinding_attack(ch, DEVICE_ID_B)

        # current_device_id set from Beacon must remain Device A
        self.assertEqual(prov.current_device_id, DEVICE_ID_A)

        prov.handle_response(ch)
        # After the call, state must be ERROR
        self.assertEqual(prov.state, "ERROR")

    def test_unknown_device_id_rejected(self):
        """A Response carrying an entirely unknown DeviceID must also be rejected."""
        ch   = NetworkChannel(verbose=False)
        prov = Provisioner(PROVISIONER_ID, self.db)
        dev  = Device(DEVICE_ID_A, self.k_a)
        att  = Attacker(ch)

        dev.send_beacon(ch)
        prov.handle_beacon(ch)
        dev.handle_challenge(ch)
        att.capture_all()
        ch.buffer.clear()

        # Spoof to an ID not in either device's DB
        att.misbinding_attack(ch, b'\xDE\xAD\x00\x01')
        result = prov.handle_response(ch)
        self.assertFalse(result)
        self.assertEqual(prov.state, "ERROR")


# ══════════════════════════════════════════════════════════════════════
# Channel interception (FR-5)
# ══════════════════════════════════════════════════════════════════════

class TestChannelInterception(unittest.TestCase):

    def test_attacker_sees_all_packets(self):
        """All 5 messages must appear in channel.intercepted (FR-5)."""
        k_a = os.urandom(16)
        db  = {DEVICE_ID_A: k_a}
        _run_full_session(DEVICE_ID_A, k_a, db, verbose=False)
        # We didn't keep ch above; redo to get reference
        ch   = NetworkChannel(verbose=False)
        prov = Provisioner(PROVISIONER_ID, db)
        dev  = Device(DEVICE_ID_A, k_a)
        dev.send_beacon(ch)
        prov.handle_beacon(ch)
        dev.handle_challenge(ch)
        prov.handle_response(ch)
        dev.handle_confirmation(ch)
        prov.handle_ack(ch)
        self.assertEqual(len(ch.intercepted), 5,
                         "Channel must have intercepted exactly 5 packets")

    def test_session_metrics_populated(self):
        """get_session_metrics() must return non-zero total bytes after a session."""
        k_a = os.urandom(16)
        db  = {DEVICE_ID_A: k_a}
        ch  = NetworkChannel(verbose=False)
        prov = Provisioner(PROVISIONER_ID, db)
        dev  = Device(DEVICE_ID_A, k_a)
        dev.send_beacon(ch)
        prov.handle_beacon(ch)
        dev.handle_challenge(ch)
        prov.handle_response(ch)
        dev.handle_confirmation(ch)
        prov.handle_ack(ch)
        m = ch.get_session_metrics()
        self.assertEqual(m["total_bytes"], 150)
        self.assertEqual(m["num_packets"], 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
