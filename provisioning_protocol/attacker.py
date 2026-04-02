from .common.packets import *
from .common.crypto import *
from .common.constants import *

class Attacker:
    def __init__(self, channel):
        self.channel = channel
        self.captured_packets = []

    def capture_all(self):
        self.captured_packets = list(self.channel.intercepted)
        print(f"\n[ATTACKER] Captured {len(self.captured_packets)} packets")

    def replay_attack(self, target_channel):
        """Replay attack: resend a captured Response in a new provisioning session.
        Defeated because NonceP in the new session is fresh — the Auth Token
        (which binds the old NonceP) will not verify.
        """
        print("\n[ATTACKER] ════ REPLAY ATTACK INITIATED ════")
        for pkt in self.captured_packets:
            if pkt[0] == MSG_RESPONSE:
                print(f"[ATTACKER] Replaying captured Response: {pkt.hex()[:40]}...")
                target_channel.send("Attacker", "Provisioner", pkt)
                return True
        print("[ATTACKER] No Response packet captured to replay")
        return False

    def craft_relayed_challenge(self, real_challenge_packet, fake_provisioner_id):
        """Relay attack: intercept the Challenge from the real provisioner and
        replace ProvisionerID with a fake identity before forwarding to the device.

        The device will compute transcript_hash and auth_token over the FAKE
        ProvisionerID.  When the provisioner later recomputes the transcript
        using its own (real) ID, the SHA-256 digests will differ and
        verification fails — demonstrating that ProvisionerID binding defeats
        the relay attack.
        """
        print("\n[ATTACKER] ════ RELAY ATTACK — tampering Challenge ════")
        parsed = parse_challenge(real_challenge_packet)
        print(f"[ATTACKER] Real ProvisionerID  : {parsed['provisioner_id'].hex()}")
        print(f"[ATTACKER] Injected fake ID    : {fake_provisioner_id.hex()}")
        tampered = build_challenge(
            fake_provisioner_id,
            parsed['nonce_p'],
            parsed['timestamp'],
        )
        print(f"[ATTACKER] Tampered Challenge injected into device channel")
        return tampered

    def misbinding_attack(self, target_channel, spoof_device_id):
        """Misbinding attack: take a captured Response (from Device A) and replace
        the DeviceID field with a different device's identity (Device B).

        The provisioner recomputes the transcript hash using Device B's ID —
        producing a different digest from the one Device A embedded in the
        packet.  The transcript hash check detects the substitution and the
        verification fails.
        """
        print("\n[ATTACKER] ════ MISBINDING ATTACK — spoofing DeviceID ════")
        for pkt in self.captured_packets:
            if pkt[0] == MSG_RESPONSE:
                parsed = parse_response(pkt)
                print(f"[ATTACKER] Original DeviceID : {parsed['device_id'].hex()}")
                print(f"[ATTACKER] Spoofed  DeviceID : {spoof_device_id.hex()}")
                # Rebuild Response with spoofed DeviceID — auth_token and
                # transcript_hash are left exactly as Device A computed them.
                tampered = build_response(
                    spoof_device_id,
                    parsed['auth_token'],
                    parsed['transcript_hash'],
                    parsed['nonce_d'],
                )
                print(f"[ATTACKER] Tampered Response injected into provisioner channel")
                target_channel.send("Attacker(misbinding)", "Provisioner", tampered)
                return True
        print("[ATTACKER] No Response packet captured for misbinding")
        return False