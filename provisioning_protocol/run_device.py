# provisioning_protocol/run_device.py

import os, sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
))

from provisioning_protocol.device import Device
from provisioning_protocol.channel import NetworkChannel
from common.constants import DEVICE_IP, DEVICE_PORT

PROVISIONER_ID = b'\x50\x52\x4F\x56'
DEVICE_ID      = b'\xDE\xAD\xBE\xEF'
K_DEVICE       = bytes.fromhex('973560d3d7cf76fb5cbac9f6a086c9e1')

# Helper functions for attack injection
def modify_device_id(packet, new_id):
    """Modify the DeviceID (bytes 1:5) in an outgoing Response packet"""
    attack_pkt = bytearray(packet)
    attack_pkt[1:5] = new_id
    return bytes(attack_pkt)

def override_provisioner_id(packet, fake_id):
    """Modify the ProvisionerID (bytes 1:5) in an incoming Challenge packet"""
    attack_pkt = bytearray(packet)
    attack_pkt[1:5] = fake_id
    return bytes(attack_pkt)

class DemoAttackerChannel:
    """Wraps the channel to transparently inject attacks without altering Device logic."""
    def __init__(self, real_channel, mode):
        self.real_channel = real_channel
        self.mode = mode
        self.MSG_CHALLENGE = 0x02
        self.MSG_RESPONSE = 0x03

        if mode != "normal":
            # Reduce timeout significantly so the demo doesn't hang when Provisioner aborts
            self.real_channel.sock.settimeout(3.0)

    def send(self, *args):
        # args might be (sender, receiver, packet) or just (packet, label) depending on channel.py
        # Safely extract packet
        packet = args[2] if len(args) >= 3 else args[0]

        if not packet or len(packet) == 0:
            self.real_channel.send(*args)
            return

        msg_type = packet[0]

        # REPLAY ATTACK: Save valid response on a normal run
        if self.mode == "normal" and msg_type == self.MSG_RESPONSE:
            with open("replay_payload.bin", "wb") as f:
                f.write(packet)
            print("  [INFO] Saved valid Response to 'replay_payload.bin' for future Replay attacks.")
            self.real_channel.send(*args)

        # REPLAY ATTACK: Send a stored old Response instead of the newly minted one
        elif self.mode == "replay" and msg_type == self.MSG_RESPONSE:
            if not os.path.exists("replay_payload.bin"):
                print("\n[ERROR] No replay payload found! Please run 'normal' mode first to generate one.")
                sys.exit(1)
            with open("replay_payload.bin", "rb") as f:
                old_packet = f.read()
            print("\n[ATTACK] REPLAY MODE: Sending PREVIOUSLY captured valid Response instead of a fresh one!")
            if len(args) >= 3:
                self.real_channel.send("Attacker(Replay)", args[1], old_packet)
            else:
                self.real_channel.send(old_packet, "Replay Attack")

        # MISBINDING ATTACK: Spoof the DeviceID before sending
        elif self.mode == "misbinding" and msg_type == self.MSG_RESPONSE:
            fake_id = b'\xca\xfe\xf0\x0d'
            print(f"\n[ATTACK] MISBINDING MODE: Replacing real DeviceID with {fake_id.hex()}!")
            tampered_packet = modify_device_id(packet, fake_id)
            if len(args) >= 3:
                self.real_channel.send("Attacker(Spoof)", args[1], tampered_packet)
            else:
                self.real_channel.send(tampered_packet, "Misbinding Spoof")

        else:
            # Normal passthrough
            self.real_channel.send(*args)

    def receive(self):
        packet = self.real_channel.receive()
        if not packet or len(packet) == 0:
            return packet

        msg_type = packet[0]

        # RELAY ATTACK: Modify ProvisionerID in received Challenge before device computes its token
        if self.mode == "relay" and msg_type == self.MSG_CHALLENGE:
            fake_id = b'\xfa\xce\xca\xfe'
            print(f"\n[ATTACK] RELAY MODE: Changing incoming ProvisionerID to {fake_id.hex()} before local auth computation!")
            return override_provisioner_id(packet, fake_id)

        return packet

    def close(self):
        self.real_channel.close()

def main():
    print("=" * 50)
    print("  DEVICE NODE (INTERACTIVE DEMO)")
    print(f"  IP   : {DEVICE_IP}")
    print(f"  Port : {DEVICE_PORT}")
    print("=" * 50)
    print()

    # User input for demo mode
    mode = input("Select mode (normal / replay / relay / misbinding): ").strip().lower()
    if mode not in ["normal", "replay", "relay", "misbinding"]:
        print("Invalid mode. Defaulting to 'normal'.")
        mode = "normal"

    real_channel = NetworkChannel(role='device')
    channel = DemoAttackerChannel(real_channel, mode)
    device = Device(DEVICE_ID, K_DEVICE)
    
    input("[DEVICE] Press Enter to broadcast Beacon...\n")
    
    # Step 1
    print("[STEP 1/5] Broadcasting Beacon...")
    device.send_beacon(channel)
    
    # Step 2
    print("[STEP 2/5] Waiting for Challenge from Provisioner...")
    device.handle_challenge(channel)
    
    # Step 3
    print("[STEP 3/5] Sending context-bound Response...")
    
    # Step 4
    print("[STEP 4/5] Waiting for Confirmation...")
    try:
        device.handle_confirmation(channel)

        # Step 5
        print("[STEP 5/5] Sending ACK...")
        device.send_ack(channel)

        print("\n" + "=" * 50)
        print("  PROVISIONING COMPLETE")
        print(f"  Assigned address : {device.assigned_address}")
        print(f"  Session key      : {device.session_key.hex()}")
        print("=" * 50)
    except Exception as e:
        print(f"\n[ATTACK RESULT] Provisioner aborted connection or validation failed!")
        print(f"Error: {e}")

if __name__ == "__main__":
    main()