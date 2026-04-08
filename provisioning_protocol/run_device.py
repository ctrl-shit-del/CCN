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

def main():
    print("=" * 50)
    print("  DEVICE NODE")
    print(f"  IP   : {DEVICE_IP}")
    print(f"  Port : {DEVICE_PORT}")
    print("=" * 50)
    print()
    
    channel = NetworkChannel(role='device')
    device  = Device(DEVICE_ID, K_DEVICE)
    
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
    device.handle_confirmation(channel)
    
    # Step 5
    print("[STEP 5/5] Sending ACK...")
    device.send_ack(channel)
    
    print("\n" + "=" * 50)
    print("  PROVISIONING COMPLETE")
    print(f"  Assigned address : {device.assigned_address}")
    print(f"  Session key      : {device.session_key.hex()}")
    print("=" * 50)
    
    channel.close()

if __name__ == '__main__':
    main()
