# provisioning_protocol/run_provisioner.py

import os, sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
))

from provisioning_protocol.provisioner import Provisioner
from provisioning_protocol.channel import NetworkChannel
from common.constants import PROVISIONER_IP, PROVISIONER_PORT

# Pre-shared setup — same on both laptops
PROVISIONER_ID = b'\x50\x52\x4F\x56'
DEVICE_ID      = b'\xDE\xAD\xBE\xEF'

import os as _os
K_DEVICE = bytes.fromhex('973560d3d7cf76fb5cbac9f6a086c9e1')
# Use a fixed key for demo — both laptops must have same key

device_db = {DEVICE_ID: K_DEVICE}

def main():
    print("=" * 50)
    print("  PROVISIONER NODE")
    print(f"  IP   : {PROVISIONER_IP}")
    print(f"  Port : {PROVISIONER_PORT}")
    print("=" * 50)
    print()
    
    channel      = NetworkChannel(role='provisioner')
    provisioner  = Provisioner(PROVISIONER_ID, device_db)
    
    print("[PROVISIONER] Ready — waiting for Device beacon...")
    print("              Start run_device.py on Laptop 2 now\n")
    
    # Run full protocol
    if not provisioner.handle_beacon(channel):
        print("[ERROR] Beacon handling failed")
        return
    
    if not provisioner.handle_response(channel):
        print("[ERROR] Response verification failed")
        return
    
    provisioner.handle_ack(channel)
    
    print("\n" + "=" * 50)
    print("  PROVISIONING COMPLETE")
    print(f"  Session key: {provisioner.session_key.hex()}")
    print("=" * 50)
    
    channel.close()

if __name__ == '__main__':
    main()
