import os
import time

from .provisioner import Provisioner
from .channel import NetworkChannel
from .topology_display import print_topology

PROVISIONER_ID = b'\x50\x52\x4F\x56'
DEVICE_ID = b'\xDE\xAD\xBE\xEF'
K_DEVICE = b'1234567890123456'
device_db = {DEVICE_ID: K_DEVICE}

def run():
    print("=" * 40)
    print("  PROVISIONER NODE STARTED (Port 5001)")
    print("=" * 40)
    
    channel = NetworkChannel(role='provisioner', verbose=False)
    provisioner = Provisioner(PROVISIONER_ID, device_db, verbose=True)
    
    try:
        print("\nWaiting for incoming Beacon...")
        provisioner.handle_beacon(channel)
        
        print("\nWaiting for Response...")
        provisioner.handle_response(channel)
        
        print("\nWaiting for ACK...")
        provisioner.handle_ack(channel)
        
        print("\n[SUCCESS] Provisioning Session Completed.")
        metrics = channel.get_session_metrics()
        print(f"End-to-End Latency: {metrics.get('end_to_end_ms', 0):.1f} ms")
        
    except KeyboardInterrupt:
        print("\nShutting down Provisioner...")
    finally:
        channel.close()

if __name__ == "__main__":
    run()
