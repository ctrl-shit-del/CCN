import os
import time

from .device import Device
from .channel import NetworkChannel
from .topology_display import print_topology

DEVICE_ID = b'\xDE\xAD\xBE\xEF'
K_DEVICE = b'1234567890123456' # Fixed key to match provisioner db

def run():
    print("=" * 40)
    print("  DEVICE NODE STARTED (Port 5002)")
    print("=" * 40)
    
    channel = NetworkChannel(role='device', verbose=False)
    device = Device(DEVICE_ID, K_DEVICE, verbose=True)
    
    try:
        input("Press Enter to broadcast Beacon...")
        print_topology('beacon', "Device initiating provisioning...")
        
        device.send_beacon(channel)
        
        print("\nWaiting for Challenge...")
        device.handle_challenge(channel)
        
        print("\nWaiting for Confirmation...")
        device.handle_confirmation(channel)
        
        print("\n[SUCCESS] Provisioning Session Completed.")
        metrics = channel.get_session_metrics()
        print(f"End-to-End Latency: {metrics.get('end_to_end_ms', 0):.1f} ms")
        
    except KeyboardInterrupt:
        print("\nShutting down Device...")
    finally:
        channel.close()

if __name__ == "__main__":
    run()
