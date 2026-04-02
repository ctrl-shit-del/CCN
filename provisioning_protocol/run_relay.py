from .relay_node import RelayNode

def run():
    print("=" * 40)
    print("  RELAY NODE STARTED (Port 5003)")
    print("=" * 40)
    
    relay = RelayNode()
    try:
        relay.run()
    except KeyboardInterrupt:
        print("\nShutting down Relay...")

if __name__ == "__main__":
    run()
