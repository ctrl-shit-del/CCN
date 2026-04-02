def print_topology(event, details=""):
    """
    Prints a live ASCII network topology during protocol execution.
    Shows packet position at each step.
    """
    
    topologies = {
        'beacon': """
    ┌──────────┐    ══════►    ┌──────────┐    ───────    ┌──────────────┐
    │  DEVICE  │   Beacon(23B) │  RELAY   │   waiting  │  PROVISIONER │
    │ deadbeef │               │ 0xAAAA   │               │   50524f56   │
    └──────────┘               └──────────┘               └──────────────┘
        """,
        'beacon_relay': """
    ┌──────────┐    ─────────  ┌──────────┐    ══════►    ┌──────────────┐
    │  DEVICE  │   sent        │  RELAY   │  Beacon(23B)  │  PROVISIONER │
    │ deadbeef │               │ TTL: 6   │               │   50524f56   │
    └──────────┘               └──────────┘               └──────────────┘
        """,
        'challenge': """
    ┌──────────┐    ◄══════    ┌──────────┐    ◄──────    ┌──────────────┐
    │  DEVICE  │  Challenge    │  RELAY   │  Challenge    │  PROVISIONER │
    │ deadbeef │   (29B)       │ TTL: 6   │   (29B)       │   50524f56   │
    └──────────┘               └──────────┘               └──────────────┘
        """,
        'complete': """
    ┌──────────┐               ┌──────────┐               ┌──────────────┐
    │  DEVICE  │  ══ ACK ══►  │  RELAY   │  ══ ACK ══►  │  PROVISIONER │
    │ ADDR:4097│   (6B) ✓      │ TTL: 6   │   (6B) ✓      │  COMPLETE ✓  │
    └──────────┘               └──────────┘               └──────────────┘
        """
    }
    
    print(topologies.get(event, ""))
    if details:
        print(f"    ► {details}")
