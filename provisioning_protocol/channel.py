import time

# Message type byte values (mirrors constants.py to avoid circular imports)
_MSG_BEACON       = 0x01
_MSG_CHALLENGE    = 0x02
_MSG_RESPONSE     = 0x03
_MSG_CONFIRMATION = 0x04
_MSG_ACK          = 0x05

_MSG_NAMES = {
    _MSG_BEACON:       "Beacon",
    _MSG_CHALLENGE:    "Challenge",
    _MSG_RESPONSE:     "Response",
    _MSG_CONFIRMATION: "Confirmation",
    _MSG_ACK:          "ACK",
}


class NetworkChannel:
    """
    Simulates a Bluetooth Mesh provisioning bearer (PB-ADV layer).

    Extended for Phase 3:
      - Records wall-clock timestamps for each message type sent.
      - Accumulates total bytes transferred per session.
      - Exposes get_session_metrics() for feature extraction and CCN metrics.
    Supports optional eavesdropping and configurable propagation delay.
    """

    def __init__(self, verbose=True, delay: float = 0.0):
        self.buffer      = []
        self.intercepted = []          # attacker always sees every packet
        self.verbose     = verbose
        self.delay       = delay       # simulated propagation delay (seconds)

        # --- timing / metrics state ---
        self._session_start: float | None = None
        self._timestamps: dict[int, float] = {}   # msg_type → send time (epoch s)
        self._total_bytes   = 0
        self._packet_sizes  = []       # individual packet sizes for variance calc

    # ------------------------------------------------------------------
    def send(self, sender_name: str, receiver_name: str, packet: bytes):
        """Transmit a packet; record timestamp and accumulate byte count."""
        now = time.perf_counter()
        if self.delay:
            time.sleep(self.delay)

        self.buffer.append(packet)
        self.intercepted.append(packet)

        # Record per-message-type timestamp (first occurrence wins)
        msg_type = packet[0] if packet else 0xFF
        if msg_type not in self._timestamps:
            self._timestamps[msg_type] = now
        if self._session_start is None:
            self._session_start = now

        self._total_bytes += len(packet)
        self._packet_sizes.append(len(packet))

        if self.verbose:
            label = _MSG_NAMES.get(msg_type, f"0x{msg_type:02X}")
            print(f"\n[CHANNEL] {sender_name} → {receiver_name}  [{label}]")
            print(f"          Packet ({len(packet)} bytes): {packet.hex()}")

    def receive(self) -> bytes | None:
        if self.buffer:
            return self.buffer.pop(0)
        return None

    # ------------------------------------------------------------------
    def get_session_metrics(self) -> dict:
        """Return timing and size metrics for the completed session.

        Keys
        ----
        beacon_to_challenge_ms   : delay between Beacon and Challenge (ms)
        challenge_to_response_ms : delay between Challenge and Response (ms)
        end_to_end_ms            : Beacon → ACK total latency (ms)
        total_bytes              : sum of all packet bytes in session
        num_packets              : number of packets exchanged
        packet_size_variance     : variance of individual packet sizes
        """
        ts = self._timestamps

        def delta_ms(a, b):
            """Return (ts[b] - ts[a]) * 1000 if both keys present, else 0."""
            if a in ts and b in ts:
                return max(0.0, (ts[b] - ts[a]) * 1000)
            return 0.0

        sizes = self._packet_sizes
        n     = len(sizes)
        mean  = sum(sizes) / n if n else 0
        variance = sum((s - mean) ** 2 for s in sizes) / n if n else 0

        return {
            "beacon_to_challenge_ms":      delta_ms(_MSG_BEACON,       _MSG_CHALLENGE),
            "challenge_to_response_ms":    delta_ms(_MSG_CHALLENGE,    _MSG_RESPONSE),
            "response_to_confirmation_ms": delta_ms(_MSG_RESPONSE,     _MSG_CONFIRMATION),
            "confirmation_to_ack_ms":      delta_ms(_MSG_CONFIRMATION, _MSG_ACK),
            "end_to_end_ms":               delta_ms(_MSG_BEACON,       _MSG_ACK),
            "total_bytes":                 self._total_bytes,
            "num_packets":                 n,
            "packet_size_variance":        round(variance, 4),
        }

    def reset(self):
        """Clear all state for reuse across sessions."""
        self.buffer.clear()
        self.intercepted.clear()
        self._session_start = None
        self._timestamps.clear()
        self._total_bytes   = 0
        self._packet_sizes  = []