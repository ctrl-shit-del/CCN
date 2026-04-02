from .common.crypto import *
from .common.packets import *
from .common.constants import *

import struct
import time


class Provisioner:
	"""Provisioner entity implementing the 5-message provisioning handshake.

	Follows PRD state machine:
	IDLE → BEACON_RECEIVED → CHALLENGE_SENT → VERIFYING → COMPLETE / ERROR
	"""

	def __init__(self, provisioner_id, device_db, verbose=True):
		# provisioner_id: 4-byte identifier
		# device_db: dict mapping DeviceID (bytes) → K_device (16-byte key)
		self.provisioner_id = provisioner_id
		self.device_db = device_db
		self.verbose = verbose

		self.state = "IDLE"
		self.current_device_id = None
		self.nonce_p = None
		self.nonce_d = None
		self.timestamp_bytes = None
		self.session_key = None
		self.assigned_address_counter = 0x1000

	def _log(self, msg):
		if self.verbose:
			print(msg)

	def _allocate_address(self):
		self.assigned_address_counter += 1
		return self.assigned_address_counter

	def handle_beacon(self, channel):
		"""Step 1 (from provisioner side):
		Receive Beacon, record NonceD, and send Challenge.
		"""
		raw = channel.receive()
		if raw is None or raw[0] != MSG_BEACON:
			self._log("[PROVISIONER] ERROR: No beacon or wrong message type")
			self.state = "ERROR"
			return False

		beacon = parse_beacon(raw)
		self.current_device_id = beacon["device_id"]
		self.nonce_d = beacon["nonce_d"]

		self._log(f"\n[PROVISIONER] Beacon received from DeviceID: {self.current_device_id.hex()}")

		# Look up device in database (mismatches defeat misbinding)
		if self.current_device_id not in self.device_db:
			self._log("[PROVISIONER] ERROR: Unknown DeviceID (mismatching or unregistered device)")
			self.state = "ERROR"
			return False

		self.state = "BEACON_RECEIVED"

		# Generate fresh NonceP and timestamp
		self.nonce_p = generate_nonce()
		timestamp_ms = int(time.time() * 1000)
		self.timestamp_bytes = struct.pack("!Q", timestamp_ms)

		challenge = build_challenge(
			self.provisioner_id,
			self.nonce_p,
			self.timestamp_bytes,
		)

		channel.send("Provisioner", "Device", challenge)
		self._log(f"[PROVISIONER] Challenge sent. NonceP: {self.nonce_p.hex()}")
		self.state = "CHALLENGE_SENT"
		return True

	def handle_response(self, channel):
		"""Step 2 (from provisioner side):
		Receive Response, verify context-bound auth token, derive session key,
		and send Confirmation.
		Returns True on successful verification, False otherwise.
		"""
		raw = channel.receive()
		if raw is None or raw[0] != MSG_RESPONSE:
			self._log("[PROVISIONER] ERROR: No response or wrong message type")
			self.state = "ERROR"
			return False

		response = parse_response(raw)
		device_id = response["device_id"]
		auth_token_rx = response["auth_token"]
		transcript_hash_rx = response["transcript_hash"]
		nonce_d_rx = response["nonce_d"]

		self._log(f"\n[PROVISIONER] Response received from DeviceID: {device_id.hex()}")

		# DeviceID must match the beacon sender (catches misbinding before crypto)
		if device_id != self.current_device_id:
			self._log(f"[PROVISIONER] ERROR: DeviceID mismatch — beacon={self.current_device_id.hex()} "
			          f"response={device_id.hex()} — misbinding detected")
			self.state = "ERROR"
			return False

		# DeviceID must also be in the provisioner database
		if device_id not in self.device_db:
			self._log("[PROVISIONER] ERROR: DeviceID not in database — possible misbinding")
			self.state = "ERROR"
			return False

		# NonceD in response must match beacon NonceD
		if self.nonce_d is not None and nonce_d_rx != self.nonce_d:
			self._log("[PROVISIONER] ERROR: NonceD mismatch between Beacon and Response")
			self.state = "ERROR"
			return False

		k_device = self.device_db[device_id]

		# Recompute transcript hash locally (context binding)
		transcript_hash_local = compute_transcript_hash(
			device_id,
			self.provisioner_id,
			self.nonce_p,
			nonce_d_rx,
			self.timestamp_bytes,
		)

		# Hash sent by device must match local view
		if transcript_hash_rx != transcript_hash_local:
			self._log("[PROVISIONER] ERROR: Transcript hash mismatch — context tampering or relay detected")
			self.state = "ERROR"
			return False

		# Auth token must verify knowledge of K_device
		expected_auth_token = compute_auth_token(k_device, transcript_hash_local)
		if auth_token_rx != expected_auth_token:
			self._log("[PROVISIONER] ERROR: Auth token mismatch — invalid K_device or replayed token")
			self.state = "ERROR"
			return False

		self._log("[PROVISIONER] Response verified ✓ — context binding and K_device authentication succeed")
		self.state = "VERIFYING"

		# Derive shared session key
		self.session_key = derive_session_key(k_device, self.nonce_p, nonce_d_rx)
		self._log(f"[PROVISIONER] Session key derived: {self.session_key.hex()}")

		# Assign unicast address and create confirmation
		assigned_address = self._allocate_address()
		session_key_id = 1  # simple fixed ID for this prototype

		# Use a fresh confirm token as provisioner's proof (can be same construction)
		confirm_token = compute_auth_token(k_device, transcript_hash_local)

		confirmation = build_confirmation(
			assigned_address,
			session_key_id,
			confirm_token,
		)

		channel.send("Provisioner", "Device", confirmation)
		self._log(f"[PROVISIONER] Confirmation sent. Assigned address: {assigned_address}")
		self.state = "COMPLETE"
		return True

	def handle_ack(self, channel):
		"""Step 3 (from provisioner side):
		Receive final ACK from device and log status.
		"""
		raw = channel.receive()
		if raw is None or raw[0] != MSG_ACK:
			self._log("[PROVISIONER] ERROR: No ACK or wrong message type")
			return False

		ack = parse_ack(raw)
		status = ack["status"]
		device_id = ack["device_id"]

		if status == STATUS_SUCCESS:
			self._log(f"\n[PROVISIONER] ACK received from {device_id.hex()} — provisioning COMPLETE ✓")
			return True

		self._log(f"\n[PROVISIONER] ACK received from {device_id.hex()} with FAILURE status")
		return False

