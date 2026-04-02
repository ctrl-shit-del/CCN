"""
test_crypto.py
Unit tests for provisioning_protocol/common/crypto.py  (PRD §6.4, FR-2, FR-3, FR-4)

Run:
    python -m pytest provisioning_protocol/tests/test_crypto.py -v
"""

import unittest
import os
import sys

# Allow running directly from repo root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from provisioning_protocol.common.crypto import (
    generate_nonce,
    compute_transcript_hash,
    compute_auth_token,
    derive_session_key,
    encrypt_message,
    decrypt_message,
)


# ── Helpers ────────────────────────────────────────────────────────────

DEVICE_ID      = b'\xDE\xAD\xBE\xEF'
PROVISIONER_ID = b'\x50\x52\x4F\x56'
K_DEVICE       = bytes(range(16))          # deterministic 16-byte key for tests
NONCE_P        = bytes(range(16, 32))      # fixed nonce for determinism
NONCE_D        = bytes(range(32, 48))
TIMESTAMP      = b'\x00' * 8


# ── generate_nonce ─────────────────────────────────────────────────────

class TestGenerateNonce(unittest.TestCase):

    def test_default_length(self):
        """generate_nonce() must return 16 bytes by default (PRD §6.3 NonceP/D)."""
        n = generate_nonce()
        self.assertEqual(len(n), 16)

    def test_custom_length(self):
        n = generate_nonce(size=8)
        self.assertEqual(len(n), 8)

    def test_randomness(self):
        """Two subsequent nonces must not be identical (birthday probability ~0)."""
        a, b = generate_nonce(), generate_nonce()
        self.assertNotEqual(a, b, "Two random nonces must not collide")

    def test_returns_bytes(self):
        self.assertIsInstance(generate_nonce(), bytes)


# ── compute_transcript_hash ────────────────────────────────────────────

class TestTranscriptHash(unittest.TestCase):

    def _hash(self, **overrides):
        params = dict(
            device_id=DEVICE_ID,
            provisioner_id=PROVISIONER_ID,
            nonce_p=NONCE_P,
            nonce_d=NONCE_D,
            timestamp=TIMESTAMP,
        )
        params.update(overrides)
        return compute_transcript_hash(**params)

    def test_returns_32_bytes(self):
        """SHA-256 digest must be 32 bytes (PRD §6.4)."""
        h = self._hash()
        self.assertEqual(len(h), 32)

    def test_determinism(self):
        """Same inputs must always give the same hash."""
        self.assertEqual(self._hash(), self._hash())

    def test_context_binding_device_id(self):
        """Changing DeviceID must produce a different hash (misbinding prevention)."""
        h1 = self._hash()
        h2 = self._hash(device_id=b'\xCA\xFE\xCA\xFE')
        self.assertNotEqual(h1, h2)

    def test_context_binding_provisioner_id(self):
        """Changing ProvisionerID must produce a different hash (relay prevention)."""
        h1 = self._hash()
        h2 = self._hash(provisioner_id=b'\xFA\xCE\xFA\xCE')
        self.assertNotEqual(h1, h2)

    def test_context_binding_nonce_p(self):
        """Changing NonceP must produce a different hash (replay prevention)."""
        h1 = self._hash()
        h2 = self._hash(nonce_p=os.urandom(16))
        self.assertNotEqual(h1, h2)

    def test_context_binding_nonce_d(self):
        h1 = self._hash()
        h2 = self._hash(nonce_d=os.urandom(16))
        self.assertNotEqual(h1, h2)

    def test_context_binding_timestamp(self):
        h1 = self._hash()
        h2 = self._hash(timestamp=b'\xFF' * 8)
        self.assertNotEqual(h1, h2)


# ── compute_auth_token ─────────────────────────────────────────────────

class TestAuthToken(unittest.TestCase):

    def _transcript(self):
        return compute_transcript_hash(
            DEVICE_ID, PROVISIONER_ID, NONCE_P, NONCE_D, TIMESTAMP
        )

    def test_returns_16_bytes(self):
        """Auth token is AES-128 output — must be exactly 16 bytes (PRD §6.4)."""
        t = compute_auth_token(K_DEVICE, self._transcript())
        self.assertEqual(len(t), 16)

    def test_determinism(self):
        t1 = compute_auth_token(K_DEVICE, self._transcript())
        t2 = compute_auth_token(K_DEVICE, self._transcript())
        self.assertEqual(t1, t2)

    def test_wrong_key_fails(self):
        """A different K_device must produce a different token (impersonation prevention)."""
        t1 = compute_auth_token(K_DEVICE, self._transcript())
        t2 = compute_auth_token(os.urandom(16), self._transcript())
        self.assertNotEqual(t1, t2)

    def test_wrong_transcript_fails(self):
        """A tampered transcript hash must produce a different token."""
        t1 = compute_auth_token(K_DEVICE, self._transcript())
        t2 = compute_auth_token(K_DEVICE, os.urandom(32))
        self.assertNotEqual(t1, t2)


# ── derive_session_key ─────────────────────────────────────────────────

class TestDeriveSessionKey(unittest.TestCase):

    def test_returns_16_bytes(self):
        """Session key from AES-128 must be 16 bytes."""
        k = derive_session_key(K_DEVICE, NONCE_P, NONCE_D)
        self.assertEqual(len(k), 16)

    def test_both_sides_agree(self):
        """Device and Provisioner must independently derive the same session key (FR-4)."""
        k1 = derive_session_key(K_DEVICE, NONCE_P, NONCE_D)
        k2 = derive_session_key(K_DEVICE, NONCE_P, NONCE_D)  # symmetric call
        self.assertEqual(k1, k2)

    def test_commutative_nonce_xor(self):
        """XOR is commutative: derive_session_key(K, Np, Nd) == derive(K, Nd, Np)
        because the spec uses NonceP XOR NonceD (order-independent).
        """
        k1 = derive_session_key(K_DEVICE, NONCE_P, NONCE_D)
        k2 = derive_session_key(K_DEVICE, NONCE_D, NONCE_P)
        self.assertEqual(k1, k2)

    def test_different_nonces_give_different_key(self):
        """Fresh nonces must produce a different session key (replay protection)."""
        k1 = derive_session_key(K_DEVICE, NONCE_P, NONCE_D)
        k2 = derive_session_key(K_DEVICE, os.urandom(16), os.urandom(16))
        self.assertNotEqual(k1, k2)

    def test_different_k_device_gives_different_key(self):
        """Different devices must get different session keys (NFR-3)."""
        k1 = derive_session_key(K_DEVICE,        NONCE_P, NONCE_D)
        k2 = derive_session_key(os.urandom(16),  NONCE_P, NONCE_D)
        self.assertNotEqual(k1, k2)


# ── encrypt / decrypt round-trip ───────────────────────────────────────

class TestEncryptDecrypt(unittest.TestCase):

    SESSION_KEY = bytes(range(16))

    def test_round_trip(self):
        """Decrypt(Encrypt(m)) must equal m."""
        msg = b'hello mesh'
        ct  = encrypt_message(self.SESSION_KEY, msg)
        pt  = decrypt_message(self.SESSION_KEY, ct)
        self.assertEqual(pt, msg)

    def test_ciphertext_differs_from_plaintext(self):
        ct = encrypt_message(self.SESSION_KEY, b'test data')
        self.assertNotEqual(ct[:9], b'test data')

    def test_wrong_key_gives_wrong_plaintext(self):
        msg = b'secret'
        ct  = encrypt_message(self.SESSION_KEY, msg)
        pt  = decrypt_message(os.urandom(16), ct)
        self.assertNotEqual(pt, msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
