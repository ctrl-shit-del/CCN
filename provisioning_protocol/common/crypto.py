from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os

def generate_nonce(size=16):
    """Generate a fresh random nonce"""
    return os.urandom(size)

def compute_transcript_hash(device_id, provisioner_id, nonce_p, nonce_d, timestamp):
    """
    Context binding — this is the core of your protocol
    Concatenate all session identifiers and hash them
    """
    transcript = device_id + provisioner_id + nonce_p + nonce_d + timestamp
    h = SHA256.new()
    h.update(transcript)
    return h.digest()  # 32 bytes

def compute_auth_token(k_device, transcript_hash):
    """
    Device proves it knows K_device by encrypting transcript hash
    Uses first 16 bytes of hash as AES block input
    """
    cipher = AES.new(k_device, AES.MODE_ECB)
    return cipher.encrypt(transcript_hash[:16])  # returns 16 bytes

def derive_session_key(k_device, nonce_p, nonce_d):
    """
    Both sides derive the same session key independently
    XOR of nonces ensures both parties contribute freshness
    """
    combined = bytes(a ^ b for a, b in zip(nonce_p, nonce_d))
    cipher = AES.new(k_device, AES.MODE_ECB)
    return cipher.encrypt(combined)  # 16 byte session key

def encrypt_message(session_key, plaintext):
    """Encrypt post-provisioning communication"""
    cipher = AES.new(session_key, AES.MODE_ECB)
    # Pad to 16 bytes
    padded = plaintext.ljust(16, b'\x00')
    return cipher.encrypt(padded)

def decrypt_message(session_key, ciphertext):
    """Decrypt post-provisioning communication"""
    cipher = AES.new(session_key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext).rstrip(b'\x00')