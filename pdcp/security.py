import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

class PDCPSecurity:
    def __init__(self):
        self.encryption_key = None
        self.integrity_key = None
        self.bearer = 0
        self.direction = 0  # 0 for uplink, 1 for downlink
        self.count = 0

    def generate_key(self):
        # In a real system, keys would be derived from the main key provided by higher layers
        # For simulation, we're generating a random key
        self.encryption_key = os.urandom(32)  # 256-bit key for AES
        self.integrity_key = os.urandom(32)  # 256-bit key for HMAC
        return self.encryption_key, self.integrity_key
    
    def set_parameters(self, bearer, direction):
        self.bearer = bearer
        self.direction = direction

 #a unique counter that increments with each PDCP PDU sent. It ensures that each encryption operation has a unique IV
    def increment_count(self):
        self.count = (self.count + 1) & 0xFFFFFFFF  # Ensure it's a 32-bit value

    def _get_iv(self):
        pdcp_count = self.count
        bearer = self.bearer & 0x1F  # 5 bits for bearer
        direction = self.direction & 0x01  # 1 bit for direction
        iv = pdcp_count.to_bytes(4, byteorder='big') + \
            bearer.to_bytes(1, byteorder='big') + \
            direction.to_bytes(1, byteorder='big') + \
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Padding to make it 128 bits (16 bytes)
        return iv
    
    def encrypt(self, plaintext):
        if self.encryption_key is None:
            raise ValueError("Encryption key not set. Call generate_keys() first.")

        iv = self._get_iv()

        # Create an AES-CTR cipher instance
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the plaintext
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return ciphertext

    def decrypt(self, ciphertext):
        if self.encryption_key is None:
            raise ValueError("Decryption key not set. Call generate_keys() first.")

        iv = self._get_iv()

        # Create an AES-CTR cipher instance
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext
    
    def generate_mac(self, message):
        if self.integrity_key is None:
            raise ValueError("Integrity key not set. Call generate_keys() first.")

        # Construct the input for MAC calculation
        mac_input = self.count.to_bytes(4, byteorder='big') + \
                    self.bearer.to_bytes(1, byteorder='big') + \
                    self.direction.to_bytes(1, byteorder='big') + \
                    message

        # Create HMAC instance
        h = hmac.HMAC(self.integrity_key, hashes.SHA256(), backend=default_backend())
        h.update(mac_input)

        # Generate MAC
        mac = h.finalize()[:16]  # Use first 16 bits of MAC

        return mac

    def verify_mac(self, message, received_mac):
        calculated_mac = self.generate_mac(message)
        return calculated_mac == received_mac

    def protect(self, plaintext):
        iv = self._get_iv()
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        mac = self.generate_mac(ciphertext)
        self.increment_count()
        return ciphertext + mac  # Combine ciphertext and MAC

    def unprotect(self, protected_packet):
        ciphertext = protected_packet[:-16]  # Assuming 16-byte MAC
        received_mac = protected_packet[-16:]
        calculated_mac = self.generate_mac(ciphertext)
        if calculated_mac != received_mac:
            raise ValueError("MAC verification failed")
        iv = self._get_iv()
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        self.increment_count()
        return plaintext
    
    