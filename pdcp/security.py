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

    def encrypt(self, plaintext):
        if self.encryption_key is None:
            raise ValueError("Encryption key not set. Call generate_key() first.")

        # Construct the PDCP Count (32 bits) as per 3GPP TS 33.501
        pdcp_count = self.count

        # Construct the bearer (5 bits) and direction (1 bit) as per 3GPP TS 33.501
        bearer = self.bearer & 0x1F  # 5 bits for bearer
        direction = self.direction & 0x01  # 1 bit for direction

        # Construct the initialization vector (IV)
        iv = pdcp_count.to_bytes(4, byteorder='big') + \
             bearer.to_bytes(1, byteorder='big') + \
             direction.to_bytes(1, byteorder='big') + \
             b'\x00\x00'  # Padding to make it 64 bits

        # Create an AES-CTR cipher instance
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the plaintext
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return ciphertext

    def decrypt(self, ciphertext):
        if self.encryption_key is None:
            raise ValueError("Decryption key not set. Call generate_key() first.")

        # Construct the PDCP Count (32 bits) as per 3GPP TS 33.501
        pdcp_count = self.count

        # Construct the bearer (5 bits) and direction (1 bit) as per 3GPP TS 33.501
        bearer = self.bearer & 0x1F  # 5 bits for bearer
        direction = self.direction & 0x01  # 1 bit for direction

        # Construct the initialization vector (IV)
        iv = pdcp_count.to_bytes(4, byteorder='big') + \
             bearer.to_bytes(1, byteorder='big') + \
             direction.to_bytes(1, byteorder='big') + \
             b'\x00\x00'  # Padding to make it 64 bits

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
        mac = h.finalize()[:4]  # Use first 32 bits of MAC

        return mac

    def verify_mac(self, message, received_mac):
        calculated_mac = self.generate_mac(message)
        return calculated_mac == received_mac

    def protect(self, plaintext):
        # Encrypt the plaintext
        ciphertext = self.encrypt(plaintext)

        # Generate MAC for the ciphertext
        mac = self.generate_mac(ciphertext)

        # Increment count after successful operation
        self.increment_count()

        return ciphertext, mac

    def unprotect(self, ciphertext, received_mac):
        # Verify MAC
        if not self.verify_mac(ciphertext, received_mac):
            raise ValueError("MAC verification failed. Message may have been tampered with.")

        # Decrypt the ciphertext
        plaintext = self.decrypt(ciphertext)

        # Increment count after successful operation
        self.increment_count()

        return plaintext
