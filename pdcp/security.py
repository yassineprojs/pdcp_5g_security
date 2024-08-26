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
        self.tx_count = 0
        self.rx_count = 0

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

    def _get_iv(self, count):
        bearer = self.bearer & 0x1F 
        direction = self.direction & 0x01 
        iv = count.to_bytes(4, byteorder='big') + \
            bearer.to_bytes(1, byteorder='big') + \
            direction.to_bytes(1, byteorder='big') + \
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 
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
    
    def generate_mac(self, message, count):
        mac_input = count.to_bytes(4, byteorder='big') + \
                    self.bearer.to_bytes(1, byteorder='big') + \
                    self.direction.to_bytes(1, byteorder='big') + \
                    message
        print(f"Generate MAC - Input: {mac_input.hex()}")
        h = hmac.HMAC(self.integrity_key, hashes.SHA256(), backend=default_backend())
        h.update(mac_input)
        mac = h.finalize()[:16]  
        return mac

    def verify_mac(self, message, received_mac):
        calculated_mac = self.generate_mac(message)
        return calculated_mac == received_mac

    def protect(self, plaintext):
        iv = self._get_iv(self.tx_count)
        print(f"Protect - IV: {iv.hex()}")
        print(f"Protect - TX Count: {self.tx_count}")
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        mac = self.generate_mac(ciphertext, self.tx_count)
        print(f"Protect - Generated MAC: {mac.hex()}")
        protected_packet = ciphertext + mac
        self.tx_count += 1
        print(f"Protect - TX Count after: {self.tx_count}")
        return protected_packet

    def unprotect(self, protected_packet):
        print(f"Unprotect - RX Count: {self.rx_count}")
        ciphertext = protected_packet[:-16]  # Assuming 16-byte MAC
        received_mac = protected_packet[-16:]
        print(f"Unprotect - Received MAC: {received_mac.hex()}")
        calculated_mac = self.generate_mac(ciphertext, self.rx_count)
        print(f"Unprotect - Calculated MAC: {calculated_mac.hex()}")
        if calculated_mac != received_mac:
            raise ValueError("MAC verification failed")
        iv = self._get_iv(self.rx_count)
        print(f"Unprotect - IV: {iv.hex()}")
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        self.rx_count += 1
        print(f"Unprotect - RX Count after: {self.rx_count}")
        return plaintext
    
    