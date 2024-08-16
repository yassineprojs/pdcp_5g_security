from pdcp.header import PDCPHeader
from pdcp.compression import ROHCCompressor,ROHCProfile, ROHCMode
from pdcp.security import PDCPSecurity
# from pdcp.sdu_handling import SDUHandler
# from pdcp.control_pdu import ControlPDU
# from pdcp.state_management import PDCPState
# from pdcp.timers import PDCPTimers

class PDCP:
    def __init__(self):
        self.pdcp_header = PDCPHeader()
        self.rohc_compressor = ROHCCompressor(ROHCProfile.IP, ROHCMode.UNIDIRECTIONAL)
        self.security = PDCPSecurity()
        self.sn = 0  # PDCP sequence number

    def initialize_security(self, bearer, direction):
        self.security.generate_key()
        self.security.set_parameters(bearer, direction)

    def process_packet(self, ip_packet: bytes, sn_length: int) -> bytes:
        # Compress the IP header
        compressed_packet = self.rohc_compressor.compress(ip_packet)

        # Protect (encrypt and generate MAC) the compressed packet
        protected_packet, mac = self.security.protect(compressed_packet)

        # Create PDCP header
        pdcp_header = self.pdcp_header.create_data_pdu_header(self.sn, sn_length)

        # Increment sequence number
        self.sn = (self.sn + 1) % (2**sn_length)

        # Combine PDCP header, protected packet, and MAC
        pdcp_pdu = pdcp_header + protected_packet + mac

        return pdcp_pdu

    def process_received_packet(self, pdcp_pdu: bytes, sn_length: int) -> bytes:
        # Parse PDCP header
        header_info = self.pdcp_header.parse_header(pdcp_pdu[:3])
        
        # Extract protected packet and MAC
        header_length = 2 if sn_length == 12 else 3
        protected_packet = pdcp_pdu[header_length:-4]
        received_mac = pdcp_pdu[-4:]

        # Unprotect (verify MAC and decrypt) the packet
        unprotected_packet = self.security.unprotect(protected_packet, received_mac)

        # Decompress the packet
        original_ip_packet = self.rohc_compressor.decompress(unprotected_packet)

        return original_ip_packet

    # ... (other methods)

# Usage
pdcp = PDCP()
pdcp.initialize_security(bearer=1, direction=0)

# Process a packet
ip_packet = b'\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x11\x3c\x8f\xc0\xa8\x00\x01\xc0\xa8\x00\xc7' + b'\x00' * 20
pdcp_pdu = pdcp.process_packet(ip_packet, PDCPHeader.PDCP_SN_LEN_12)

# Simulate receiving and processing the packet
received_ip_packet = pdcp.process_received_packet(pdcp_pdu, PDCPHeader.PDCP_SN_LEN_12)

assert ip_packet == received_ip_packet, "End-to-end processing failed"