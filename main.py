from pdcp.header import PDCPHeader
from pdcp.compression import ROHCCompressor,ROHCProfile, ROHCMode
from pdcp.security import PDCPSecurity
# from pdcp.sdu_handling import SDUHandler
# from pdcp.control_pdu import ControlPDU
# from pdcp.state_management import PDCPState
# from pdcp.timers import PDCPTimers

class PDCP:
    def __init__(self, profile=ROHCProfile.IP, mode=ROHCMode.UNIDIRECTIONAL):
        self.pdcp_header = PDCPHeader()
        self.rohc_compressor = ROHCCompressor(profile, mode)
        self.security = PDCPSecurity()
        self.sn = 0  # PDCP sequence number

    def set_rohc_profile(self, profile: ROHCProfile, mode: ROHCMode):
        self.rohc_compressor = ROHCCompressor(profile, mode)

    def initialize_security(self, bearer, direction):
        self.security.generate_key()
        self.security.set_parameters(bearer, direction)

    def process_packet(self, ip_packet: bytes, sn_length: int) -> bytes:
        try:
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
        except Exception as e:
            print(f"Error processing packet: {e}")
            return b''

    def process_received_packet(self, pdcp_pdu: bytes, sn_length: int) -> bytes:
        try:
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
        except Exception as e:
            print(f"Error processing received packet: {e}")
            return b''
        
    def reset_rohc_context(self):
        self.rohc_compressor.context_timeout()

    def get_state_info(self):
        return {
            "ROHC Compressor Profile": self.rohc_compressor.profile.name,
            "ROHC Compressor Mode": self.rohc_compressor.mode.name,
            "Security Bearer": self.security.bearer,
            "Security Direction": "Uplink" if self.security.direction == 0 else "Downlink",
            "PDCP Count": self.security.count,
            "PDCP SN": self.sn
        }
