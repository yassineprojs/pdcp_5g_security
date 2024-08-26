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
        self.reset_security_counts()

    def reset_security_counts(self):
        self.security.tx_count = 0
        self.security.rx_count = 0
        self.sn = 0


    def set_rohc_profile(self, profile: ROHCProfile, mode: ROHCMode):
        self.rohc_compressor = ROHCCompressor(profile, mode)

    def initialize_security(self, bearer, direction):
        self.security.generate_key()
        self.security.set_parameters(bearer, direction)

    def process_packet(self, ip_packet: bytes, sn_length: int) -> bytes:
        try:
            print(f"Process Packet - SN: {self.sn}, SN Length: {sn_length}")
            compressed_packet = self.rohc_compressor.compress(ip_packet)
            print(f"Compressed packet: {compressed_packet.hex()}")
            protected_packet = self.security.protect(compressed_packet)
            print(f"Protected packet: {protected_packet.hex()}")
            pdcp_header = self.pdcp_header.create_data_pdu_header(self.sn, sn_length)
            print(f"PDCP Header: {pdcp_header.hex()}")
            self.sn = (self.sn + 1) % (2**sn_length)
            pdcp_pdu = pdcp_header + protected_packet
            print(f"PDCP PDU: {pdcp_pdu.hex()}")
            return pdcp_pdu
        except Exception as e:
            print(f"Error processing packet: {str(e)}")
            raise
  


    def process_received_packet(self, pdcp_pdu: bytes, sn_length: int) -> bytes:
        try:
            print(f"Process Received Packet - PDU: {pdcp_pdu.hex()}, SN Length: {sn_length}")
            header_info = self.pdcp_header.parse_header(pdcp_pdu[:3])
            print(f"Parsed Header Info: {header_info}")
            
            if header_info['pdu_type'] != 'Data':
                raise ValueError("Received PDU is not a Data PDU")
            
            header_length = 2 if sn_length == 12 else 3
            protected_packet = pdcp_pdu[header_length:]
            print(f"Protected packet: {protected_packet.hex()}")
            
            unprotected_packet = self.security.unprotect(protected_packet)
            print(f"Unprotected packet: {unprotected_packet.hex()}")
            original_ip_packet = self.rohc_compressor.decompress(unprotected_packet)
            print(f"Original IP packet: {original_ip_packet.hex()}")
            
            return original_ip_packet
        except Exception as e:
            print(f"Error processing received packet: {str(e)}")
            raise
        
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
