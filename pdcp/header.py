class PDCPHeader:
    def __init__(self):
        self.DC_BIT_DATA = 0
        self.DC_BIT_CONTROL = 1
        self.PDCP_SN_LEN_12 = 12
        self.PDCP_SN_LEN_18 = 18

    def create_data_pdu_header(self, sn, sn_length):
        """
        Create a header for a PDCP Data PDU.
        
        :param sn: Sequence Number
        :param sn_length: Length of the Sequence Number (12 or 18 bits)
        :return: Bytes object representing the header
        """
        if sn_length not in [self.PDCP_SN_LEN_12, self.PDCP_SN_LEN_18]:
            raise ValueError("Invalid SN length. Must be 12 or 18.")

        if sn_length == self.PDCP_SN_LEN_12:
            if sn < 0 or sn > 4095:  # 2^12 - 1
                raise ValueError("SN out of range for 12-bit SN")
            header = self.DC_BIT_DATA << 7 | (sn & 0x7F)  # First 7 bits of SN
            return bytes([header, (sn >> 7) & 0x1F])  # Remaining 5 bits of SN
        else:  # 18-bit SN
            if sn < 0 or sn > 262143:  # 2^18 - 1
                raise ValueError("SN out of range for 18-bit SN")
            header = self.DC_BIT_DATA << 7 | ((sn >> 11) & 0x7F)  # First 7 bits of SN
            return bytes([header, (sn >> 3) & 0xFF, (sn & 0x07) << 5])  # Remaining 11 bits of SN

    def create_control_pdu_header(self, pdu_type):
        """
        Create a header for a PDCP Control PDU.
        
        :param pdu_type: Type of control PDU (e.g., 'STATUS_REPORT')
        :return: Bytes object representing the header
        """
        control_pdu_types = {
            'STATUS_REPORT': 0x00,
            'ROHC_FEEDBACK': 0x01,
            # Add more control PDU types
        }

        if pdu_type not in control_pdu_types:
            raise ValueError("Invalid control PDU type")

        header = (self.DC_BIT_CONTROL << 7) | control_pdu_types[pdu_type]
        return bytes([header])

    def parse_header(self, header_bytes):
        """
        Parse a PDCP header.
        
        :param header_bytes: Bytes object containing the header
        :return: Dictionary with header information
        """
        first_byte = header_bytes[0]
        dc_bit = (first_byte >> 7) & 0x01
        if dc_bit == self.DC_BIT_DATA:
            if len(header_bytes) >= 2:  # We might receive more than just the header
                sn_length = 12 if len(header_bytes) == 2 else 18
                if sn_length == 12:
                    sn = ((first_byte & 0x7F) << 5) | ((header_bytes[1] & 0xF8) >> 3)
                else:  # 18-bit SN
                    sn = ((first_byte & 0x7F) << 11) | (header_bytes[1] << 3) | ((header_bytes[2] & 0xE0) >> 5)
                return {
                    'pdu_type': 'Data',
                    'sn_length': sn_length,
                    'sn': sn
                }
            else:
                raise ValueError("Invalid header length for Data PDU")
        else:  # Control PDU
            pdu_type = first_byte & 0x7F
            control_pdu_types = {
                0x00: 'STATUS_REPORT',
                0x01: 'ROHC_FEEDBACK',
                # Add more control PDU types as needed
            }
            return {
                'pdu_type': 'Control',
                'control_pdu_type': control_pdu_types.get(pdu_type, 'Unknown')
            }

    def get_sn_from_data_pdu(self, pdu):
        """
        Extract the Sequence Number from a Data PDU.
        
        :param pdu: Bytes object containing the full PDU
        :return: Extracted Sequence Number
        """
        header_info = self.parse_header(pdu[:3])  # Parse up to 3 bytes to cover both 12 and 18-bit SN
        return header_info['sn']
