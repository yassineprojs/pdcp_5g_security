import enum
import struct
import zlib

class ROHCProfile(enum.Enum):
    UNCOMPRESSED=0
    RTP = 1
    UDP = 2
    ESP = 3
    IP = 4


class ROHCMode(enum.Enum):
    UNIDIRECTIONAL = 0
    BIDIRECTIONAL_OPTIMISTIC = 1
    BIDERCTIONAL_RELIABLE =2

class ROHCError(Exception):
    pass

class ROHCCompressor:
    def __init__(self, profile: ROHCProfile, mode: ROHCMode = ROHCMode.UNIDIRECTIONAL):
        self.profile = profile
        self.mode = mode
        self.context = {}
        self.sn = 0  # Sequence Number
        self.gen_id = 0  # Generation ID for context
        self.max_cid = 15  # Maximum Context ID
        self.feedback_buffer = []
        self.last_packet = None



    def compress(self, ip_packet: bytes) -> bytes:
        if self.profile == ROHCProfile.UNCOMPRESSED:
            return self._compress_uncompressed(ip_packet)
        else:
            # For all other profiles, we'll use a simplified compression
            packet_type = 0xFD
            compressed = struct.pack('!BB', packet_type, self.profile.value)
            compressed += struct.pack('!B', 0)  # CID
            compressed += ip_packet  # For simplicity, we're not actually compressing
            self.last_packet = ip_packet
            return compressed

    def _compress_uncompressed(self, ip_packet: bytes) -> bytes:
        packet_type = 0xFE  # Uncompressed profile indicator
        cid = 0x00  # Assuming Context ID is 0
        return struct.pack('!BB', packet_type, cid) + ip_packet


    def _compress_rtp(self, ip_packet: bytes) -> bytes:
        # For this example, we'll just use IR packet type for RTP
        packet_type = 0xFD  # IR packet type
        compressed = struct.pack('!BB', packet_type, self.profile.value)
        compressed += struct.pack('!B', 0)  # CID (assuming 0 for simplicity)
        
        # Compress IP header
        ip_header = ip_packet[:20]
        version, _, total_length, id, _, ttl, protocol, _, src_ip, dst_ip = struct.unpack('!BBHHHBBHII', ip_header)
        compressed += struct.pack('!BBHHHBBHII', version, 0, total_length, id, 0, ttl, protocol, 0, src_ip, dst_ip)
        
        # Add UDP header (assuming UDP for RTP)
        udp_header = ip_packet[20:28]
        compressed += udp_header
        
        # Add RTP header (assuming RTP starts after UDP)
        rtp_header = ip_packet[28:40]
        compressed += rtp_header
        
        # Add payload
        compressed += ip_packet[40:]
        
        self._update_context(ip_header)
        return compressed

    def decompress(self, compressed_packet: bytes) -> bytes:
        packet_type = compressed_packet[0]
        if packet_type == 0xFE:  # UNCOMPRESSED
            return compressed_packet[2:]  # Skip the ROHC header (2 bytes)
        elif packet_type == 0xFD:  # Other profiles
            return compressed_packet[3:]  # Skip the ROHC header (3 bytes)
        else:
            raise ROHCError("Unknown packet type")


    def _decompress_uncompressed(self, compressed_packet: bytes) -> bytes:
        return compressed_packet[2:]  

    def _significant_changes(self, ip_header: bytes) -> bool:
        if not self.context:
            return True
        _, _, _, _, _, _, protocol, _, src_ip, dst_ip = struct.unpack('!BBHHHBBHII', ip_header)
        return (protocol != self.context.get('protocol') or
                src_ip != self.context.get('src_ip') or
                dst_ip != self.context.get('dst_ip'))

    def _minor_changes(self, ip_header: bytes) -> bool:
        if not self.context:
            return True
        _, _, total_length, id, _, ttl, _, _, _, _ = struct.unpack('!BBHHHBBHII', ip_header)
        return (total_length != self.context.get('last_length') or
                id != (self.context.get('last_id', 0) + 1) & 0xFFFF or
                ttl != self.context.get('last_ttl'))
    
    def _compress_ir(self, ip_header: bytes, payload: bytes) -> bytes:
        # IR packet format: [1 1 1 1 1 1 0 1] [Profile ID] [CID] [Static chain] [Dynamic chain] [Payload]
        packet_type = 0xFD  # 11111101 in binary (use dto identify that it's an IR packet)
        compressed = struct.pack('!BB', packet_type, self.profile.value)
        compressed += struct.pack('!B', 0)  # CID (assuming 0 for simplicity)
        
        # Static chain (for IPv4), only interested in the version field, which is the first byte. The rest of the fields are ignored (denoted by _).
        version, _, _, _, _, _, _, _ = struct.unpack('!BBHHHBBH', ip_header[:12])
        compressed += struct.pack('!B', version)
        
        # Dynamic chain (includes parts of the header that might change frequently between packets, needs to be synchronized with the decompressor.)
        _, _, total_length, id, _, ttl, protocol, _, src_ip, dst_ip = struct.unpack('!BBHHHBBHII', ip_header)
        compressed += struct.pack('!HHHBBII', total_length, id, 0, ttl, protocol, src_ip, dst_ip)
        
        self._update_context(ip_header)
        if self.profile == ROHCProfile.RTP:
            # Add RTP-specific compression logic here
            rtp_header = payload[:12]  # Assuming RTP header is 12 bytes
            ssrc, sequence, timestamp = struct.unpack('!III', rtp_header[4:])
            compressed += struct.pack('!III', ssrc, sequence, timestamp)
            payload = payload[12:]
        
        compressed += payload
        crc = self.calculate_crc(compressed)
        return compressed + struct.pack('!I', crc)

    def _compress_ir_dyn(self, ip_header: bytes, payload: bytes) -> bytes:
        # IR-DYN packet format: [1 1 1 1 1 0 0 0] [Profile ID] [CID] [Dynamic chain] [Payload]
        packet_type = 0xF8  # 11111000 in binary
        compressed = struct.pack('!BB', packet_type, self.profile.value)
        compressed += struct.pack('!B', 0)  # CID (assuming 0 for simplicity)
        
        # Dynamic chain
        _, _, total_length, id, _, ttl, _, _, _, _ = struct.unpack('!BBHHHBBHII', ip_header)
        compressed += struct.pack('!HHB', total_length, id, ttl)
        
        self._update_context(ip_header)
        return compressed + payload

    def _compress_uo(self, ip_header: bytes, payload: bytes) -> bytes:
        # UO-0 packet format: [0] [SN]
        _, _, total_length, id, _, ttl, _, _, _, _ = struct.unpack('!BBHHHBBHII', ip_header)
        
        if self._can_use_uo_0(total_length, id, ttl):
            compressed = struct.pack('!B', self.sn & 0x7F)  # 7-bit SN
        elif self._can_use_uo_1(total_length, id, ttl):
            # UO-1 packet format: [1 0] [IP-ID] [SN]
            ip_id_delta = (id - self.context['last_id']) & 0xFFFF
            compressed = struct.pack('!BH', 0x80 | (self.sn & 0x3F), ip_id_delta)
        else:
            # UO-2 packet format: [1 1 0] [IP-ID] [SN] [TTL]
            ip_id_delta = (id - self.context['last_id']) & 0xFFFF
            compressed = struct.pack('!BHH', 0xC0 | (self.sn & 0x3F), ip_id_delta, ttl)

        self._update_context(ip_header)
        self.sn = (self.sn + 1) & 0xFFFF
        return compressed + payload

    def _can_use_uo_0(self, total_length: int, id: int, ttl: int) -> bool:
        return (total_length == self.context['last_length'] and
                id == (self.context['last_id'] + 1) & 0xFFFF and
                ttl == self.context['last_ttl'])

    def _can_use_uo_1(self, total_length: int, id: int, ttl: int) -> bool:
        return (total_length == self.context['last_length'] and
                ttl == self.context['last_ttl'])

    def _significant_changes(self, ip_header: bytes) -> bool:
        if not self.context:
            return True
        _, _, _, _, _, _, protocol, _, src_ip, dst_ip = struct.unpack('!BBHHHBBHII', ip_header)
        return (protocol != self.context['protocol'] or
                src_ip != self.context['src_ip'] or
                dst_ip != self.context['dst_ip'])

    def _update_context(self, ip_header: bytes):
        _, _, total_length, id, _, ttl, protocol, _, src_ip, dst_ip = struct.unpack('!BBHHHBBHII', ip_header)
        self.context.update({
            'last_length': total_length,
            'last_id': id,
            'last_ttl': ttl,
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip
        })



    def _decompress_uncompressed(self, compressed_packet: bytes) -> bytes:
        if compressed_packet[0] == ROHCProfile.UNCOMPRESSED.value:
            return compressed_packet[1:]
        else:
            return compressed_packet  # Remove the profile identifier

    def _decompress_ir(self, compressed_packet: bytes) -> bytes:
        # Skip packet type, profile, and CID
        decompressed = compressed_packet[3:]
        
        # If it's RTP profile, we need to reconstruct the packet
        if self.profile == ROHCProfile.RTP:
            ip_header = decompressed[:20]
            udp_header = decompressed[20:28]
            rtp_header = decompressed[28:40]
            payload = decompressed[40:]
            
            # Reconstruct the packet
            return ip_header + udp_header + rtp_header + payload
        
        return decompressed

    def _decompress_ir_dyn(self, compressed_packet: bytes) -> bytes:
        _, profile, cid = struct.unpack('!BBB', compressed_packet[:3])
        dynamic_chain_start = 3
        
        # Decode dynamic chain
        total_length, id, ttl = struct.unpack('!HHB', compressed_packet[dynamic_chain_start:dynamic_chain_start+5])
        
        # Reconstruct IP header using context and new dynamic values
        ip_header = struct.pack('!BBHHHBBHII', 
                                self.context['version'] << 4 | 5, 
                                0, 
                                total_length, 
                                id, 
                                0, 
                                ttl, 
                                self.context['protocol'], 
                                0, 
                                self.context['src_ip'], 
                                self.context['dst_ip'])
        
        # Update context
        self._update_context(ip_header)
        
        # Return reconstructed packet
        return ip_header + compressed_packet[dynamic_chain_start+5:]

    def _decompress_uo(self, compressed_packet: bytes) -> bytes:
        if compressed_packet[0] & 0x80 == 0:  # UO-0
            sn = compressed_packet[0] & 0x7F
            payload_start = 1
            id = (self.context['last_id'] + 1) & 0xFFFF
            ttl = self.context['last_ttl']
        elif compressed_packet[0] & 0xC0 == 0x80:  # UO-1
            sn = compressed_packet[0] & 0x3F
            ip_id_delta, = struct.unpack('!H', compressed_packet[1:3])
            id = (self.context['last_id'] + ip_id_delta) & 0xFFFF
            ttl = self.context['last_ttl']
            payload_start = 3
        else:  # UO-2
            sn = compressed_packet[0] & 0x3F
            ip_id_delta, ttl = struct.unpack('!HH', compressed_packet[1:5])
            id = (self.context['last_id'] + ip_id_delta) & 0xFFFF
            payload_start = 5

        # Reconstruct IP header
        ip_header = struct.pack('!BBHHHBBHII', 
                                self.context['version'] << 4 | 5, 
                                0, 
                                self.context['last_length'], 
                                id, 
                                0, 
                                ttl, 
                                self.context['protocol'], 
                                0, 
                                self.context['src_ip'], 
                                self.context['dst_ip'])

        # Update context and sequence number
        self._update_context(ip_header)
        self.sn = (sn + 1) & 0xFFFF

        # Return reconstructed packet
        return ip_header + compressed_packet[payload_start:]


    def feedback(self, feedback: bytes):
        if self.mode != ROHCMode.UNIDIRECTIONAL:
            try:
                feedback_type = feedback[0] & 0xC0
                if feedback_type == 0:  # FEEDBACK-1
                    ack_type = feedback[0] & 0x3F
                    if ack_type == 0:
                        print("Received ACK")
                    elif ack_type == 1:
                        print("Received NACK")
                    elif ack_type == 2:
                        print("Received STATIC-NACK")
                elif feedback_type == 0x40:  # FEEDBACK-2
                    # Process FEEDBACK-2
                    ack_type = feedback[1] & 0x3F
                    sn = struct.unpack('!H', feedback[2:4])[0]
                    print(f"Received FEEDBACK-2: ACK type {ack_type}, SN {sn}")
                
                self.feedback_buffer.append(feedback)
            except IndexError:
                raise ROHCError("Invalid feedback format")

    def context_timeout(self):
        # Handle context timeout
        self.context.clear()
        self.sn = 0
        self.gen_id += 1

    @staticmethod
    def calculate_crc(data: bytes) -> int:
        return zlib.crc32(data) & 0xFFFFFFFF