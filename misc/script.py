import socket
import struct
import array
import signal
from enum import Enum
from typing import Callable
from dataclasses import dataclass


class NetworkParseError(Exception):
    pass
class NetworkLevel(Enum):
    DATALINK = 'DataLink layer'
    NETWORK = 'Network layer'
    TRANSPORT = 'Transport layer'
    APPLICATION = 'Application layer'
class NetworkProtocol:
    def __init__(self, raw_data: bytes):
        self.raw_data = raw_data
        self.data_length = len(self.raw_data)

    def get_proto_info(self) -> str:
        raise NetworkParseError('Override function: %s in class: %s' % (self.get_proto_info.__name__,
                                                                        self.__class__.__name__))

    def __str__(self) -> str:
        return self.get_proto_info()

    @staticmethod
    def get_format_address(raw_addr: bytes, *, sep: str = '', function: Callable = str.upper) -> str:
        return f'{sep}'.join(map(function, raw_addr))

    def get_data(self, offset: int, total_length: int = None) -> bytes:
        if self.data_length:
            return self.raw_data[offset:] if total_length is None else self.raw_data[offset:total_length]
        else:
            raise NetworkParseError('No raw data in %s object' % self.__class__.__name__)

    def get_json_proto_header(self):
        raise NotImplementedError('Override function')
class EthernetFrameHeader:
    def __init__(self, src_mac: bytes, dst_mac: bytes, encapsulated_proto: int) -> None:
        self.__src_mac: bytes = src_mac
        self.__dst_mac: bytes = dst_mac
        self.__encapsulated_proto: int = encapsulated_proto

    @property
    def format_src_mac(self) -> str:
        return NetworkProtocol.get_format_address(self.__src_mac, sep=':', function="{:02x}".format).upper()

    @property
    def format_dst_mac(self) -> str:
        return NetworkProtocol.get_format_address(self.__dst_mac, sep=':', function="{:02x}".format).upper()

    @property
    def encapsulated_proto(self) -> int:
        return socket.ntohs(self.__encapsulated_proto)

    @property
    def source_mac(self) -> bytes:
        return self.__src_mac

    @property
    def destination_mac(self) -> bytes:
        return self.__dst_mac

    def __str__(self) -> str:
        result = f'DATALINK\tEthernetProtocol:\n'
        result += f'Src MAC: {self.format_src_mac}\tDst MAC: {self.format_dst_mac}\t' \
                  f'Eth Proto: {self.encapsulated_proto}\n'
        return result
class EthernetFrame(NetworkProtocol):
    def __init__(self, raw_data: bytes):
        NetworkProtocol.__init__(self, raw_data)
        self.__header = self.__parse_data()
        self.__offset: int = 14

    def __parse_data(self):
        if self.data_length:
            try:
                dst_mac, src_mac, proto = struct.unpack('!6s6sH', self.raw_data[:14])
                return EthernetFrameHeader(src_mac, dst_mac, proto)
            except struct.error:
                raise NetworkParseError("Incorrect Ethernet frame format")
        else:
            raise NetworkParseError(f"No {self.__class__.__name__} header")

    @property
    def header(self):
        return self.__header

    @property
    def source_mac(self) -> bytes:
        return self.__header.source_mac

    @property
    def destination_mac(self) -> bytes:
        return self.__header.destination_mac

    @property
    def encapsulated_proto(self) -> int:
        return self.__header.encapsulated_proto

    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__offset)

    def get_proto_info(self) -> str:
        return str(self.__header)

    def get_json_proto_header(self):
        pass
class IPPacketHeader:
    __level: NetworkLevel = NetworkLevel.NETWORK
    def __init__(self, ip_header: tuple):
        self.__first_byte = ip_header[0]
        self.__version = ip_header[0] >> 4
        self.__hLen = ip_header[0] & 0xF
        self.__header_len = self.__hLen * 4
        self.__tos = ip_header[1]
        self.__total_len = ip_header[2]
        self.__unique_id = ip_header[3]
        self.__offset_flags = ip_header[4]
        self.__ttl = ip_header[5]
        self.__proto = ip_header[6]
        self.__checksum = ip_header[7]
        # self.__src_addr = ip_header[8]
        # self.__dst_addr = ip_header[9]
        self.__src_addr = NetworkProtocol.get_format_address(ip_header[8], sep='.', function=str)
        self.__dst_addr = NetworkProtocol.get_format_address(ip_header[9], sep='.', function=str)
    @property
    def source_address(self):
        return self.__src_addr
    @property
    def destination_address(self):
        return self.__dst_addr
    @property
    def header_length(self):
        return self.__header_len
    @property
    def protocol(self):
        return self.__proto
    @property
    def ttl(self):
        return self.__ttl
    @property
    def level(self):
        return self.__level
    @property
    def total_length(self):
        return self.__total_len
    def set_source_address(self, source_address: str):
        self.__src_addr = source_address
    def __str__(self) -> str:
        result = f'{self.__level.value}\tIPv4:\n'
        result += f'TTL: {self.ttl}\tSrc: {self.source_address}\tDst: {self.destination_address}\n'
        result += f'Checksum: {hex(self.__checksum)}\n'
        return result
    def build_header(self, checksum=0) -> bytes:
        header = struct.pack('!B', self.__first_byte) +\
                 struct.pack('!BHHHBB', self.__tos, self.__total_len, self.__unique_id, self.__offset_flags, self.__ttl,
                             self.__proto) +\
                 struct.pack('H', checksum) + struct.pack('!4s4s', socket.inet_aton(self.__src_addr),
                                                          socket.inet_aton(self.__dst_addr))
        return header
    def get_raw_header(self):
        header = struct.pack('!BBHHHBBH4s4s', self.__first_byte, self.__tos, self.__total_len,
                             self.__unique_id, self.__offset_flags, self.__ttl, self.__proto, self.__checksum,
                             self.__src_addr, self.__dst_addr)
        return header
    def set_destination_address(self, destination_address: str) -> None:
        self.__dst_addr = destination_address
class IPPacket(NetworkProtocol):
    def __init__(self, raw_data: bytes, parent: EthernetFrameHeader = None):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.NETWORK
        self.__header = self.__parse_data()
        self.__offset = self.__header.header_length
        self.__child = None
        self.__parent = parent
    def __parse_data(self) -> IPPacketHeader:
        if self.data_length:
            try:
                ip_header = struct.unpack('!BBHHHBBH4s4s', self.raw_data[:20])
                return IPPacketHeader(ip_header)
            except struct.error:
                raise NetworkParseError('Incorrect IP packet format')
        else:
            raise NetworkParseError("No {self.__class__.__name__} header")
    @property
    def header(self):
        return self.__header
    @property
    def source_address(self):
        return self.__header.source_address
    @property
    def destination_address(self):
        return self.__header.destination_address
    @property
    def protocol(self):
        return self.__header.protocol
    def checksum(self) -> int:
        packet = self.__header.build_header(checksum=0) + self.get_encapsulated_data()
        if len(packet) % 2 != 0:
            packet += b'\0'

        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff
    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__offset, self.header.total_length)
    def get_packet(self) -> bytes:
        return self.__header.build_header(checksum=self.checksum()) + self.get_encapsulated_data()
    def get_proto_info(self) -> str:
        result = str(self.__parent)
        result += str(self.__header)
        return result
    def set_parent(self, parent: EthernetFrameHeader) -> None:
        self.__parent = parent
    def set_child(self, child) -> None:
        self.__child = child
    def set_source_address(self, ip_address: str) -> None:
        self.__header.set_source_address(ip_address)
        self.checksum()
    def set_destination_address(self, ip_address: str) -> None:
        self.__header.set_destination_address(ip_address)
    def get_json_proto_header(self):
        pass
class TCPHeader:
    __level: NetworkLevel = NetworkLevel.TRANSPORT

    def __init__(self, header: tuple, raw_header: bytes = None):
        self.__src_port = header[0]
        self.__dst_port = header[1]
        self.__sequence = header[2]
        self.__acknowledgment = header[3]
        self.__offset_reserved_flags = header[4]
        self.__offset = (self.__offset_reserved_flags >> 12) * 4
        self.__reserved = (self.__offset_reserved_flags >> 8) & 15
        flag_urg = (self.__offset_reserved_flags & 32) >> 5
        flag_ack = (self.__offset_reserved_flags & 16) >> 4
        flag_psh = (self.__offset_reserved_flags & 8) >> 3
        flag_rst = (self.__offset_reserved_flags & 4) >> 2
        flag_syn = (self.__offset_reserved_flags & 2) >> 1
        flag_fin = self.__offset_reserved_flags & 1
        self.__flags = {
            'URG': flag_urg,
            'ACK': flag_ack,
            'PSH': flag_psh,
            'RST': flag_rst,
            'SYN': flag_syn,
            'FIN': flag_fin
        }
        self.__window_size = header[5]
        self.__check_sum = header[6]
        self.__urgent_pointer = header[7]
        self.__options = None if self.__offset == 20 else raw_header[20:self.__offset]
    @property
    def source_port(self) -> int:
        return self.__src_port
    @property
    def destination_port(self) -> int:
        return self.__dst_port
    @property
    def sequence(self) -> int:
        return self.__sequence
    @property
    def flags(self) -> dict:
        return self.__flags
    @property
    def header_length(self) -> int:
        return self.__offset
    @property
    def checksum(self) -> int:
        return self.__check_sum
    @property
    def level(self):
        return self.__level
    def build_header(self, checksum=0) -> bytes:
        header = struct.pack('!HHIIHH', self.__src_port, self.__dst_port, self.__sequence, self.__acknowledgment,
                             self.__offset_reserved_flags, self.__window_size) + \
                 struct.pack('H', checksum) + struct.pack('!H', self.__urgent_pointer)
        if self.__options is not None:
            header += self.__options
        return header
    def get_raw_header(self):
        header = struct.pack('!HHIIHHHH', self.__src_port, self.__dst_port, self.__sequence, self.__acknowledgment,
                             self.__offset_reserved_flags, self.__window_size, self.__check_sum, self.__urgent_pointer)
        if self.__options is not None:
            header += self.__options
        return header
    def __str__(self) -> str:
        result = f'{self.__level.value}\tTCP:\n'
        result += f'Src port: {self.source_port}\tDst port: {self.destination_port}\tChecksum: {hex(self.checksum)}\n'
        result += 'Flags:\n'
        flags = [f'{flag}' for flag in self.__flags.keys() if self.__flags[flag] != 0]
        for flag in flags:
            result += f'{flag}\n'
        return result
class TCPPacket(NetworkProtocol):
    def __init__(self, raw_data: bytes, parent: IPPacketHeader = None):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.TRANSPORT
        self.__header = self.__parse_data()
        self.__parent: IPPacketHeader = parent
        self.__child = None
    def __parse_data(self) -> TCPHeader:
        if self.data_length:
            try:
                header = struct.unpack('!HHIIHHHH', self.raw_data[:20])
                return TCPHeader(header, self.raw_data)
            except struct.error:
                raise NetworkParseError('Incorrect TCP packet format')
        else:
            raise NetworkParseError('No {self.__class__.__name__} header')
    def set_parent(self, parent: IPPacketHeader) -> None:
        self.__parent = parent
    def set_child(self, child) -> None:
        self.__child = child
    @property
    def source_port(self) -> int:
        return self.__header.source_port
    @property
    def destination_port(self) -> int:
        return self.__header.destination_port
    @property
    def flags(self):
        return self.__header.flags
    @property
    def header(self) -> TCPHeader:
        return self.__header
    @property
    def pseudo_header(self) -> bytes:
        if self.__parent is not None:
            return struct.pack(
                '!4s4sHH', socket.inet_aton(self.__parent.source_address),
                socket.inet_aton(self.__parent.destination_address),
                socket.IPPROTO_TCP, self.data_length
            )
        else:
            raise NetworkParseError('No parent')
    @property
    def parent(self) -> IPPacketHeader:
        return self.__parent
    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.header.header_length)
    def checksum(self) -> int:
        packet = self.pseudo_header + self.__header.build_header(checksum=0) + self.get_encapsulated_data()
        if len(packet) % 2 != 0:
            packet += b'\0'
        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff
    def get_packet(self) -> bytes:
        return self.__header.build_header(checksum=self.checksum()) + self.get_encapsulated_data()
    def get_proto_info(self) -> str:
        result = str(self.__parent)
        result += str(self.header)
        return result
    def get_json_proto_header(self):
        pass
class UDPHeader:
    __level: NetworkLevel = NetworkLevel.TRANSPORT
    def __init__(self, header: tuple):
        self.__src_port = header[0]
        self.__dst_port = header[1]
        self.__length = header[2]  # Length all packet (header + data)
        self.__chk_sum = header[3]
        self.__offset = 8
    @property
    def source_port(self):
        return self.__src_port
    @property
    def destination_port(self):
        return self.__dst_port
    @property
    def length(self):
        return self.__length
    @property
    def checksum(self):
        return self.__chk_sum
    @property
    def offset(self):
        return self.__offset
    def build_header(self, checksum=0) -> bytes:
        header = struct.pack('!HHH', self.source_port, self.destination_port, self.length) + struct.pack('H', checksum)
        return header
    def __str__(self) -> str:
        result = f'{self.__level.value}\tUDP:\n'
        result += f'Src Port: {self.source_port}\tDst Port: {self.destination_port}\tChecksum: {hex(self.checksum)}\n'
        return result
class UDPPacket(NetworkProtocol):
    def __init__(self, raw_data: bytes, parent: IPPacketHeader = None):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.TRANSPORT
        self.__header = self.__parse()
        self.__parent: IPPacketHeader = parent
    def __parse(self) -> UDPHeader:
        if self.data_length:
            try:
                header = struct.unpack('!HHHH', self.raw_data[:8])
                return UDPHeader(header)
            except struct.error:
                raise NetworkParseError('Incorrect UDP packet format')
        else:
            raise NetworkParseError(f'No {self.__class__.__name__} header')
    @property
    def header(self) -> UDPHeader:
        return self.__header
    @property
    def source_port(self) -> int:
        return self.__header.source_port
    @property
    def destination_port(self) -> int:
        return self.__header.destination_port
    @property
    def length(self) -> int:
        return self.__header.length
    @property
    def parent(self) -> IPPacketHeader:
        return self.__parent
    @property
    def pseudo_header(self) -> bytes:
        if self.__parent is not None:
            return struct.pack(
                '!4s4sHH', socket.inet_aton(self.__parent.source_address),
                socket.inet_aton(self.__parent.destination_address),
                socket.IPPROTO_UDP, self.data_length
            )
        else:
            raise NetworkParseError('No parent')
    def checksum(self) -> int:
        packet = self.pseudo_header + self.__header.build_header(checksum=0) + self.get_encapsulated_data()
        if len(packet) % 2 != 0:
            packet += b'\0'

        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff
    def get_packet(self) -> bytes:
        return self.__header.build_header(checksum=self.checksum()) + self.get_encapsulated_data()
    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__header.offset)
    def get_proto_info(self) -> str:
        result = str(self.__parent)
        result += str(self.__header)
        return result
    def get_json_proto_header(self):
        pass
class ICMPHeader:
    __level = NetworkLevel.NETWORK
    def __init__(self, header: tuple, raw_header: bytes):
        self.__type = header[0]
        self.__code = header[1]
        self.__checksum = header[2]
        self.__add_info = header[3]
        self.__offset = 8
        self.__other_data = raw_header[self.__offset:]
    @property
    def type(self) -> int:
        return self.__type
    @property
    def code(self) -> int:
        return self.__code
    @property
    def checksum(self) -> int:
        return self.__checksum
    @property
    def packet_data(self) -> bytes:
        return self.__other_data
    @property
    def offset(self) -> int:
        return self.__offset
    @property
    def encapsulated_data(self):
        return self.__other_data
    def build_header(self, checksum=0) -> bytes:
        return struct.pack('!BB', self.__type, self.__code) + struct.pack('H', checksum) + \
            struct.pack('!I', self.__add_info)
    def __str__(self) -> str:
        result = f'{self.__level.value}\tICMP:\n'
        result += f'Type: {self.__type}\tCode: {self.__code}\tChecksum: {hex(self.__checksum)}\n'
        result += f'Data: {self.__other_data}\n'
        return result
class ICMPData:
    def __init__(self, raw_data: bytes, header: ICMPHeader):
        self.__raw_data = raw_data
        self.__header = header
    @property
    def encapsulate_data(self) -> bytes:
        if self.__header.type == 8 or self.__header.type == 0:
            return self.__raw_data
class ICMPPacket(NetworkProtocol):
    def __init__(self, raw_data: bytes, parent: IPPacketHeader):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.NETWORK
        self.__header = self.__parse_data()
        self.__encapsulated_data = self.__header.encapsulated_data
        self.__parent: IPPacketHeader = parent
    def __parse_data(self) -> ICMPHeader:
        if self.data_length:
            try:
                header = struct.unpack('!BBHI', self.raw_data[:8])
                return ICMPHeader(header, self.raw_data)
            except struct.error:
                raise NetworkParseError('Incorrect TCP packet format')
        else:
            raise NetworkParseError('No {self.__class__.__name__} header')
    @property
    def level(self) -> NetworkLevel:
        return self.__level
    @property
    def header(self) -> ICMPHeader:
        return self.__header
    def checksum(self) -> int:
        packet = self.__header.build_header(checksum=0) + self.__encapsulated_data
        if len(packet) % 2 != 0:
            packet += b'\0'

        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff
    def get_packet(self):
        return self.__header.build_header(checksum=self.checksum()) + self.__encapsulated_data
    def get_proto_info(self) -> str:
        result = str(self.__parent)
        result += str(self.__header)
        return result
    def get_json_proto_header(self):
        pass
class ProtocolType(Enum):
    IP = 8
    ICMP = 1
    TCP = 6
    UDP = 17
    ARP = 26632
@dataclass(frozen=True)
class EndInfo:
    end_protocol: ProtocolType
    end_level: NetworkLevel
class Packet:
    def __init__(self, ethernet_frame: EthernetFrame):
        self.__raw_data = ethernet_frame.get_encapsulated_data()
        self.__end_protocol: EndInfo = EndInfo(ProtocolType.IP, NetworkLevel.NETWORK)
        self.__network_stack: dict[NetworkLevel, list] = {NetworkLevel.DATALINK: [ethernet_frame]}
        self.__parse_raw_data()
    @property
    def stack(self):
        return self.__network_stack
    @property
    def datalink_header(self) -> EthernetFrameHeader:
        return self.__network_stack.get(NetworkLevel.DATALINK)[0].header
    @property
    def ip_packet(self) -> IPPacket:
        return self.__network_stack[NetworkLevel.NETWORK][0]
    @property
    def last_protocol(self):
        return self.__end_protocol
    def __str__(self):
        return str(self.stack[self.__end_protocol.end_level][-1])
    def __put_packet_on_stack(self, level: NetworkLevel, proto_type: ProtocolType, packet):
        if self.__network_stack.get(level) is None:
            self.__network_stack[level] = [packet]
        else:
            self.__network_stack[level].append(packet)
        self.__end_protocol = EndInfo(proto_type, level)
    def __parse_tcp_packet(self, ip_packet: IPPacket) -> None:
        tcp_packet = TCPPacket(ip_packet.get_encapsulated_data(), ip_packet.header)
        self.__put_packet_on_stack(NetworkLevel.TRANSPORT, ProtocolType.TCP, tcp_packet)
    def __parse_udp_packet(self, ip_packet: IPPacket) -> None:
        udp_packet = UDPPacket(ip_packet.get_encapsulated_data(), ip_packet.header)
        self.__put_packet_on_stack(NetworkLevel.TRANSPORT, ProtocolType.UDP, udp_packet)
    def __parse_icmp_packet(self, ip_packet: IPPacket) -> None:
        icmp_packet = ICMPPacket(ip_packet.get_encapsulated_data(), ip_packet.header)
        self.__put_packet_on_stack(NetworkLevel.NETWORK, ProtocolType.ICMP, icmp_packet)
    def __parse_raw_data(self):
        ip_packet = IPPacket(self.__raw_data, self.datalink_header)
        self.__network_stack[NetworkLevel.NETWORK] = [ip_packet]

        if ip_packet.protocol == ProtocolType.TCP.value:
            self.__parse_tcp_packet(ip_packet)

        elif ip_packet.protocol == ProtocolType.UDP.value:
            self.__parse_udp_packet(ip_packet)

        elif ip_packet.protocol == ProtocolType.ICMP.value:
            self.__parse_icmp_packet(ip_packet)
def create_active_packet(packet: Packet, destination: str):
    top_level = packet.last_protocol

    if top_level.end_level == NetworkLevel.NETWORK:
        if top_level.end_protocol == ProtocolType.ICMP:
            icmp_packet: ICMPPacket = packet.stack[NetworkLevel.NETWORK][1]
            ip_packet = packet.stack[NetworkLevel.NETWORK][0]
            ip_packet.set_destination_address(destination)
            raw_packet = ip_packet.header.build_header() + icmp_packet.get_packet()
            return raw_packet

        elif top_level.end_protocol == ProtocolType.IP:
            ip_packet: IPPacket = packet.stack[NetworkLevel.NETWORK][0]
            ip_packet.set_destination_address(destination)
            return ip_packet.get_packet()

        else:
            pass
    elif top_level.end_level == NetworkLevel.TRANSPORT:
        if top_level.end_protocol == ProtocolType.TCP:
            tcp_packet: TCPPacket = packet.stack[NetworkLevel.TRANSPORT][0]
            ip_packet: IPPacket = packet.stack[NetworkLevel.NETWORK][0]
            ip_packet.set_destination_address(destination)
            raw_packet = ip_packet.header.build_header() + tcp_packet.get_packet()
            return raw_packet

        elif top_level.end_protocol == ProtocolType.UDP:
            udp_packet: UDPPacket = packet.stack[NetworkLevel.TRANSPORT][0]
            ip_packet: IPPacket = packet.stack[NetworkLevel.NETWORK][0]
            ip_packet.set_destination_address(destination)
            raw_packet = ip_packet.header.build_header() + udp_packet.get_packet()
            return raw_packet

        else:
            pass
    else:
        pass
class NetworkFilter:
    def __init__(self, params: dict):
        self.params = {param: params.get(param) for param in params if params.get(param) is not None}

    def filtrate(self, ethernet: EthernetFrame) -> bool:
        net_level_proto = ethernet.header.encapsulated_proto
        if self.params.get('ARP') is None and net_level_proto == ProtocolType.ARP.value:
            return False
        elif net_level_proto == ProtocolType.IP.value:
            if self.params.get('is_router') is None or self.params.get('is_router') is False:
                destination_ip = self.params.get('target_ip')
                source_ip = self.params.get('listen_ip')
            else:
                destination_ip = self.params.get('listen_ip')
                source_ip = self.params.get('target_ip')

            ip_packet = IPPacket(ethernet.get_encapsulated_data(), ethernet.header)
            if ip_packet.destination_address == destination_ip and ip_packet.source_address == source_ip:
                return True
            else:
                # TODO: Сделать фильтр интеллектуальнее
                return False
def timeout(timeout):
    def decorator(func):
        def wrapper(*args, **kwargs):
            def handler(signum, frame):
                raise TimeoutError("Function call timed out")
            signal.signal(signal.SIGALRM, handler)
            signal.setitimer(signal.ITIMER_REAL, timeout)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result
        return wrapper
    return decorator
@timeout(0.5)
def handle_net_packet(sniffer, sender, net_filter):
    while True:
        raw_net_data = sniffer.recvfrom(65535)[0]
        ethernet = EthernetFrame(raw_net_data)

        if net_filter.filtrate(ethernet):
            net_packet = Packet(ethernet)
            # print(net_packet)
            raw_net_packet = create_active_packet(net_packet, '192.168.148.5')
            sender.sendto(raw_net_packet, ('192.168.148.5', 0))
            break


def main():
    net_filter = NetworkFilter({'target_ip': '192.168.25.128', 'listen_ip': '192.168.25.1'})
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

    sender.sendto(raw_packet, ('192.168.25.1', 0))

    try:
        handle_net_packet(sniffer, sender, net_filter)
    except TimeoutError:
        print('Pass packet')


main()
