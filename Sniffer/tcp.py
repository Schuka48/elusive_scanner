import array
import struct
import socket

import Exceptions.exception as Exs

from .protocol import NetworkLevel, NetworkProtocol
from .ip import IPPacketHeader


class TCPHeader:
    def __init__(self, header: tuple):
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

    def build_header(self, checksum=0) -> bytes:
        header = struct.pack('!HHIIHHHH', self.__src_port, self.__dst_port, self.__sequence, self.__acknowledgment,
                             self.__offset_reserved_flags, self.__window_size, checksum, self.__urgent_pointer)
        return header


class TCPPacket(NetworkProtocol):
    def __init__(self, raw_data: bytes, parent: IPPacketHeader = None):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.TRANSPORT
        self.__header = self.__parse_data()
        self.__parent = parent
        self.__child = None

    def __parse_data(self) -> TCPHeader:
        if self.data_length:
            try:
                header = struct.unpack('!HHIIHHHH', self.raw_data[:20])
                return TCPHeader(header)
            except struct.error:
                raise Exs.TCPPacketParseError('Incorrect TCP packet format')
        else:
            raise Exs.TCPPacketParseError('No {self.__class__.__name__} header')

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

    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.header.header_length)

    def get_proto_info(self) -> str:
        return ''  # TODO: realize function, that return pretty view about network protocol

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
            raise Exs.TCPPacketParseError('No parent')

    def checksum(self) -> int:
        packet = self.pseudo_header + self.__header.build_header(checksum=0) + self.get_encapsulated_data()
        if len(packet) % 2 != 0:
            packet += b'\0'

        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff

    def send_packet(self):
        pass

    def get_json_proto_header(self):
        pass
