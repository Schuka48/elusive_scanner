import array
import struct
import socket

import Exceptions.exception as Exs

from .protocol import NetworkLevel, NetworkProtocol
from .ip import IPPacketHeader


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

    def get_tcp_packet(self) -> bytes:
        return self.__header.build_header(checksum=self.checksum()) + self.get_encapsulated_data()

    def get_proto_info(self) -> str:
        result = str(self.__parent)
        result += str(self.header)
        return result

    def get_json_proto_header(self):
        pass
