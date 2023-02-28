import array
import struct
import socket

import Exceptions.exception as Exs

from .protocol import NetworkLevel, NetworkProtocol


class TCPProtocol(NetworkProtocol):
    def __init__(self, raw_data: bytes, parent=None):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.TRANSPORT
        self.__parse_data()
        self.__parent = parent
        self.__child = None

    def __parse_data(self) -> None:
        if self.data_length:
            try:
                header = struct.unpack('!HHIIHHHH', self.raw_data[:20])
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
            except struct.error:
                raise Exs.TCPPacketParseError('Incorrect TCP packet format')
        else:
            raise Exs.TCPPacketParseError('No {self.__class__.__name__} header')

    def set_parent(self, parent) -> None:
        self.__parent = parent

    def set_child(self, child) -> None:
        self.__child = child

    @property
    def source_port(self) -> int:
        return self.__src_port

    @property
    def destination_port(self) -> int:
        return self.__dst_port

    @property
    def flags(self):
        return self.__flags

    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__offset)

    def get_proto_info(self) -> str:
        return ''  # TODO: realize function, that return pretty view about network protocol

    def build_header(self) -> bytes:
        header = struct.pack('!HHIIHHHH', self.__src_port, self.__dst_port, self.__sequence, self.__acknowledgment,
                             self.__offset_reserved_flags, self.__window_size, self.__check_sum, self.__urgent_pointer)
        return header

    @property
    def pseudo_header(self) -> bytes:
        return struct.pack('!4s4sHH', socket.inet_aton(self.__parent.source_address),
                           socket.inet_aton(self.__parent.destination_address), socket.IPPROTO_TCP, self.data_length)

    @staticmethod
    def checksum(packet):
        if len(packet) % 2 != 0:
            packet += b'\0'

        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff

    def send_packet(self):
        pass

