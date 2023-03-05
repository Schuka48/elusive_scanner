import struct

import Exceptions.exception as Exs

from .protocol import NetworkLevel, NetworkProtocol
from .ethernet import EthernetFrameHeader


class IPPacketHeader:
    __level: NetworkLevel = NetworkLevel.NETWORK

    def __init__(self, ip_header: tuple):
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

    def __str__(self) -> str:
        result = f'{self.__level.value}\tIPv4:\n'
        result += f'TTL: {self.ttl}\tSrc: {self.source_address}\tDst: {self.destination_address}\n'
        return result


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
                raise Exs.IPPacketParseError('Incorrect IP packet format')
        else:
            raise Exs.IPPacketParseError("No {self.__class__.__name__} header")

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

    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__offset, self.header.total_length)

    def get_proto_info(self) -> str:
        # TODO: realize function, that return pretty view about network protocol
        result = str(self.__parent)
        result += str(self.__header)
        return result

    def set_parent(self, parent: EthernetFrameHeader) -> None:
        self.__parent = parent

    def set_child(self, child) -> None:
        self.__child = child

    def get_json_proto_header(self):
        pass
