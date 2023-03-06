import struct

import Exceptions.exception as Exs

from .protocol import NetworkProtocol, NetworkLevel
from .ip import IPPacketHeader


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

    def __str__(self) -> str:
        result = f'{self.__level.value}\tICMP:\n'
        result += f'Type: {self.__type}\tCode: {self.__code}\tChecksum: {self.__checksum}\n'
        result += f'Data: {self.__other_data}\n'
        return result


# TODO: Realize data class for ICMP packets
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
        self.__encapsulated_data = ICMPData(self.raw_data[self.header.offset:], self.__header)
        self.__parent: IPPacketHeader = parent

    def __parse_data(self) -> ICMPHeader:
        if self.data_length:
            try:
                header = struct.unpack('!BBHI', self.raw_data[:8])
                return ICMPHeader(header, self.raw_data)
            except struct.error:
                raise Exs.TCPPacketParseError('Incorrect TCP packet format')
        else:
            raise Exs.TCPPacketParseError('No {self.__class__.__name__} header')

    @property
    def level(self) -> NetworkLevel:
        return self.__level

    @property
    def header(self) -> ICMPHeader:
        return self.__header

    def get_proto_info(self) -> str:
        result = str(self.__parent)
        result += str(self.__header)
        return result

    def get_json_proto_header(self):
        pass
