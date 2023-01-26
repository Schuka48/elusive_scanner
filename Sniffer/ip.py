import struct

import Exceptions.exception as Exs

from .protocol import NetworkLevel, NetworkProtocol


class IPPacket(NetworkProtocol):
    def __init__(self, raw_data: bytes):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.NETWORK
        self.__parse_data()
        self.__offset = self.__header_len

    def __parse_data(self) -> None:
        if self.data_length:
            ip_header = struct.unpack('!BBHHHBBH4s4s', self.raw_data[:20])
        else:
            raise Exs.EthernetFrameParseError("Can't parse IP header.")
        
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
        self.__src_addr = self.get_format_address(ip_header[8], sep='.', function=str)
        self.__dst_addr = self.get_format_address(ip_header[9], sep='.', function=str)

    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__offset)

    def get_proto_info(self) -> str:
        return '' # TODO: realize function, that return pretty view about network protocol