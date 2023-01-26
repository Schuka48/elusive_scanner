import socket
import struct

import Exceptions.exception as Exs

from .protocol import NetworkLevel, NetworkProtocol


class EthernetFrame(NetworkProtocol):
    """
    Layer 2 protocol implementation of the OSI model.
    This class allows you to define Ethernet frame fields and save them in different formats.
    """
    def __init__(self, raw_data: bytes):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.DATALINK
        self.__parse_data()
        self.__offset: int = 14

    def __parse_data(self) -> None:
        if self.data_length:
            dst_mac, src_mac, proto = struct.unpack('!6s6sH', self.raw_data[:14])
        else:
            raise Exs.IPPacketParseError("Can't Parse Ethernet header.")

        self.dst_mac = self.get_format_address(dst_mac, sep=':', function="{:02x}".format).upper()
        self.src_mac = self.get_format_address(src_mac, sep=':', function="{:02x}".format).upper()
        self.encapsulated_proto = socket.ntohs(proto)

    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__offset)
    
    def get_proto_info(self) -> str:
        return '' # TODO: realize function get_proto_info

        
        
