import socket
import struct
from dataclasses import dataclass
import Exceptions.exception as Exs

from .protocol import NetworkLevel, NetworkProtocol


class EthernetFrameHeader:
    def __init__(self, src_mac: bytes, dst_mac: bytes, encapsulated_proto: int) -> None:
        self.__src_mac: bytes = src_mac
        self.__dst_mac: bytes = dst_mac
        self.__encapsulated_proto: int = encapsulated_proto

    @property
    def format_src_mac(self) -> str:
        return NetworkProtocol.get_format_address(self.__src_mac, sep=';', function="{:02x}".format).upper()

    @property
    def format_dst_mac(self) -> str:
        return NetworkProtocol.get_format_address(self.__dst_mac, sep=';', function="{:02x}".format).upper()

    @property
    def encapsulated_proto(self) -> int:
        return self.__encapsulated_proto

    @property
    def src_mac(self) -> bytes:
        return self.__src_mac

    @property
    def dst_mac(self) -> bytes:
        return self.__dst_mac


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
            try:
                dst_mac, src_mac, proto = struct.unpack('!6s6sH', self.raw_data[:14])
                self.__dst_mac = self.get_format_address(dst_mac, sep=':', function="{:02x}".format).upper()
                self.__src_mac = self.get_format_address(src_mac, sep=':', function="{:02x}".format).upper()
                self.__encapsulated_proto = socket.ntohs(proto)
                self.__header = EthernetFrameHeader(src_mac, dst_mac, socket.ntohs(proto))
            except struct.error:
                raise Exs.EthernetFrameParseError("Incorrect Ethernet frame format")
        else:
            raise Exs.EthernetFrameParseError(f"No {self.__class__.__name__} header")

    @property
    def dst_mac(self) -> str:
        return self.__dst_mac

    @property
    def src_mac(self) -> str:
        return self.__src_mac

    @property
    def encapsulated_proto(self) -> int:
        return self.__encapsulated_proto

    @property
    def header(self) -> EthernetFrameHeader:
        return self.__header

    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__offset)

    def get_proto_info(self) -> str:
        result = f'{self.__level.value}\tEthernetProtocol:\n'
        result += f'Src MAC: {self.__src_mac}\tDst MAC: {self.__dst_mac}\tEth Proto: {self.__encapsulated_proto}\n'
        return result
