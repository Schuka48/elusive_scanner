import socket
import struct
from enum import Enum
from typing import Callable


class NetworkProtocol:
    def __init__(self, raw_data: bytes):
        self.raw_data = raw_data
        self.data_length = len(self.raw_data)

    def get_proto_info(self) -> str:
        raise Exs.NetworkParseError('Override function: %s in class: %s' % (self.get_proto_info.__name__,
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
            raise Exs.NetworkParseError('No raw data in %s object' % self.__class__.__name__)

    def get_json_proto_header(self):
        raise NotImplementedError('Override function')


class NetworkLevel(Enum):
    DATALINK = 'DataLink layer'
    NETWORK = 'Network layer'
    TRANSPORT = 'Transport layer'
    APPLICATION = 'Application layer'


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
        result = 'DATALINK\tEthernetProtocol:\n'
        result += f'Src MAC: {self.format_src_mac}\tDst MAC: {self.format_dst_mac}\t' \
                  f'Eth Proto: {self.encapsulated_proto}\n'
        return result


class EthernetFrame(NetworkProtocol):
    def __init__(self, raw_data: bytes):
        NetworkProtocol.__init__(self, raw_data)
        self.__header = self.__parse_data()
        self.__offset: int = 14

    def __parse_data(self) -> EthernetFrameHeader:
        if self.data_length:
            try:
                dst_mac, src_mac, proto = struct.unpack('!6s6sH', self.raw_data[:14])
                return EthernetFrameHeader(src_mac, dst_mac, proto)
            except struct.error:
                raise Exs.EthernetFrameParseError("Incorrect Ethernet frame format")
        else:
            raise Exs.EthernetFrameParseError(f"No {self.__class__.__name__} header")

    @property
    def header(self) -> EthernetFrameHeader:
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



sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

raw_data = sniffer.recvfrom(65535)[0]

print(EthernetFrame(raw_data))