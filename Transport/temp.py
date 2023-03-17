import socket
import struct
from enum import Enum
from typing import Callable

class ArgParseError(Exception):
    pass


class NoTargetIpAddr(ArgParseError):
    def __str__(self) -> str:
        return 'Target ip address is missing'


class NoListenPort(ArgParseError):
    def __str__(self) -> str:
        return 'No Port to listen for connections'


class NoListenIp(ArgParseError):
    def __str__(self) -> str:
        return 'No IP address to listen for connections'


class StopSniffer(Exception):
    pass

class RouteError(Exception):
    pass


class NetworkParseError(Exception):
    pass


class EthernetFrameParseError(NetworkParseError):
    pass


class IPPacketParseError(NetworkParseError):
    pass


class TCPPacketParseError(NetworkParseError):
    pass


class UDPPacketParseError(NetworkParseError):
    pass


class ICMPPacketParseError(NetworkParseError):
    pass

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

class NetworkLevel(Enum):
    DATALINK = 'DataLink layer'
    NETWORK = 'Network layer'
    TRANSPORT = 'Transport layer'
    APPLICATION = 'Application layer'


sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

print(raw_packet)

sender.sendto(raw_packet, ('192.168.25.1', 0))

sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

raw_data = sniffer.recvfrom(65535)[0]

print(NetworkProtocol(raw_data), NetworkLevel.NETWORK.value)