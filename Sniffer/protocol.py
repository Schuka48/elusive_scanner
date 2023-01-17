from typing import Callable
import Exceptions.exception as Exs
from enum import Enum


class NetworkLevel(Enum):
    """
    This class implements an enumeration that contains the layers of network protocols according to the OSI model.
    """
    DATALINK = 'DataLink layer'
    NETWORK = 'Network layer'
    TRANSPORT = 'Transport layer'
    APPLICATION = 'Application layer'


class NetworkProtocol:
    """
    This class is an abstract class for inheritance.
    It contains basic functions for implementing network protocol classes handled by this application.
    """
    def __init__(self, raw_data: bytes):
        self.raw_data = raw_data
        self.data_length = len(self.raw_data)

    def get_proto_info(self) -> str:
        raise Exs.NetworkParseError('Override function: %s in class:%s' % (self.get_proto_info.__name__,
                                                                           self.__class__.__name__))

    def __str__(self) -> str:
        return self.get_proto_info()

    def parse_data(self) -> None:
        raise Exs.NetworkParseError('Override parse_data function')

    @staticmethod
    def get_format_address(raw_addr: bytes, *, sep: str = '', function: Callable = str.upper) -> str:
        return f'{sep}'.join(map(function, raw_addr))

    def get_encapsulated_data(self, offset: int) -> bytes:
        if self.data_length:
            return self.raw_data[offset:]
        else:
            raise Exs.NetworkParseError('No raw data in %s object' % self.__class__.__name__)


class Ethernet(NetworkProtocol):
    """
    Layer 2 protocol implementation of the OSI model.
    This class allows you to define Ethernet frame fields and save them in different formats.
    """
    def __init__(self, raw_data: bytes):
        NetworkProtocol.__init__(self, raw_data)
        self.level: NetworkLevel = NetworkLevel.DATALINK
        self.parse_data()

    def parse_data(self) -> None:
        pass


class IP(NetworkProtocol):
    pass


class ARP(NetworkProtocol):
    pass


class TCP(NetworkProtocol):
    pass


class UDP(NetworkProtocol):
    pass


if __name__ == '__main__':
    pass