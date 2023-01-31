from enum import Enum
from typing import Callable

import Exceptions.exception as Exs


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
        raise Exs.NetworkParseError('Override function: %s in class: %s' % (self.get_proto_info.__name__,
                                                                           self.__class__.__name__))

    def __str__(self) -> str:
        return self.get_proto_info()

    @staticmethod
    def get_format_address(raw_addr: bytes, *, sep: str = '', function: Callable = str.upper) -> str:
        return f'{sep}'.join(map(function, raw_addr))

    def get_data(self, offset: int) -> bytes:
        if self.data_length:
            return self.raw_data[offset:]
        else:
            raise Exs.NetworkParseError('No raw data in %s object' % self.__class__.__name__)

    def get_json_proto_header(self):
        raise NotImplementedError('Override function')


class ARP(NetworkProtocol):
    pass

class UDP(NetworkProtocol):
    pass

class ICMP(NetworkProtocol):
    pass


if __name__ == '__main__':
    pass