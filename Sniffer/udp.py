import struct
import Exceptions.exception as Exs


from .protocol import NetworkProtocol, NetworkLevel


class UDPHeader:
    def __init__(self, header: tuple):
        self.__src_port = header[0]
        self.__dst_port = header[1]
        self.__length = header[2]  # Length all packet (header + data)
        self.__chk_sum = header[3]
        self.__offset = 8

    @property
    def source_port(self):
        return self.__src_port

    @property
    def destination_port(self):
        return self.__dst_port

    @property
    def length(self):
        return self.__length

    @property
    def chk_sum(self):
        return self.__chk_sum

    @property
    def offset(self):
        return self.__offset

    def __str__(self) -> str:
        return f''


class UDPPacket(NetworkProtocol):
    def __init__(self, raw_data: bytes):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.TRANSPORT
        self.__header = self.__parse()

    def __parse(self) -> UDPHeader:
        if self.data_length:
            try:
                header = struct.unpack('!HHHH', self.raw_data[:8])
                return UDPHeader(header)
            except struct.error:
                raise Exs.UDPPacketParseError('Incorrect UDP packet format')
        else:
            raise Exs.UDPPacketParseError(f'No {self.__class__.__name__} header')

    @property
    def header(self) -> UDPHeader:
        return self.__header

    @property
    def source_port(self) -> int:
        return self.__header.source_port

    @property
    def destination_port(self) -> int:
        return self.__header.destination_port

    @property
    def length(self) -> int:
        return self.__header.length

    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__header.offset)

    def get_proto_info(self) -> str:
        return ''

    def get_json_proto_header(self):
        pass
