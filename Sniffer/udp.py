import struct
import Exceptions.exception as Exs


from .protocol import NetworkProtocol, NetworkLevel


class UDPProtocol(NetworkProtocol):
    def __init__(self, raw_data: bytes):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.TRANSPORT
        self.__parse()
        self.__offsset: int = 8

    def __parse(self):
        if self.data_length:
            try:
                header = struct.unpack('!HHHH', self.raw_data[:8])
                self.src_port = header[0]
                self.dst_port = header[1]
                self.length = header[2]     # Length all packet (header + data)
                self.chk_sum = header[3]
            except struct.error:
                raise Exs.UDPPacketParseError('Incorrect UDP packet format')
        else:
            raise Exs.UDPPacketParseError(f'No {self.__class__.__name__} header')

    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__offsset)

    def get_proto_info(self) -> str:
        return ''
