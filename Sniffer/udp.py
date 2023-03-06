import struct
import socket
import array

import Exceptions.exception as Exs


from .protocol import NetworkProtocol, NetworkLevel
from .ip import IPPacketHeader


class UDPHeader:
    __level: NetworkLevel = NetworkLevel.TRANSPORT

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
    def checksum(self):
        return self.__chk_sum

    @property
    def offset(self):
        return self.__offset

    def build_header(self, checksum=0) -> bytes:
        header = struct.pack('!HHH', self.source_port, self.destination_port, self.length) + struct.pack('H', checksum)
        return header

    def __str__(self) -> str:
        result = f'{self.__level.value}\tUDP:\n'
        result += f'Src Port: {self.source_port}\tDst Port: {self.destination_port}\tChecksum: {hex(self.checksum)}\n'
        return result


class UDPPacket(NetworkProtocol):
    def __init__(self, raw_data: bytes, parent: IPPacketHeader = None):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.TRANSPORT
        self.__header = self.__parse()
        self.__parent: IPPacketHeader = parent

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

    @property
    def parent(self) -> IPPacketHeader:
        return self.__parent

    @property
    def pseudo_header(self) -> bytes:
        if self.__parent is not None:
            return struct.pack(
                '!4s4sHH', socket.inet_aton(self.__parent.source_address),
                socket.inet_aton(self.__parent.destination_address),
                socket.IPPROTO_UDP, self.data_length
            )
        else:
            raise Exs.TCPPacketParseError('No parent')

    def checksum(self) -> int:
        packet = self.pseudo_header + self.__header.build_header(checksum=0) + self.get_encapsulated_data()
        if len(packet) % 2 != 0:
            packet += b'\0'

        res = sum(array.array("H", packet))
        res = (res >> 16) + (res & 0xffff)
        res += res >> 16

        return (~res) & 0xffff

    def get_udp_packet(self) -> bytes:
        return self.__header.build_header(checksum=self.checksum()) + self.get_encapsulated_data()

    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__header.offset)

    def get_proto_info(self) -> str:
        result = str(self.__parent)
        result += str(self.__header)
        return result

    def get_json_proto_header(self):
        pass
