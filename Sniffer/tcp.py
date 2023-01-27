import struct

import Exceptions.exception as Exs

from .protocol import NetworkLevel, NetworkProtocol

class TCPProtocol(NetworkProtocol):
    def __init__(self, raw_data: bytes):
        NetworkProtocol.__init__(self, raw_data)
        self.__level: NetworkLevel = NetworkLevel.TRANSPORT
        self.__parse_data()

    def __parse_data(self) -> None:
        if self.data_length:
            try:
                header = struct.unpack('!HHIIHHH', self.raw_data)
            except struct.error:
                raise Exs.TCPPacketParseError('Incorrect TCP packet format')
        else:
            raise Exs.TCPPacketParseError('No {self.__class__.__name__} header')

        self.__src_port = header[0]
        self.__dst_port = header[1]
        self.__sequence = header[2]
        self.__acknowledgment = header[3]
        self.__offset_reserved_flags = header[4]
        self.__offset = (self.__offset_reserved_flags >> 12) * 4
        self.__reserved = (self.__offset_reserved_flags >> 8) & 15
        # flags = ['URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']
        # self.__flags = {flag: ((self.__offset_reserved_flags & (2 ** (5 - i))) >> (5 - i)) for i, flag in enumerate(reversed(flags))}
        flag_urg = (self.__offset_reserved_flags & 32) >> 5
        flag_ack = (self.__offset_reserved_flags & 16) >> 4
        flag_psh = (self.__offset_reserved_flags & 8) >> 3
        flag_rst = (self.__offset_reserved_flags & 4) >> 2
        flag_syn = (self.__offset_reserved_flags & 2) >> 1
        flag_fin = self.__offset_reserved_flags & 1
        self.__flags = {
            'URG': flag_urg,
            'ACK': flag_ack,
            'PSH': flag_psh,
            'RST': flag_rst,
            'SYN': flag_syn,
            'FIN': flag_fin
        }
        self.__window_size = header[5]
        self.__check_sum = header[6]
        self.__urgent_pointer = header[7]

    def get_encapsulated_data(self) -> bytes:
        return NetworkProtocol.get_data(self, self.__offset)
    
    def get_proto_info(self) -> str:
        return '' # TODO: realize function, that return pretty view about network protocol
        