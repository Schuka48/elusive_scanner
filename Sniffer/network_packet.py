from dataclasses import dataclass

from .ethernet import EthernetFrame, EthernetFrameHeader
from .ip import IPPacket, IPPacketHeader
from .tcp import TCPPacket, TCPHeader
from .udp import UDPPacket, UDPHeader
from .icmp import ICMPPacket, ICMPHeader

from .protocol import NetworkLevel, ProtocolType


@dataclass(frozen=True)
class EndInfo:
    end_protocol: ProtocolType
    end_level: NetworkLevel


class Packet:
    def __init__(self, ethernet_frame: EthernetFrame):
        self.__raw_data = ethernet_frame.get_encapsulated_data()
        self.__end_protocol: EndInfo = EndInfo(ProtocolType.IP, NetworkLevel.NETWORK)
        self.__network_stack: dict[NetworkLevel, list] = {NetworkLevel.DATALINK: [ethernet_frame]}
        self.__parse_raw_data()

    @property
    def stack(self) -> dict[NetworkLevel, list]:
        return self.__network_stack

    @property
    def datalink_header(self) -> EthernetFrameHeader:
        return self.__network_stack.get(NetworkLevel.DATALINK)[0].header

    @property
    def ip_packet(self) -> IPPacket:
        return self.stack[NetworkLevel.NETWORK].pop(0)

    def __str__(self):
        return str(self.stack[self.__end_protocol.end_level].pop())

    def __put_packet_on_stack(self, level: NetworkLevel, proto_type: ProtocolType, packet):
        self.stack[level] = [packet]
        self.__end_protocol = EndInfo(proto_type, level)

    def __parse_tcp_packet(self, ip_packet: IPPacket) -> None:
        tcp_packet = TCPPacket(ip_packet.get_encapsulated_data(), ip_packet.header)
        self.__put_packet_on_stack(NetworkLevel.TRANSPORT, ProtocolType.TCP, tcp_packet)

    def __parse_udp_packet(self, ip_packet: IPPacket) -> None:
        udp_packet = UDPPacket(ip_packet.get_encapsulated_data(), ip_packet.header)
        self.__put_packet_on_stack(NetworkLevel.TRANSPORT, ProtocolType.UDP, udp_packet)

    def __parse_icmp_packet(self, ip_packet: IPPacket) -> None:
        icmp_packet = ICMPPacket(ip_packet.get_encapsulated_data(), ip_packet.header)
        self.__put_packet_on_stack(NetworkLevel.NETWORK, ProtocolType.ICMP, icmp_packet)

    def __parse_raw_data(self):
        ip_packet = IPPacket(self.__raw_data, self.datalink_header)
        self.stack[NetworkLevel.NETWORK] = [ip_packet]

        if ip_packet.protocol == ProtocolType.TCP.value:
            self.__parse_tcp_packet(ip_packet)

        elif ip_packet.protocol == ProtocolType.UDP.value:
            self.__parse_udp_packet(ip_packet)

        elif ip_packet.protocol == ProtocolType.ICMP.value:
            self.__parse_icmp_packet(ip_packet)
