from .ethernet import EthernetFrame
from .protocol import ProtocolType as pt
from .ip import IPPacket
from .tcp import TCPPacket


def _check_only_rst_tcp_packet(tcp_packet: TCPPacket):
    packet_flags = tcp_packet.flags
    rst_flag = packet_flags.get('RST')
    other_flags = [flag for flag_name, flag in packet_flags.items() if flag_name != 'RST']
    if rst_flag != 0:
        if any(other_flags):
            return False
        else:
            return True
    else:
        return False


class NetworkFilter:
    def __init__(self, params: dict):
        self.params = {param: params.get(param) for param in params if params.get(param) is not None}

    def filtrate(self, ethernet: EthernetFrame) -> bool:
        net_level_proto = ethernet.header.encapsulated_proto
        if self.params.get('ARP') is None and net_level_proto == pt.ARP.value:
            return False
        elif net_level_proto == pt.IP.value:
            if self.params.get('is_router') is None or self.params.get('is_router') is False:
                destination_ip = self.params.get('target_ip')
                source_ip = self.params.get('listen_ip')
            else:
                destination_ip = self.params.get('listen_ip')
                source_ip = self.params.get('target_ip')

            ip_packet = IPPacket(ethernet.get_encapsulated_data(), ethernet.header)
            if ip_packet.destination_address == destination_ip and ip_packet.source_address == source_ip:
                if ip_packet.protocol == pt.TCP.value:
                    if _check_only_rst_tcp_packet(TCPPacket(ip_packet.get_encapsulated_data(), ip_packet.header)):
                        return False
                return True
            else:
                # TODO: Сделать фильтр интеллектуальнее
                return False


