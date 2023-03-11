from .ethernet import EthernetFrame
from .protocol import ProtocolType as pt
from .ip import IPPacket


class NetworkFilter:
    def __init__(self, params: dict):
        self.params = {param: params.get(param) for param in params if params.get(param) is not None}

    def filtrate(self, ethernet: EthernetFrame) -> bool:
        net_level_proto = ethernet.header.encapsulated_proto
        if self.params.get('ARP') is None and net_level_proto == pt.ARP.value:
            return False
        elif net_level_proto == pt.IP.value:
            target_ip = self.params.get('target_ip')
            ip_packet = IPPacket(ethernet.get_encapsulated_data(), ethernet.header)
            if ip_packet.destination_address == target_ip:
                return True
            else:
                return False


