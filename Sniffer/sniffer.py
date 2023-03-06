import socket

# from art import tprint

# # from . import protocol
from .ethernet import EthernetFrame
from .ip import IPPacket
from .tcp import TCPPacket
from .udp import UDPPacket


def start_sniffer():
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data = sniffer.recvfrom(65535)[0]
        ethernet = EthernetFrame(raw_data)
        if ethernet.encapsulated_proto == 8:
            ip_packet = IPPacket(ethernet.get_encapsulated_data(), ethernet.header)
            if ip_packet.protocol == 6:
                tcp_packet = TCPPacket(ip_packet.get_encapsulated_data(), ip_packet.header)
                if tcp_packet.parent.source_address == '10.33.0.200' or tcp_packet.parent.destination_address == '10.33.0.200':
                    print(tcp_packet)
                    print(ip_packet.get_encapsulated_data())
                    print(tcp_packet.get_tcp_packet())
                    print('-' * 30)
            elif ip_packet.protocol == 17:
                udp_packet = UDPPacket(ip_packet.get_encapsulated_data(), ip_packet.header)
                if udp_packet.parent.source_address == '10.33.0.200' or udp_packet.parent.destination_address == '10.33.0.200':
                    print(udp_packet)
                    print(ip_packet.get_encapsulated_data())
                    print(udp_packet.get_udp_packet())
                    print(UDPPacket(udp_packet.get_udp_packet()).header.checksum)
                    print('-' * 30)


if __name__ == '__main__':
    # tprint('My Sniffer')
    start_sniffer()
