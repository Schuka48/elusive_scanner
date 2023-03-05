import socket

# from art import tprint

# # from . import protocol
from .ethernet import EthernetFrame
from .ip import IPPacket
from .tcp import TCPPacket


# def filtrate_eth_frame(frame: EthernetFrame) -> bool:
#     if frame.src_mac == '00:00:00:00:00:00' and frame.dst_mac == '00:00:00:00:00:00':
#         return False
#     else:
#         return True


def start_sniffer():
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data = sniffer.recvfrom(65535)[0]
        ethernet = EthernetFrame(raw_data)
        if ethernet.encapsulated_proto == 8:
            ip_packet = IPPacket(ethernet.get_encapsulated_data(), ethernet.header)
            if ip_packet.protocol == 6:
                tcp_packet = TCPPacket(ip_packet.get_encapsulated_data(), ip_packet.header)
                # if tcp_packet.parent.source_address == '192.168.148.129' or tcp_packet.parent.source_address == '192.168.148.1':
                print(tcp_packet)
                print(ip_packet.get_encapsulated_data())
                print(tcp_packet.header.get_raw_header())
                print('-' * 30)



if __name__ == '__main__':
    # tprint('My Sniffer')
    start_sniffer()
