import socket

# from art import tprint

# # from . import protocol
from .ethernet import EthernetFrame
from .ip import IPPacket
from .tcp import TCPPacket
from .udp import UDPPacket
from .network_packet import Packet


def start_sniffer():
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data = sniffer.recvfrom(65535)[0]
        ethernet = EthernetFrame(raw_data)
        if ethernet.encapsulated_proto == 8:
            np = Packet(ethernet)
            if np.ip_packet.source_address == '10.33.0.200' or np.ip_packet.destination_address == '10.33.0.200':
                print(np)

