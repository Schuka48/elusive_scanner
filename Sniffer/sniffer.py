import socket

# from art import tprint

from .ethernet import EthernetFrame
from .network_packet import Packet
from .filter import NetworkFilter


def start_sniffer(filter_params: dict):
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    net_filter = NetworkFilter(filter_params)
    while True:
        raw_data = sniffer.recvfrom(65535)[0]
        ethernet = EthernetFrame(raw_data)
        if net_filter.filtrate(ethernet):
            packet = Packet(ethernet)
            print(packet)
