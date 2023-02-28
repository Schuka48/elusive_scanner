import socket

from art import tprint

# # from . import protocol
from .ethernet import EthernetFrame
from .ip import IPPacket
from .tcp import TCPProtocol


def filtrate_eth_frame(frame: EthernetFrame) -> bool:
    if frame.src_mac == '00:00:00:00:00:00' and frame.dst_mac == '00:00:00:00:00:00':
        return False
    else:
        return True


def start_sniffer():
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data = sniffer.recvfrom(65535)[0]
        ethernet = EthernetFrame(raw_data)
        if filtrate_eth_frame(ethernet):
            if ethernet.encapsulated_proto == 8:

                ip = IPPacket(ethernet.get_encapsulated_data())
                ip.set_parent(ethernet.header)
                if ip.protocol == 6:
                    tcp = TCPProtocol(ip.get_encapsulated_data())
        else:
            continue


if __name__ == '__main__':
    tprint('My Sniffer')
    start_sniffer()
