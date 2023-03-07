import socket

# from art import tprint
from Sniffer.sniffer import start_sniffer
from Sniffer import network_packet as np


def test(lst):
    print(id(lst))
    print(id(lst[0]))
    pass


if __name__ == '__main__':
    # tprint('Packet Sniffer')

    start_sniffer()
