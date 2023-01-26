import socket

from art import tprint

from Sniffer.ethernet import EthernetFrame

if __name__ == '__main__':
    tprint('Packet Sniffer')
    eth_frame = EthernetFrame(b'test')
    print(eth_frame)
    