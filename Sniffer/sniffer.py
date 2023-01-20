from art import tprint
from . import protocol


def start_sniffer():
    eth_frame = protocol.Ethernet(b'test')


if __name__ == '__main__':
    tprint('My Sniffer')
    start_sniffer()
