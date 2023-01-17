from art import tprint
import protocol


def start_sniffer():
    proto = protocol.NetworkProtocol('test')
    print(proto)


if __name__ == '__main__':
    tprint('My Sniffer')
    start_sniffer()
