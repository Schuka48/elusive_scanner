# from art import tprint
from sniffer import start_sniffer


def test(lst):
    print(id(lst))
    print(id(lst[0]))
    pass


if __name__ == '__main__':
    # tprint('Packet Sniffer')

    start_sniffer()
