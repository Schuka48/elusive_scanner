import sys

from art import tprint
from argument_parser import get_args
import Exceptions.exception as Exs
import Sniffer.sniffer


def main():
    try:
        args = get_args()
    except Exs.ArgParseError as exception:
        print('[-] ' + str(exception))
        print('[-] Rerun the application with the required parameters.')
        sys.exit(1)


if __name__ == '__main__':
    print('[+] Starting Program ...')
    tprint('Elusive Scanner')
    main()
