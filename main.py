import sys

from art import tprint

import Exceptions.exception as Exs
import sniffer as sniffer
from argument_parser import get_args


def parse_args():
    args = None
    try:
        args = get_args()
        return args
    except Exs.ArgParseError as exception:
        print('[-] ' + str(exception))
        print('[-] Rerun the application with the required parameters.')
        sys.exit(1)


def main():
    args = parse_args()

    print('[*] Starting the sniffer...')

    try:
        sniffer.start_sniffer(args)
    except Exs.StopSniffer:
        print('[*] Stopped the sniffer')


if __name__ == '__main__':
    print('[+] Starting Program ...')
    tprint('Elusive Scanner')
    main()
