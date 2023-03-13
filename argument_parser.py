import argparse

import Exceptions.exception as Exs


def add_args(parser: argparse.ArgumentParser) -> None:

    parser.add_argument('--ti', '--targetip', dest='target_ip',
                        help='IP address of the scanned target')

    parser.add_argument('--li', '--listenip', dest='listen_ip',
                        help='IP address for listen to connections')

    parser.add_argument('--sf', '--script_file', dest='script_file',
                        help="Path to the script file, that's generate active data")

    parser.add_argument('--is-router', action='store_true', dest='is_router',
                        help='Set this flag if the device is a node in transport network')


def check_args(args: argparse.Namespace) -> bool:
    if args.target_ip is None:
        raise Exs.ArgParseError('Target ip address is missing')
    elif args.listen_ip is None:
        raise Exs.NoListenIp()
    elif args.listen_port is None:
        raise Exs.NoListenPort
    else:
        return True


def get_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='This application is designed ' +
                                                 'to configure a distributed ' +
                                                 'scanning system.')
    add_args(parser)
    parser.print_help()
    args = parser.parse_args()
    # if check_args(args):

    return args
    # else:
        # raise Exs.ArgParseError('Some problem with module argparse.')
