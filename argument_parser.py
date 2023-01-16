import argparse
import Exceptions.exception as Exs


def add_args(parser):

    parser.add_argument('--ti', '--targetip', dest='target_ip',
                        help='IP address of the scanned target')

    parser.add_argument('--li', '--listenip', dest='listen_ip',
                        help='IP address for listen to connections')

    parser.add_argument('--lp', '--listenport', dest='listen_port',
                        help='Port to listen for connections')


def check_args(args):
    if args.target_ip is None:
        raise Exs.ArgParseError('Target ip address is missing')
    elif args.listen_ip is None:
        raise Exs.NoListenIp()
    elif args.listen_port is None:
        raise Exs.NoListenPort
    else:
        return True


def get_args():
    parser = argparse.ArgumentParser(description='This application is designed ' +
                                                 'to configure a distributed ' +
                                                 'scanning system.')

    add_args(parser)
    parser.print_help()
    args = parser.parse_args()
    if check_args(args):
        return args
