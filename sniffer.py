import socket

# from art import tprint
from Exceptions.exception import StopSniffer
from Sniffer.ethernet import EthernetFrame
from Sniffer.network_packet import Packet, create_active_packet
from Sniffer.filter import NetworkFilter
from Transport.route_master import RouteMaster


def start_sniffer(command_args):
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    net_filter = NetworkFilter(vars(command_args))
    route_master = RouteMaster()

    try:
        while True:
            traffic_route = route_master.create_route()  # попробовать многопоточно
            raw_data = sniffer.recvfrom(65535)[0]
            ethernet = EthernetFrame(raw_data)
            packet = None
            if net_filter.filtrate(ethernet):
                packet = Packet(ethernet)
                print(packet)
            else:
                continue
            packet = create_active_packet(packet)
            # active_data = compile_active_data(packet, command_args.script_file)
            # send_active_data(active_data, traffic_route)

    except KeyboardInterrupt:
        raise StopSniffer


start_sniffer({'target_ip': '192.168.148.1', 'listen_ip': '192.168.148.129'})
