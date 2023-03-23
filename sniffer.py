import socket
import urllib.parse
import urllib.request
import urllib.error
import base64
import gzip
from threading import Thread

import requests
from art import tprint
from Exceptions.exception import StopSniffer
from Sniffer.ethernet import EthernetFrame
from Sniffer.network_packet import Packet, create_active_packet
from Sniffer.filter import NetworkFilter
from Transport.route_master import RouteMaster, Route


def send_post_request(script_code: str, raw_packet: bytes, url: str, route: Route):
    encoded_packet = base64.b64encode(raw_packet).decode()

    data = urllib.parse.urlencode({
        "script": base64.b64encode(gzip.compress(script_code.encode())).decode(),
        "raw_packet": encoded_packet,
        "packet_route": route.route,
        "target": route.destination
    }).encode()

    req = urllib.request.Request(url, data=data)

    try:
        resp = urllib.request.urlopen(req, timeout=1)
    except TimeoutError:
        print('Error request')


def handle_raw_data(raw_data: bytes, script_code: str, *, route: Route, net_filter: NetworkFilter):
    ethernet = EthernetFrame(raw_data)

    if net_filter.filtrate(ethernet):
        packet = Packet(ethernet)
        print(packet)
        last_node = route.last_node

        raw_packet = create_active_packet(packet, last_node)
        try:
            send_post_request(script_code, raw_packet, f'http://{last_node}:8000', route)
        except urllib.error.URLError:
            pass
    else:
        pass


def start_sniffer(command_args):
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sniffer.bind(('eth1', 0))

    script_code = open('misc/script.py', 'rt').read()

    net_filter = NetworkFilter(command_args)
    # net_filter = NetworkFilter(vars(command_args))
    route_master = RouteMaster(command_args.get('route_len'))

    stop_flag = False

    try:
        while not stop_flag:
            traffic_route: Route = route_master.create_route(1)  # попробовать многопоточно
            raw_data = sniffer.recvfrom(1024)[0]
            traffic_route.set_destination(command_args.get('target_ip'))
            handle_raw_data(raw_data, script_code, route=traffic_route, net_filter=net_filter)

    except KeyboardInterrupt:
        raise StopSniffer


if __name__ == '__main__':
    target_ip = '192.168.25.1'
    listen_ip = '192.168.148.5'
    try:
        start_sniffer({
            'target_ip': target_ip,
            'listen_ip': listen_ip,
            'route_len': 1
        })
    except StopSniffer:
        print('Exit')
