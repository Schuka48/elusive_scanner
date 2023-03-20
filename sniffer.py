import socket
import urllib.parse
import urllib.request
import base64
import struct
from enum import Enum
from typing import Callable

from art import tprint
from Exceptions.exception import StopSniffer
from Sniffer.ethernet import EthernetFrame
from Sniffer.network_packet import Packet, create_active_packet
from Sniffer.filter import NetworkFilter
from Transport.route_master import RouteMaster


def send_post_request(script_code: str, raw_packet: bytes, url: str):
    encoded_packet = base64.b64encode(raw_packet).decode()

    data = urllib.parse.urlencode({
        "script": script_code,
        "raw_packet": encoded_packet
    }).encode()
    # Читаем ответ сервера
    req = urllib.request.Request(url, data=data)
    resp = urllib.request.urlopen(req)
    response_data = resp.read()
    print(response_data)


def start_sniffer(command_args):
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sniffer.bind(('eth1', 0))
    url = 'http://localhost:8000'

    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    script_code = open('misc/script.txt', 'rt').read()

    net_filter = NetworkFilter(command_args)
    # net_filter = NetworkFilter(vars(command_args))
    # route_master = RouteMaster()

    try:
        packet = None
        while True:
            # traffic_route = route_master.create_route(4)  # попробовать многопоточно
            raw_data = sniffer.recvfrom(65535)[0]

            ethernet = EthernetFrame(raw_data)

            if net_filter.filtrate(ethernet):
                packet = Packet(ethernet)
                print(packet)
                raw_packet = create_active_packet(packet, '192.168.25.128')
                # send_post_request(script_code, raw_packet, url)
                sender.sendto(raw_packet, ('192.168.25.1', 0))
            else:
                continue

    except KeyboardInterrupt:
        raise StopSniffer


start_sniffer({'target_ip': '192.168.25.1', 'listen_ip': '192.168.148.5'})
