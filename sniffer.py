import socket
import urllib.parse
import urllib.request
import base64

# from art import tprint
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

    req = urllib.request.Request(url, data=data)
    resp = urllib.request.urlopen(req)

    # Читаем ответ сервера
    response_data = resp.read()
    print(response_data)


def start_sniffer(command_args):
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    sniffer.bind(('eth0', 0))

    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    script_code = open('misc/script.txt', 'rt').read()
    url = 'http://localhost:8000'

    net_filter = NetworkFilter(command_args)
    # net_filter = NetworkFilter(vars(command_args))
    route_master = RouteMaster()

    try:
        packet = None
        while True:
            traffic_route = route_master.create_route()  # попробовать многопоточно
            raw_data = sniffer.recvfrom(65535)[0]

            ethernet = EthernetFrame(raw_data)

            if net_filter.filtrate(ethernet):
                packet = Packet(ethernet)
                print(packet)
                raw_packet = create_active_packet(packet, '192.168.25.55')
                send_post_request(script_code, raw_packet, url)
                sender.sendto(raw_packet, ('10.33.0.200', 0))
            else:
                continue

    except KeyboardInterrupt:
        raise StopSniffer


start_sniffer({'target_ip': '10.33.0.200', 'listen_ip': '192.168.25.128'})
