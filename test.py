# import urllib.request
# from typing import List
# import asyncio
# import socket
# import urllib.parse
# import urllib.request
# import urllib.error
# import base64
# import gzip
# import threading
#
# import aiohttp
# from art import tprint
# from Exceptions.exception import StopSniffer
# from Sniffer.ethernet import EthernetFrame
# from Sniffer.network_packet import Packet, create_active_packet
# from Sniffer.filter import NetworkFilter
# from Transport.route_master import RouteMaster
#
#
# async def send_post_request(script_code: str, raw_packet: bytes, url: str) -> None:
#     encoded_packet = base64.b64encode(raw_packet).decode()
#
#     data = aiohttp.FormData()
#     data.add_field('script', script_code)
#     data.add_field('raw_packet', encoded_packet)
#     data.add_field('packet_route', '192.168.25.128')
#
#     print(f"Sending POST request to {url} with data: {data}")
#
#     async with aiohttp.ClientSession() as session:
#         async with session.post(url, data=data) as resp:
#             response_data = await resp.read()
#             print(response_data)
#
#
# async def sniff_packets(command_args, script_code: str, url: str) -> None:
#     sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
#     sniffer.bind(('eth1', 0))
#
#     net_filter = NetworkFilter(command_args)
#     loop = asyncio.get_running_loop()
#
#     try:
#         while True:
#             raw_data = await loop.sock_recv(sniffer, 65535)
#
#             # raw_data = sniffer.recvfrom(65535)[0]
#
#             ethernet = EthernetFrame(raw_data)
#
#             if net_filter.filtrate(ethernet):
#                 packet = Packet(ethernet)
#                 print(packet)
#                 raw_packet = create_active_packet(packet, '192.168.25.128')
#                 try:
#                     task = asyncio.create_task(send_post_request(script_code, raw_packet, url))
#                 except urllib.error.URLError:
#                     pass
#             else:
#                 continue
#
#     except KeyboardInterrupt:
#         raise StopSniffer
#
#
# async def start_sniffer(command_args, script_path: str, url: str) -> None:
#     script_code = open(script_path, 'rt').read()
#     await sniff_packets(command_args, script_code, url)
#
# if __name__ == '__main__':
#     asyncio.run(start_sniffer(
#         {'target_ip': '192.168.25.1', 'listen_ip': '192.168.148.5'},
#         'misc/script.py',
#         'http://localhost:8000')
#     )


from Transport.route_master import RouteMaster, Route

command_args = {
        'target_ip': '192.168.25.1',
        'listen_ip': '192.168.148.5',
        'route_len': 1
    }

route_master = RouteMaster(command_args.get('route_len'))
route: Route = route_master.create_route()
print(route.get_destination())


