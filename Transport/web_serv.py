from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import socket
import struct
from enum import Enum
from typing import Callable
from Exceptions.exception import NetworkParseError
import base64


class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()
        post_params = parse_qs(post_data)
        if 'raw_packet' in post_params and 'script' in post_params:
            raw_packet = post_params['raw_packet'][0]
            raw_packet = base64.b64decode(raw_packet)
            script = post_params['script'][0]
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f'200 Ok'.encode('utf-8'))

            exec(script, globals())

        else:
            self.send_error(400, 'Missing script parameter')


def run():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, MyHTTPRequestHandler)
    print('Starting server on port 8000...')
    httpd.serve_forever()


if __name__ == '__main__':
    run()
