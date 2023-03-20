import gzip
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
import base64
from typing import NamedTuple
from typing import Callable, AnyStr


class PostParams(NamedTuple):
    raw_packet: bytes
    script_code: str
    packet_route: str


def _get_post_param(post_params: dict[AnyStr, list[AnyStr]], param_name: str):
    return post_params[param_name][0]


class MyHTTPRequestHandler(BaseHTTPRequestHandler):
    def _get_post_params(self) -> dict[AnyStr, list[AnyStr]]:
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()
        post_params = parse_qs(post_data)
        return post_params

    def parse_request_data(self) -> PostParams:
        post_params = self._get_post_params()
        if 'raw_packet' in post_params and 'script' in post_params and 'packet_route' in post_params:
            return PostParams(
                base64.b64decode(_get_post_param(post_params, 'raw_packet')),
                _get_post_param(post_params, 'script'),
                _get_post_param(post_params, 'packet_route')
            )
        else:
            raise EnvironmentError('Error while parsing POST params')

    def do_POST(self):
        try:
            post_params = self.parse_request_data()
            exec(
                post_params.script_code,
                {'raw_packet': post_params.raw_packet, 'packet_route': post_params.packet_route, 'Callable': Callable}
            )
            print('Success execute')
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f'200 Ok'.encode('utf-8'))
        except EnvironmentError as ex:
            print(ex)
            self.send_error(400, 'Missing script parameter')


def run():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, MyHTTPRequestHandler)
    print('Starting server on port 8000...')
    httpd.serve_forever()


if __name__ == '__main__':
    run()
