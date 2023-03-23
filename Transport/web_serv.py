import gzip
import base64
import socketserver
from typing import NamedTuple
from typing import Callable, AnyStr
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs


class PostParams(NamedTuple):
    raw_packet: bytes
    script_code: str
    packet_route: str
    target: str


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
        try:
            script_b64 = _get_post_param(post_params, 'script')
            script_gz = base64.b64decode(script_b64.encode())
            script_code = gzip.decompress(script_gz).decode()
            return PostParams(
                base64.b64decode(_get_post_param(post_params, 'raw_packet')),
                script_code,
                _get_post_param(post_params, 'packet_route'),
                _get_post_param(post_params, 'target')
            )
        except:
            raise EnvironmentError('Error while parsing POST params')

    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        try:
            post_params = self.parse_request_data()
            exec(
                post_params.script_code,
                {
                    'raw_packet': post_params.raw_packet,
                    'packet_route': post_params.packet_route,
                    'script_code': post_params.script_code,
                    'target': post_params.target,
                    'Callable': Callable
                }
            )
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
