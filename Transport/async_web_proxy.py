import aiohttp
import asyncio
import base64
import gzip
from aiohttp import web
from typing import NamedTuple, AnyStr, List, Callable


class PostParams(NamedTuple):
    raw_packet: bytes
    script_code: bytes
    packet_route: str


async def parse_request_data(request: aiohttp.web.Request) -> PostParams:
    post_params = await request.post()
    if 'raw_packet' in post_params and 'script' in post_params and 'packet_route' in post_params:
        return PostParams(
            base64.b64decode(post_params['raw_packet'].encode('utf-8')),
            post_params['script'],
            post_params['packet_route']
        )
    else:
        raise EnvironmentError('Error while parsing POST params')


async def handle_post_request(request: aiohttp.web.Request) -> aiohttp.web.Response:
    try:
        post_params = await parse_request_data(request)
        exec(
            post_params.script_code,
            {'raw_packet': post_params.raw_packet, 'packet_route': post_params.packet_route, 'Callable': Callable}
        )
        print('Success execute')
        return web.Response(text='200 OK')
    except EnvironmentError as ex:
        print(ex)
        return web.Response(status=400, text='Missing script parameter')


async def run_server():
    app = aiohttp.web.Application()
    app.router.add_post('/', handle_post_request)

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()

    site = aiohttp.web.TCPSite(runner, '0.0.0.0', 8000)
    await site.start()

    print('Starting server on port 8000...')
    while True:
        await asyncio.sleep(3600)


loop = asyncio.get_event_loop()
loop.run_until_complete(run_server())
