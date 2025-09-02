import pytest
import asyncio
import itertools
import mlsip  # substituindo aiosip

# pytest_plugins = ['mlsip.pytest_plugin']  # caso você crie um plugin equivalente

class TestServer:
    def __init__(self, app, *, loop=None, host='127.0.0.1'):
        self.loop = loop
        self.host = host
        self.app = app
        self._loop = loop

    async def start_server(self, protocol, **kwargs):
        self.handler = await self.app.run(
            protocol=protocol,
            local_addr=(self.sip_config['server_host'], self.sip_config['server_port'])
        )
        return self.handler

    async def close(self):
        pass

    @property
    def sip_config(self):
        return {
            'client_host': self.host,
            'client_port': 7000,
            'server_host': self.host,
            'server_port': 6000,
            'user': 'pytest',
            'realm': 'example.com'
        }


class TestProxy(TestServer):
    @property
    def sip_config(self):
        return {
            'server_host': self.host,
            'server_port': 8000,
        }


@pytest.fixture(params=['udp', 'tcp'])
def protocol(request):
    if request.param == 'udp':
        return mlsip.UDP
    elif request.param == 'tcp':
        return mlsip.TCP
    pytest.fail(f'Test requested unknown protocol: {request.param}')


@pytest.fixture
async def test_server(protocol, event_loop):
    servers = []

    async def go(handler, **kwargs):
        server = TestServer(handler)
        await server.start_server(protocol, **kwargs)
        servers.append(server)
        return server

    yield go

    for server in servers:
        await server.close()


@pytest.fixture
async def test_proxy(protocol, event_loop):
    servers = []

    async def go(handler, **kwargs):
        server = TestProxy(handler)
        await server.start_server(protocol, **kwargs)
        servers.append(server)
        return server

    yield go

    for server in servers:
        await server.close()


@pytest.fixture
def from_details():
    return 'sip:{user}@{host}:{port}'.format(
        user='pytest',
        host='127.0.0.1',
        port=7000
    )


@pytest.fixture
def to_details():
    return 'sip:{user}@{host}:{port}'.format(
        user='666',
        host='127.0.0.1',
        port=6000
    )


@pytest.fixture(params=itertools.permutations(('client', 'server')))
def close_order(request):
    return request.param
