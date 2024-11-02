# -*- coding: utf-8 -*-

import asyncio
import io

from electrum.plugins.joinmarket.jmdaemon import (
    OnionMessageChannel, MessageChannelCollection)
from electrum.plugins.joinmarket.jmdaemon.onionmc import OnionPeer
from electrum.plugins.joinmarket.jmdaemon.onionmc_support import (
    TorClientService)

from electrum.plugins.joinmarket.tests import JMTestCase


class DummyTransport(asyncio.Transport):

    def __init__(self, logger):
        super().__init__()
        self._t = io.BytesIO(b'')
        self.logger = logger

    def write(self, data):
        self.logger.debug(f'DummyTransport.write: {data}')
        self._t.write(data)

    def close(self):
        self._t.close()


class DummyTorClientService(TorClientService):

    async def _proxy_create_conn(self):
        self.logger.debug(f'_proxy_create_conn: {self.factory.buildProtocol}, '
                          f'{self.host}:{self.port}')
        self.transport = DummyTransport(self.logger)
        self.protocol = self.factory.buildProtocol()
        self.protocol.connection_made(self.transport)


class DummyMC(OnionMessageChannel):

    def __init__(self, jmman, configdata, nick):
        super().__init__(jmman, configdata,
                         client_service_cls=DummyTorClientService)
        self.set_nick(nick)


class OnionBaseTestCase(JMTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        jmman = self.jmman
        jmconf = jmman.jmconf
        jmconf.maker_timeout_sec = 1
        configdata = list(jmconf.get_msg_channels().values())[2]
        directory_node = configdata['directory_nodes'].split(',')[0]
        configdata['directory_nodes'] = directory_node
        self.mc = DummyMC(jmman, configdata, 'onionnick')
        self.mcc = MessageChannelCollection([self.mc], jmman)
        await self.mcc.run()

    async def asyncTearDown(self):

        async def cb(m):
            # don't try to reconnect
            m.give_up = True
            await m.shutdown()

        await cb(self.mc)

    async def test_setup(self):
        assert 0
