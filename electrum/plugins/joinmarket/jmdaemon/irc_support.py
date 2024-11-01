# -*- coding: utf-8 -*-

import asyncio
import ssl

import aiorpcx


class IRCClientService:

    def __init__(self, factory, *, host, port, loop, usessl=False,
                 socks5=False, socks5_host=None, socks5_port=None):
        self.factory = factory
        self.logger = factory.logger
        self.host = host
        self.port = port
        self.loop = loop
        self.usessl = usessl
        self.socks5 = socks5
        self.proxy = (aiorpcx.SOCKSProxy(f'{socks5_host}:{socks5_port}',
                                         aiorpcx.SOCKS5,
                                         None)
                      if socks5_host and socks5_port
                      else None)
        self.transport = None
        self.protocol = None
        self.srv_task = None
        self.stop_task = None

    async def _create_conn(self, sslc):
        self.transport, self.protocol = await self.loop.create_connection(
            self.factory.buildProtocol, self.host, self.port,
            ssl=sslc)

    async def _proxy_create_conn(self, sslc):
        self.transport, self.protocol = await self.proxy.create_connection(
            self.factory.buildProtocol, self.host, self.port,
            ssl=sslc)

    async def _start_service(self, wait_sec):
        if self.stop_task and not self.stop_task.done():
            await self.stop_task
        self.stop_task = None
        await asyncio.sleep(wait_sec)
        try:
            sslc = None
            if self.usessl:
                sslc = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
                sslc.check_hostname = False
                sslc.verify_mode = ssl.CERT_NONE
            if self.socks5:
                await asyncio.wait_for(self._proxy_create_conn(sslc),
                                       timeout=60)
            else:
                await asyncio.wait_for(self._create_conn(sslc), timeout=30)
        except BaseException as e:
            self.logger.error(f'_start_service: {repr(e)}')
            self.factory.clientConnectionFailed(str(e))

    def startService(self):
        wait_sec = 5 if self.stop_task else 0
        self.srv_task = asyncio.create_task(self._start_service(wait_sec))

    async def _stop_service(self):
        try:
            if self.srv_task and not self.srv_task.done():
                self.srv_task.cancel()
            self.srv_task = None

            if self.transport:
                self.transport.close()
            self.transport = None
            self.protocol = None
        except BaseException as e:
            self.logger.error(f'_stop_service: {repr(e)}')

    def stopService(self):
        self.stop_task = asyncio.create_task(self._stop_service())
