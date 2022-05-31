# -*- coding: utf-8 -*-

import asyncio

import aiorpcx


class SimpleDeferredMock:

    def __init__(self):
        self.cb = None
        self.errb = None

    def addCallback(self, cb):
        self.cb = cb

    def addErrback(self, errb):
        self.errb = errb

    def addCallbacks(self, cb, errb):
        self.cb = cb
        self.errb = errb


class TorClientService:

    def __init__(self, factory, timeout, socks5_host, socks5_port, host, port):
        self.factory = factory
        self.logger = factory.logger
        self.timeout = timeout
        self.proxy = aiorpcx.SOCKSProxy(
            f'{socks5_host}:{socks5_port}', aiorpcx.SOCKS5, None)
        self.host = host
        self.port = port
        self.fail_after_failures = 1
        self.transport = None
        self.protocol = None
        self.connected_deferred = None
        self.stop_deferred = None
        self.srv_task = None
        self.stop_task = None

    def whenConnected(self, failAfterFailures=None):
        if failAfterFailures:
            self.fail_after_failures = failAfterFailures
        self.connected_deferred = SimpleDeferredMock()
        return self.connected_deferred

    async def _create_connection(self):
        if self.stop_task and not self.stop_task.done():
            await self.stop_task
        self.stop_task = None

        fail_count = 0
        proxy = self.proxy
        timeout = self.timeout

        async def proxy_create_conn():
            self.transport, self.protocol = await proxy.create_connection(
                self.factory.buildProtocol, self.host, self.port)

        while fail_count < self.fail_after_failures:
            try:
                await asyncio.wait_for(proxy_create_conn(), timeout=timeout)
                if self.connected_deferred and self.connected_deferred.cb:
                    self.connected_deferred.cb(self.protocol)
                break
            except BaseException as e:
                self.logger.error(f'create_connection: {repr(e)}')
                fail_count += 1
                if fail_count < self.fail_after_failures:
                    continue
                if self.connected_deferred and self.connected_deferred.errb:
                    self.connected_deferred.errb(e)

    def startService(self):
        self.srv_task = asyncio.create_task(self._create_connection())

    async def _stop_service(self):
        if self.srv_task and not self.srv_task.done():
            self.srv_task.cancel()
        self.srv_task = None

        if self.transport:
            self.transport.close()
        self.transport = None
        self.protocol = None
        if self.stop_deferred and self.stop_deferred.cb:
            self.stop_deferred.cb(None)

    def stopService(self):
        self.stop_deferred = SimpleDeferredMock()
        self.stop_task = asyncio.create_task(self._stop_service())
        return self.stop_deferred
