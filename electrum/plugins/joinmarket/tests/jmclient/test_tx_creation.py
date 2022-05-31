# -*- coding: utf-8 -*-

from electrum.plugins.joinmarket.jmclient import direct_send

from electrum.plugins.joinmarket.tests import JMTestCase


class TxCreationTestCase(JMTestCase):

    async def test_direct_send(self):
        jmman = self.jmman
        jmw = jmman.jmw
        destn = jmw.get_internal_addr(1)

        def info_cb(msg, txinfo):
            self.fut_res.set_result(txinfo)

        def error_cb(msg):
            self.jmman.logger.error(msg)
            self.fut_res.set_result(None)

        # check direct send transaction creation
        amount = 350000
        self.fut_res = self.asyncio_loop.create_future()
        await direct_send(jmman, 0, [(destn, amount)], answeryes=True,
                          info_callback=info_cb, error_callback=error_cb,
                          return_transaction=True)

        tx = await self.fut_res
        assert tx
        for i in tx.inputs():
            # check optin_rbf is enabled
            assert i.nsequence == 0xfffffffd

        # check sweep direct send transaction creation
        amount = 0
        self.fut_res = self.asyncio_loop.create_future()
        await direct_send(jmman, 0, [(destn, amount)], answeryes=True,
                          info_callback=info_cb, return_transaction=True)

        tx = await self.fut_res
        assert tx
        for i in tx.inputs():
            # check optin_rbf is enabled
            assert i.nsequence == 0xfffffffd
