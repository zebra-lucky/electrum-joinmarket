# -*- coding: utf-8 -*-

import asyncio
import io

from electrum.plugins.joinmarket.jmbase import commands
from electrum.plugins.joinmarket.jmdaemon import (
    IRCMessageChannel, MessageChannelCollection)
from electrum.plugins.joinmarket.jmdaemon.irc import (
    wlog, get_irc_nick, get_config_irc_channel, TxIRCFactory)
from electrum.plugins.joinmarket.jmdaemon.irc_support import IRCClientService

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


class DummyIRCClientService(IRCClientService):

    async def _dummy_create_conn(self, sslc):
        self.logger.debug(f'_dummy_create_conn: {self.factory.buildProtocol}, '
                          f'{self.host}:{self.port}, {sslc}')
        transport = DummyTransport(self.logger)
        protocol = self.factory.buildProtocol()
        protocol.connection_made(transport)
        return transport, protocol

    async def _create_conn(self, sslc):
        self.logger.debug(f'_create_conn: {sslc}')
        self.transport, self.protocol = await self._dummy_create_conn(sslc)

    async def _proxy_create_conn(self, sslc):
        self.logger.debug(f'_proxy_create_conn: {sslc}')
        self.transport, self.protocol = await self._create_conn(sslc)


class DummyMC(IRCMessageChannel):

    def __init__(self, jmman, configdata, nick):
        super().__init__(jmman, configdata)
        self.set_nick(nick)

    async def build_irc(self):
        wlog(self.logger, 'building irc')
        if self.tx_irc_client:
            raise Exception('irc already built')
        try:
            self.irc_factory = TxIRCFactory(self)
            wlog(
                self.logger,
                f'build_irc: host={self.host}, port={self.port}, '
                f'channel={self.channel}, usessl={self.usessl}, '
                f'socks5={self.socks5}, socks5_host={self.socks5_host}, '
                f'socks5_port={self.socks5_port}')
            self.client_service = DummyIRCClientService(
                self.irc_factory, host=self.host, port=self.port,
                loop=self.loop, usessl=self.usessl, socks5=self.socks5,
                socks5_host=self.socks5_host, socks5_port=self.socks5_port)
            self.client_service.startService()
            await self.client_service.srv_task
        except Exception as e:
            wlog(self.logger, 'error in buildirc: ' + repr(e))


class IRCBaseTestCase(JMTestCase):

    async def on_connect(self, x):
        print('simulated on-connect', x)

    async def on_welcome(self, mc):
        print('simulated on-welcome', mc)
        mc.tx_irc_client.lineRate = 0.2
        if mc.nick == "irc_publisher":
            d = commands.deferLater(3.0, self.junk_pubmsgs, mc)
            d.addCallback(self.junk_longmsgs)
            d.addCallback(self.junk_announce)
            d.addCallback(self.junk_fill)

    async def on_disconnect(self, x):
        print('simulated on-disconnect', x)

    def on_order_seen(self, dummy, counterparty, oid, ordertype, minsize,
                      maxsize, txfee, cjfee):
        self.yg_name = counterparty

    async def on_pubkey(self, pubkey):
        print("received pubkey: " + pubkey)

    async def junk_pubmsgs(self, mc):
        # start a raw IRCMessageChannel instance in a thread;
        # then call send_* on it with various errant messages
        await asyncio.sleep(1)
        await mc.request_orderbook()
        await asyncio.sleep(1)
        # now try directly
        await mc.pubmsg("!orderbook")
        await asyncio.sleep(1)
        # should be ignored; can we check?
        await mc.pubmsg("!orderbook!orderbook")
        return mc

    async def junk_longmsgs(self, mc):
        # assuming MAX_PRIVMSG_LEN is not something crazy
        # big like 550, this should fail
        # with pytest.raises(AssertionError) as e_info:
        await mc.pubmsg("junk and crap"*40)
        await asyncio.sleep(1)
        # assuming MAX_PRIVMSG_LEN is not something crazy
        # small like 180, this should succeed
        await mc.pubmsg("junk and crap"*15)
        await asyncio.sleep(1)
        return mc

    async def junk_announce(self, mc):
        # try a long order announcement in public
        # because we don't want to build a real orderbook,
        # call the underlying IRC announce function.
        # TODO: how to test that the sent format was correct?
        print('got here')
        await mc._announce_orders(["!abc def gh 0001"]*30)
        await asyncio.sleep(1)
        return mc

    async def junk_fill(self, mc):
        cpname = "irc_receiver"
        # send a fill with an invalid pubkey to the existing yg;
        # this should trigger a NaclError but should NOT kill it.
        await mc._privmsg(cpname, "fill", "0 10000000 abcdef")
        # Try with ob flag
        await mc._pubmsg("!reloffer stuff")
        await asyncio.sleep(1)
        # Trigger throttling with large messages
        await mc._privmsg(cpname, "tx", "aa"*5000)
        await asyncio.sleep(1)
        # with pytest.raises(CJPeerError) as e_info:
        await mc.send_error(cpname, "fly you fools!")
        await asyncio.sleep(1)
        return mc

    def getmc(self, nick):
        jmman = self.jmman
        jmconf = jmman.jmconf
        mchannels = list(jmconf.get_msg_channels().values())
        mc = DummyMC(jmman, mchannels[0], nick)
        mc.register_orderbookwatch_callbacks(on_order_seen=self.on_order_seen)
        mc.register_taker_callbacks(on_pubkey=self.on_pubkey)
        mc.on_connect = self.on_connect
        mc.on_disconnect = self.on_disconnect
        mc.on_welcome = self.on_welcome
        mcc = MessageChannelCollection([mc], jmman)
        return mc, mcc

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.jmman.jmconf.maker_timeout_sec = 1
        self.mc, self.mcc = self.getmc("irc_publisher")
        self.mc2, self.mcc2 = self.getmc("irc_receiver")
        await self.mcc.run()
        self.irc = self.mc.tx_irc_client
        await self.mcc2.run()
        self.irc2 = self.mc2.tx_irc_client

    async def asyncTearDown(self):

        async def cb(m):
            # don't try to reconnect
            m.give_up = True
            await m.shutdown()

        await cb(self.mc)
        await cb(self.mc2)


class IRCMessageChannelTestCase(IRCBaseTestCase):

    async def test_wlog(self):
        log = self.logger
        wlog(log, 'INFO', 'test info wlog')
        wlog(log, 'WARNING', 'test warning wlog')
        wlog(log, 'test debug wlog', 'test', b'wlog', 1e9, 5, None)

    async def test_get_irc_nick(self):
        assert get_irc_nick('@dummynick! text') == '@dummynick'
        assert get_irc_nick('@verylongdummynick! text') == '@verylongdummyni'

    async def test_get_config_irc_channel(self):
        chan = 'joinmarket-pit'
        assert get_config_irc_channel(chan, 'testnet') == f'#{chan}-test'
        assert get_config_irc_channel(chan, 'testnet4') == f'#{chan}-test4'
        assert get_config_irc_channel(chan, 'signet') == f'#{chan}-sig'
        assert get_config_irc_channel(chan, 'mainnet') == f'#{chan}'

    async def test_factory_clientConnectionLost(self):
        self.mc.irc_factory.clientConnectionLost('testreason')

    async def test_factory_clientConnectionFailed(self):
        self.mc.irc_factory.clientConnectionFailed('testreason')

    async def test_pubmsg(self):
        await self.mc._pubmsg('testmsg')

    async def test_privmsg(self):
        await self.mc._privmsg('dummynick', "fill", "0 10000000 abcdef")

    async def test_change_nick(self):
        self.mc.change_nick('newdummynick')

    async def test_announce_orders(self):
        await self.mc._announce_orders(["!abc def gh 0001"]*30)


class txIRC_ClientTestCase(IRCBaseTestCase):

    async def test_connection_lost(self):
        self.irc.connection_lost('test reason')

    async def test_privmsg(self):
        self.irc._privmsg('dummynick', "fill", "0 10000000 abcdef")
        self.irc._privmsg('dummynick', "fill", 'msg'*500)

    async def test_signedOn(self):
        self.irc.signedOn()

    async def test_joined(self):
        await self.irc.joined('dummy')

    async def test_handle_privmsg(self):
        to_nick = 'irc_publisher'
        to_chan = '#joinmarket-pit-test'
        self.irc.handle_privmsg('@dummy1!', '@dummy2!', 'badcmd')
        self.irc.handle_privmsg('@dummy1!', to_nick, 'badcmd')
        self.irc.handle_privmsg('@dummy1!', to_nick, '!fill 123')
        self.irc.handle_privmsg('@dummy1!', to_nick, '!fill 123;')
        self.irc.handle_privmsg('@dummy1!', to_nick, '!fill 123~')
        self.irc.handle_privmsg('@dummy1!', to_chan, '!fill 123~')
