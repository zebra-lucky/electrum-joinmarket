# -*- coding: utf-8 -*-

import asyncio
import io

from electrum.plugins.joinmarket.jmbase import commands
from electrum.plugins.joinmarket.jmdaemon import (
    OnionMessageChannel, MessageChannelCollection)
from electrum.plugins.joinmarket.jmdaemon.onionmc import (
    PEER_STATUS_UNCONNECTED, PEER_STATUS_CONNECTED, PEER_STATUS_HANDSHAKED,
    PEER_STATUS_DISCONNECTED, NOT_SERVING_ONION_HOSTNAME, OnionPeerError,
    OnionCustomMessageDecodingError, OnionCustomMessage, JM_MESSAGE_TYPES,
    OnionPeer, OnionDirectoryPeerNotFound)
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

    async def on_connect(self, x):
        print('simulated on-connect', x)

    async def on_welcome(self, mc):
        print('simulated on-welcome', mc)
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

    async def on_nick_leave(self, nick, msgchan):
        print('simulated on_nick_leave', nick, msgchan)

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

    async def asyncSetUp(self):
        await super().asyncSetUp()
        jmman = self.jmman
        jmconf = jmman.jmconf
        jmconf.maker_timeout_sec = 1
        configdata = list(jmconf.get_msg_channels().values())[2]
        directory_node = configdata['directory_nodes'].split(',')[0]
        configdata['directory_nodes'] = directory_node
        self.mc = mc = DummyMC(jmman, configdata, 'onionnick')
        mc.register_orderbookwatch_callbacks(on_order_seen=self.on_order_seen)
        mc.register_taker_callbacks(on_pubkey=self.on_pubkey)
        mc.on_connect = self.on_connect
        mc.on_disconnect = self.on_disconnect
        mc.on_welcome = self.on_welcome
        mc.on_nick_leave = self.on_nick_leave
        for p in self.mc.peers:
            p.connect()
            p._status = PEER_STATUS_HANDSHAKED
        self.peer = list(self.mc.peers)[0]
        self.mcc = MessageChannelCollection([self.mc], jmman)
        await self.mcc.run()

    async def asyncTearDown(self):

        async def cb(m):
            # don't try to reconnect
            m.give_up = True
            await m.shutdown()

        await cb(self.mc)


class OnionCustomMessageTestCase(OnionBaseTestCase):

    async def test_from_string_decode(self):
        with self.assertRaises(OnionCustomMessageDecodingError):
            OnionCustomMessage.from_string_decode(b'')
        msg = OnionCustomMessage.from_string_decode(
            b'{"line": "dummymsg", "type": 1}')
        assert msg.text == 'dummymsg'
        assert msg.msgtype == 1


class OnionLineProtocolTestCase(OnionBaseTestCase):

    async def test_connection_lost(self):
        protocol = self.peer.reconnecting_service.protocol
        protocol.connection_lost(Exception('dummy connection lost'))

    async def test_line_received(self):
        protocol = self.peer.reconnecting_service.protocol
        protocol.line_received(
            b'{"line": "dummymsg", "type": 1}')
        protocol.line_received(b'dummymsg')


class OnionClientFactoryTestCase(OnionBaseTestCase):

    async def test_register_disconnection(self):
        peer = self.peer
        factory = peer.factory
        factory.register_disconnection(peer.reconnecting_service.protocol)

    async def test_send(self):
        factory = self.peer.factory
        msg = OnionCustomMessage('dummymsg', JM_MESSAGE_TYPES["pubmsg"])
        assert factory.send(msg)

    async def test_receive_message(self):
        peer = self.peer
        factory = peer.factory
        msg = OnionCustomMessage('dummymsg', JM_MESSAGE_TYPES["pubmsg"])
        factory.receive_message(msg, peer.reconnecting_service.protocol)


class OnionPeerTestCase(OnionBaseTestCase):

    async def test_update_status(self):
        peer = self.peer
        assert peer.status() == PEER_STATUS_HANDSHAKED
        peer._status = PEER_STATUS_UNCONNECTED
        assert peer.status() == PEER_STATUS_UNCONNECTED
        peer.update_status(PEER_STATUS_CONNECTED)
        assert peer.status() == PEER_STATUS_CONNECTED
        peer.update_status(PEER_STATUS_HANDSHAKED)
        assert peer.status() == PEER_STATUS_HANDSHAKED
        peer.update_status(PEER_STATUS_DISCONNECTED)
        assert peer.status() == PEER_STATUS_DISCONNECTED

    async def test_set_nick(self):
        peer = self.peer
        assert peer.nick == ''
        peer.set_nick('dummynick')
        assert peer.nick == 'dummynick'

    async def test_get_nick_peerlocation_ser(self):
        peer = self.peer
        with self.assertRaises(OnionPeerError):
            peer.get_nick_peerlocation_ser()
        peer.set_nick('dummynick')
        assert peer.get_nick_peerlocation_ser() == (
            'dummynick;'
            'rr6f6qtleiiwic45bby4zwmiwjrj3jsbmcvutwpqxjziaydjydkk5iad'
            '.onion:5222')

    async def test_set_location(self):
        peer = self.peer
        assert peer.set_location(NOT_SERVING_ONION_HOSTNAME)
        assert not peer.set_location('host:port')
        assert not peer.set_location('host:-5')
        assert peer.set_location('host:5222')

    async def test_peer_location(self):
        peer = self.peer
        assert peer.peer_location() == (
            'rr6f6qtleiiwic45bby4zwmiwjrj3jsbmcvutwpqxjziaydjydkk5iad'
            '.onion:5222')
        assert peer.set_location('host:5222')
        assert peer.peer_location() == 'host:5222'

    async def test_send(self):
        peer = self.peer
        msg = OnionCustomMessage('dummymsg', JM_MESSAGE_TYPES["pubmsg"])
        assert peer.send(msg)

    async def test_receive_message(self):
        msg = OnionCustomMessage('!dummymsg test', JM_MESSAGE_TYPES["pubmsg"])
        peer = self.peer
        await peer.receive_message(msg)

    async def test_notify_message_unsendable(self):
        peer = self.peer
        peer.notify_message_unsendable()


class OnionMessageChannelTestCase(OnionBaseTestCase):

    async def test_info_callback(self):
        self.mc.info_callback('dummymsg')

    async def test_setup_error_callback(self):
        self.mc.setup_error_callback('dummymsg')

    async def test_shutdown_callback(self):
        self.mc.shutdown_callback('dummymsg')

    async def test_get_pubmsg(self):
        assert self.mc.get_pubmsg('dummymsg', 'dummynick') == (
            'dummynick!PUBLICdummymsg')

    async def test_get_privmsg(self):
        assert self.mc.get_privmsg(
            'dummynick', 'cmd', 'dummymsg', 'dummy2') == (
                'dummy2!dummynick!cmd dummymsg')

    async def test_pubmsg(self):
        await self.mc._pubmsg('dummymsg')

    async def test_should_try_to_connect(self):
        assert not self.mc.should_try_to_connect(None)
        mc = self.mc
        peer = OnionPeer(mc, mc.socks5_host, mc.socks5_port,
                         (NOT_SERVING_ONION_HOSTNAME, -1), False, 'dummynick')
        assert not self.mc.should_try_to_connect(peer)
        peer = OnionPeer(mc, mc.socks5_host, mc.socks5_port,
                         ('host', 5222), True, 'dummynick')
        assert not self.mc.should_try_to_connect(peer)
        assert not self.mc.should_try_to_connect(mc.self_as_peer)
        peer = OnionPeer(mc, mc.socks5_host, mc.socks5_port,
                         ('host', 5222), False, 'dummynick')
        peer._status = PEER_STATUS_HANDSHAKED
        assert not self.mc.should_try_to_connect(peer)
        peer._status = PEER_STATUS_UNCONNECTED
        assert self.mc.should_try_to_connect(peer)

    async def test_privmsg(self):
        await self.mc._privmsg('dummynick', 'cmd', 'dummymsg')

    async def test_announce_orders(self):
        await self.mc._announce_orders(['a', 'b', 'c'])

    async def test_get_directory_for_nick(self):
        mc = self.mc
        dummynick = 'dummynick'
        with self.assertRaises(OnionDirectoryPeerNotFound):
            mc.get_directory_for_nick(dummynick)
        mc.active_directories[dummynick] = {}
        with self.assertRaises(OnionDirectoryPeerNotFound):
            mc.get_directory_for_nick(dummynick)
        mc.active_directories[dummynick][self.peer] = False
        with self.assertRaises(OnionDirectoryPeerNotFound):
            mc.get_directory_for_nick(dummynick)
        mc.active_directories[dummynick][self.peer] = True
        assert mc.get_directory_for_nick(dummynick) == self.peer

    async def test_on_nick_leave_directory(self):
        mc = self.mc
        dp = self.peer
        dummynick = 'dummynick'
        assert not await mc.on_nick_leave_directory(dummynick, dp)
        mc.active_directories[dummynick] = {}
        assert not await mc.on_nick_leave_directory(dummynick, dp)
        mc.active_directories[dummynick][self.peer] = True
        await mc.on_nick_leave_directory(dummynick, dp)