# -*- coding: utf-8 -*-

'''Tests of joinmarket bots end-to-end (including IRC and bitcoin) '''

import io
import time

from electrum.plugins.joinmarket.jmbase import commands
from electrum.plugins.joinmarket.jmdaemon import (
    IRCMessageChannel, MessageChannelCollection)

from electrum.plugins.joinmarket.tests import JMTestCase


si = 1


class DummyDaemon(object):

    def request_signature_verify(self, a, b, c, d, e, f, g, h):
        return True


class DummyMC(IRCMessageChannel):

    def __init__(self, jmman, configdata, nick):
        super().__init__(jmman, configdata)
        self.jmman = jmman
        self.set_nick(nick)

    async def shutdown(self):
        self.tx_irc_client.transport = io.BytesIO(b'')
        self.tx_irc_client._queue = []
        self.tx_irc_client.quit()
        self.give_up = True
        if self.client_service:
            self.client_service.stopService()


def on_connect(x):
    print('simulated on-connect')


def on_welcome(mc):
    print('simulated on-welcome')
    mc.tx_irc_client.lineRate = 0.2
    if mc.nick == "irc_publisher":
        d = commands.deferLater(3.0, junk_pubmsgs, mc)
        d.addCallback(junk_longmsgs)
        d.addCallback(junk_announce)
        d.addCallback(junk_fill)


def on_disconnect(x):
    print('simulated on-disconnect')


def on_order_seen(dummy, counterparty, oid, ordertype, minsize,
                  maxsize, txfee, cjfee):
    global yg_name
    yg_name = counterparty


def on_pubkey(pubkey):
    print("received pubkey: " + pubkey)


async def junk_pubmsgs(mc):
    # start a raw IRCMessageChannel instance in a thread;
    # then call send_* on it with various errant messages
    time.sleep(si)
    await mc.request_orderbook()
    time.sleep(si)
    # now try directly
    await mc.pubmsg("!orderbook")
    time.sleep(si)
    # should be ignored; can we check?
    await mc.pubmsg("!orderbook!orderbook")
    return mc


async def junk_longmsgs(mc):
    # assuming MAX_PRIVMSG_LEN is not something crazy
    # big like 550, this should fail
    # with pytest.raises(AssertionError) as e_info:
    await mc.pubmsg("junk and crap"*40)
    time.sleep(si)
    # assuming MAX_PRIVMSG_LEN is not something crazy
    # small like 180, this should succeed
    await mc.pubmsg("junk and crap"*15)
    time.sleep(si)
    return mc


async def junk_announce(mc):
    # try a long order announcement in public
    # because we don't want to build a real orderbook,
    # call the underlying IRC announce function.
    # TODO: how to test that the sent format was correct?
    print('got here')
    await mc._announce_orders(["!abc def gh 0001"]*30)
    time.sleep(si)
    return mc


async def junk_fill(mc):
    cpname = "irc_receiver"
    # send a fill with an invalid pubkey to the existing yg;
    # this should trigger a NaclError but should NOT kill it.
    await mc._privmsg(cpname, "fill", "0 10000000 abcdef")
    # Try with ob flag
    await mc._pubmsg("!reloffer stuff")
    time.sleep(si)
    # Trigger throttling with large messages
    await mc._privmsg(cpname, "tx", "aa"*5000)
    time.sleep(si)
    # with pytest.raises(CJPeerError) as e_info:
    await mc.send_error(cpname, "fly you fools!")
    time.sleep(si)
    return mc


def getmc(jmman, nick):
    jmconf = jmman.jmconf
    mchannels = list(jmconf.get_msg_channels().values())
    mc = DummyMC(jmman, mchannels[0], nick)
    mc.register_orderbookwatch_callbacks(on_order_seen=on_order_seen)
    mc.register_taker_callbacks(on_pubkey=on_pubkey)
    mc.on_connect = on_connect
    mc.on_disconnect = on_disconnect
    mc.on_welcome = on_welcome
    mcc = MessageChannelCollection([mc], jmman)
    return mc, mcc


class TrialIRC(JMTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.jmman.jmconf.maker_timeout_sec = 1
        mc, mcc = getmc(self.jmman, "irc_publisher")
        mc2, mcc2 = getmc(self.jmman, "irc_receiver")
        await mcc.run()
        mc.irc_factory.buildProtocol()
        await mcc2.run()
        mc2.irc_factory.buildProtocol()

        async def cb(m):
            # don't try to reconnect
            m.give_up = True
            await mc.shutdown()

        self.addCleanup(cb, mc)
        self.addCleanup(cb, mc2)
        # test_junk_messages()
        print("Got here")

    async def test_waiter(self):
        # commands.callLater(1.0, junk_messages, self.mcc)
        return commands.deferLater(30, self._called_by_deffered)

    async def _called_by_deffered(self):
        pass
