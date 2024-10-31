# -*- coding: utf-8 -*-

'''test daemon-protocol interfacae.'''

import base64

from electrum.logging import get_logger, ShortcutInjectingFilter

from electrum.plugins.joinmarket.jmdaemon import MessageChannelCollection
from electrum.plugins.joinmarket.jmdaemon import OrderbookWatch
from electrum.plugins.joinmarket.jmbase import commands
from electrum.plugins.joinmarket.jmclient import (
    JMClientProtocolFactory, NO_ROUNDING,
    get_max_cj_fee_values, fidelity_bond_weighted_order_choose)
from electrum.plugins.joinmarket.tests import JMTestCase
from electrum.plugins.joinmarket.tests.jmclient.test_client_protocol import (
    DummyTaker)

from .dummy_mc import DummyMessageChannel
from .msgdata import t_chosen_orders


LOGGING_SHORTCUT = 'J'
jlog = get_logger(__name__)
jlog.addFilter(ShortcutInjectingFilter(shortcut=LOGGING_SHORTCUT))


class DummyMC(DummyMessageChannel):
    # override run() for twisted compatibility
    def run(self):
        if self.on_welcome:
            commands.callLater(1, self.on_welcome, self)


class JMBaseProtocol(commands.CallRemoteMock):

    def checkClientResponse(self, response):
        """A generic check of client acceptance; any failure
        is considered criticial.
        """
        if 'accepted' not in response or not response['accepted']:
            raise Exception(response)

    def defaultErrback(self, failure):
        raise failure

    def defaultCallbacks(self, d):
        d.addCallback(self.checkClientResponse)
        d.addErrback(self.defaultErrback)


class JMTestClientProtocol(JMBaseProtocol):

    def connectionMade(self):
        self.clientStart()

    async def clientStart(self):
        self.sigs_received = 0
        chan_configs = list(self.jmman.jmconf.get_msg_channels().values())[0]
        d = await self.callRemote(commands.JMInit, self.proto_daemon,
                                  bcsource="dummyblockchain",
                                  network="dummynetwork",
                                  chan_configs=chan_configs,
                                  minmakers=2,
                                  maker_timeout_sec=3,
                                  dust_threshold=27300,
                                  blacklist_location=".")
        self.defaultCallbacks(d)

    @commands.JMInitProto.responder
    async def on_JM_INIT_PROTO(self, nick_hash_length, nick_max_encoded,
                               joinmarket_nick_header, joinmarket_version):
        show_receipt("JMINITPROTO", nick_hash_length, nick_max_encoded,
                     joinmarket_nick_header, joinmarket_version)
        d = await self.callRemote(commands.JMStartMC, self.proto_daemon,
                                  nick="dummynick")
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMUp.responder
    async def on_JM_UP(self):
        show_receipt("JMUP")
        d = await self.callRemote(commands.JMSetup, self.proto_daemon,
                                  role="TAKER",
                                  initdata=None,
                                  use_fidelity_bond=False)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSetupDone.responder
    async def on_JM_SETUP_DONE(self):
        show_receipt("JMSETUPDONE")
        d = await self.callRemote(commands.JMRequestOffers, self.proto_daemon)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMFillResponse.responder
    async def on_JM_FILL_RESPONSE(self, success, ioauth_data):
        show_receipt("JMFILLRESPONSE", success, ioauth_data)
        commands.callLater(1, self.maketx, ioauth_data)
        return {'accepted': True}

    async def maketx(self, ioauth_data):
        nl = list(ioauth_data)
        d = await self.callRemote(commands.JMMakeTx, self.proto_daemon,
                                  nick_list=nl,
                                  tx=b"deadbeef")
        self.defaultCallbacks(d)

    @commands.JMOffers.responder
    async def on_JM_OFFERS(self, orderbook, fidelitybonds):
        jlog.debug("JMOFFERS" + str(orderbook))
        # Trigger receipt of verified privmsgs, including unverified
        nick = str(list(t_chosen_orders.keys())[0])
        b64tx = base64.b64encode(b"deadbeef").decode('ascii')
        d1 = await self.callRemote(commands.JMMsgSignatureVerify,
                                   self.proto_daemon,
                                   verif_result=True,
                                   nick=nick,
                                   fullmsg="!push " + b64tx + " abc def",
                                   hostid="dummy")
        self.defaultCallbacks(d1)
        # unverified
        d2 = await self.callRemote(commands.JMMsgSignatureVerify,
                                   self.proto_daemon,
                                   verif_result=False,
                                   nick=nick,
                                   fullmsg="!push " + b64tx + " abc def",
                                   hostid="dummy")
        self.defaultCallbacks(d2)
        d = await self.callRemote(commands.JMFill, self.proto_daemon,
                                  amount=100,
                                  commitment="dummycommitment",
                                  revelation="dummyrevelation",
                                  filled_offers=t_chosen_orders)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSigReceived.responder
    async def on_JM_SIG_RECEIVED(self, nick, sig):
        show_receipt("JMSIGRECEIVED", nick, sig)
        self.sigs_received += 1
        return {'accepted': True}

    @commands.JMRequestMsgSig.responder
    async def on_JM_REQUEST_MSGSIG(self, nick, cmd, msg, msg_to_be_signed,
                                   hostid):
        show_receipt("JMREQUESTMSGSIG", nick, cmd, msg, msg_to_be_signed,
                     hostid)
        d = await self.callRemote(commands.JMMsgSignature, self.proto_daemon,
                                  nick=nick,
                                  cmd=cmd,
                                  msg_to_return="xxxcreatedsigxx",
                                  hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMRequestMsgSigVerify.responder
    async def on_JM_REQUEST_MSGSIG_VERIFY(self, msg, fullmsg, sig, pubkey,
                                          nick, hashlen, max_encoded, hostid):
        show_receipt("JMREQUESTMSGSIGVERIFY", msg, fullmsg, sig, pubkey,
                     nick, hashlen, max_encoded, hostid)
        d = await self.callRemote(commands.JMMsgSignatureVerify,
                                  self.proto_daemon,
                                  verif_result=True,
                                  nick=nick,
                                  fullmsg=fullmsg,
                                  hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}


def show_receipt(name, *args):
    jlog.debug("Received msgtype: " + name + ", args: " +
               ",".join([str(x) for x in args]))


class TestJMDaemonProtocol(JMTestCase):

    def check_offers_callback(self, *args):
        print('check_offers_callback', args)

    def taker_info_callback(self, *args):
        print('taker_info_callback', args)

    def taker_finished_callback(self, *args):
        print('taker_finished_callback', args)

    def on_order_seen(self, *args):
        print('on_order_seen', args)

    def on_order_cancel(self, *args):
        print('on_order_cancel', args)

    def on_fidelity_bond_seen(self, *args):
        print('on_fidelity_bond_seen', args)

    def on_welcome(self, *args):
        print('on_welcome', args)

    def on_set_topic(self, *args):
        print('on_set_topic', args)

    def on_disconnect(self, *args):
        print('on_disconnect', args)

    def on_nick_leave(self, *args):
        print('on_nick_leave', args)

    async def asyncSetUp(self):
        await super().asyncSetUp()

        jmman = self.jmman
        jmconf = self.jmconf
        jmconf.maker_timeout_sec = 1
        jmconf.max_cj_fee_confirmed = True
        self.schedule = [[0, 0, 2, 'INTERNAL', 0, NO_ROUNDING, 0]]
        self.maxcjfee = get_max_cj_fee_values(jmman, None)
        self.destaddrs = []
        self.taker = DummyTaker(
            jmman,
            self.schedule,
            self.maxcjfee,
            order_chooser=fidelity_bond_weighted_order_choose,
            callbacks=[self.check_offers_callback,
                       self.taker_info_callback,
                       self.taker_finished_callback],
            tdestaddrs=self.destaddrs,
            custom_change_address=None,
            ignored_makers=jmman.jmw.ignored_makers
        )
        self.clientfactory = JMClientProtocolFactory(self.taker)
        jmman.set_client_factory(self.clientfactory)
        self.client_proto = self.clientfactory.getClient()
        self.daemon_proto = self.clientfactory.proto_daemon
        mcs = [DummyMC(self.jmman, None)]
        self.daemon_proto.mcc = MessageChannelCollection(mcs, self.jmman)
        OrderbookWatch.set_msgchan(self.daemon_proto, self.daemon_proto.mcc)

    async def test_on_JM_INIT(self):
        jmconf = self.jmconf
        blockchain_source = jmconf.BLOCKCHAIN_SOURCE
        network = jmconf.blockchain_network
        chan_configs = self.clientfactory.get_mchannels(mode="TAKER")
        minmakers = jmconf.minimum_makers
        maker_timeout_sec = jmconf.maker_timeout_sec

        await self.daemon_proto.on_JM_INIT(
            bcsource=blockchain_source,
            network=network,
            chan_configs=chan_configs,
            minmakers=minmakers,
            maker_timeout_sec=maker_timeout_sec,
            dust_threshold=jmconf.DUST_THRESHOLD,
            blacklist_location=None)

    async def test_on_JM_START_MC(self):
        await self.daemon_proto.on_JM_START_MC('dummynick')

    async def test_on_JM_SETUP(self):
        await self.daemon_proto.on_JM_SETUP(
            role="TAKER", initdata=None, use_fidelity_bond=False)

    async def test_on_JM_MSGSIGNATURE(self):
        await self.daemon_proto.on_JM_MSGSIGNATURE(
            nick='dummy', cmd='cmd', msg_to_return='fullmsg', hostid='dummy')

    async def test_on_JM_MSGSIGNATURE_VERIFY(self):
        await self.daemon_proto.on_JM_MSGSIGNATURE_VERIFY(
            verif_result=True, nick='dummy', fullmsg='fullm', hostid='dummy')

    async def test_on_JM_SHUTDOWN(self):
        await self.daemon_proto.on_JM_SHUTDOWN()

    async def test_on_JM_REQUEST_OFFERS(self):
        await self.daemon_proto.on_JM_REQUEST_OFFERS()

    async def test_on_JM_FILL(self):
        await self.daemon_proto.on_JM_FILL(
            amount=100, commitment="dummycommitment",
            revelation="dummyrevelation", filled_offers=t_chosen_orders)

    async def test_on_JM_MAKE_TX(self):
        nl = ['nick1', 'nick2']
        await self.daemon_proto.on_JM_MAKE_TX(nick_list=nl, tx=b"deadbeef")

    async def test_on_JM_PushTx(self):
        await self.daemon_proto.on_JM_PushTx(nick='dummy', tx=b"deadbeef")
