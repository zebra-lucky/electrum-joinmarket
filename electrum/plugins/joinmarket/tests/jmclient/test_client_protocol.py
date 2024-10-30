# -*- coding: utf-8 -*-

'''test client-protocol interfacae.'''

import json
import base64

from electrum.logging import get_logger, ShortcutInjectingFilter

from electrum.plugins.joinmarket.jmbase import commands
from electrum.plugins.joinmarket.jmbase import bintohex
from electrum.plugins.joinmarket import jmbitcoin as bitcoin
from electrum.plugins.joinmarket.jmclient import (
    Taker, JMClientProtocolFactory, NO_ROUNDING,
    get_max_cj_fee_values, fidelity_bond_weighted_order_choose)
from electrum.plugins.joinmarket.jmdaemon.protocol import (
    NICK_HASH_LENGTH, NICK_MAX_ENCODED, JM_VERSION, JOINMARKET_NICK_HEADER)

from electrum.plugins.joinmarket.tests import JMTestCase

from .taker_test_data import t_raw_signed_tx


LOGGING_SHORTCUT = 'J'
jlog = get_logger(__name__)
jlog.addFilter(ShortcutInjectingFilter(shortcut=LOGGING_SHORTCUT))


class DummyTaker(Taker):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.failutxos = 0
        self.failinit = 0

    def set_fail_init(self, val):
        self.failinit = val

    def set_fail_utxos(self, val):
        self.failutxos = val

    def default_taker_info_callback(self, infotype, msg):
        jlog.debug(infotype + ":" + msg)

    async def initialize(self, orderbook, fidelity_bonds_info):
        """Once the daemon is active and has returned the current orderbook,
        select offers, re-initialize variables and prepare a commitment,
        then send it to the protocol to fill offers.
        """
        if self.failinit == -1:
            return (True, -1, "aa" * 32, {'dummy': 'revelation'},
                    orderbook[:2])
        elif self.failinit:
            return (False,)
        else:
            return (True, 1000000, "aa"*32, {'dummy': 'revelation'},
                    orderbook[:2])

    async def receive_utxos(self, ioauth_data):
        """Triggered when the daemon returns utxo data from
        makers who responded; this is the completion of phase 1
        of the protocol
        """
        if self.failutxos:
            return (False, "dummyreason")
        else:
            return (True, [x*64 + ":01" for x in ["a", "b", "c"]],
                    base64.b16decode(t_raw_signed_tx, casefold=True))

    async def on_sig(self, nick, sigb64):
        """For test, we exit 'early' on first message, since this marks the end
        of client-server communication with the daemon.
        """
        jlog.debug("We got a sig: " + sigb64)
        return None


class JMBaseProtocol(commands.CallRemoteMock):

    def checkClientResponse(self, response):
        """A generic check of client acceptance; any failure
        is considered criticial.
        """
        if 'accepted' not in response or not response['accepted']:
            raise Exception("unexpected client response")

    def defaultErrback(self, failure):
        raise failure

    def defaultCallbacks(self, d):
        d.addCallback(self.checkClientResponse)
        d.addErrback(self.defaultErrback)


def show_receipt(name, *args):
    jlog.debug("Received msgtype: " + name + ", args: " +
               ",".join([str(x) for x in args]))


class JMTestServerProtocol(JMBaseProtocol):

    @commands.JMInit.responder
    async def on_JM_INIT(self, bcsource, network, chan_configs,
                         minmakers, maker_timeout_sec,
                         dust_threshold, blacklist_location):
        show_receipt("JMINIT", bcsource, network, chan_configs, minmakers,
                     maker_timeout_sec, dust_threshold, blacklist_location)
        d = await self.callRemote(
            commands.JMInitProto,
            self.factory.proto_client,
            nick_hash_length=1,
            nick_max_encoded=2,
            joinmarket_nick_header="J",
            joinmarket_version=5
        )
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMStartMC.responder
    async def on_JM_START_MC(self, nick):
        show_receipt("STARTMC", nick)
        d = await self.callRemote(commands.JMUp, self.factory.proto_client)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSetup.responder
    async def on_JM_SETUP(self, role, initdata, use_fidelity_bond):
        show_receipt("JMSETUP", role, initdata, use_fidelity_bond)
        d = await self.callRemote(commands.JMSetupDone,
                                  self.factory.proto_client)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMRequestOffers.responder
    async def on_JM_REQUEST_OFFERS(self):
        show_receipt("JMREQUESTOFFERS")
        # build a huge orderbook to test BigString Argument
        orderbook = ["aaaa" for _ in range(15)]
        fidelitybonds = ["bbbb" for _ in range(15)]
        d = await self.callRemote(commands.JMOffers,
                                  self.factory.proto_client,
                                  orderbook=json.dumps(orderbook),
                                  fidelitybonds=json.dumps(fidelitybonds))
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMFill.responder
    async def on_JM_FILL(self, amount, commitment, revelation, filled_offers):
        success = False if amount == -1 else True
        show_receipt("JMFILL", amount, commitment, revelation, filled_offers)
        d = await self.callRemote(commands.JMFillResponse,
                                  self.factory.proto_client, success=success,
                                  ioauth_data=['dummy', 'list'])
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMMakeTx.responder
    async def on_JM_MAKE_TX(self, nick_list, tx):
        show_receipt("JMMAKETX", nick_list, tx)
        d = await self.callRemote(commands.JMSigReceived,
                                  self.factory.proto_client,
                                  nick="dummynick", sig="xxxsig")
        self.defaultCallbacks(d)
        # add dummy calls to check message sign and message verify
        d2 = await self.callRemote(commands.JMRequestMsgSig,
                                   self.factory.proto_client,
                                   nick="dummynickforsign",
                                   cmd="command1",
                                   msg="msgforsign",
                                   msg_to_be_signed="fullmsgforsign",
                                   hostid="hostid1")
        self.defaultCallbacks(d2)
        # To test, this must include a valid ecdsa sig
        fullmsg = "fullmsgforverify"
        priv = b"\xaa"*32 + b"\x01"
        pub = bintohex(bitcoin.privkey_to_pubkey(priv).get_public_key_bytes())
        sig = bitcoin.ecdsa_sign(fullmsg, priv)
        d3 = await self.callRemote(commands.JMRequestMsgSigVerify,
                                   self.factory.proto_client,
                                   msg="msgforverify",
                                   fullmsg=fullmsg,
                                   sig=sig,
                                   pubkey=pub,
                                   nick="dummynickforverify",
                                   hashlen=4,
                                   max_encoded=5,
                                   hostid="hostid2")
        self.defaultCallbacks(d3)
        d4 = await self.callRemote(commands.JMSigReceived,
                                   self.factory.proto_client,
                                   nick="dummynick", sig="dummysig")
        self.defaultCallbacks(d4)
        return {'accepted': True}

    @commands.JMPushTx.responder
    async def on_JM_PushTx(self, nick, tx):
        show_receipt("JMPUSHTX", nick, tx)
        return {'accepted': True}

    @commands.JMMsgSignature.responder
    async def on_JM_MSGSIGNATURE(self, nick, cmd, msg_to_return, hostid):
        show_receipt("JMMSGSIGNATURE", nick, cmd, msg_to_return, hostid)
        return {'accepted': True}

    @commands.JMMsgSignatureVerify.responder
    async def on_JM_MSGSIGNATURE_VERIFY(self, verif_result, nick, fullmsg,
                                        hostid):
        show_receipt("JMMSGSIGVERIFY", verif_result, nick, fullmsg, hostid)
        return {'accepted': True}


class BaseClientProtocolTestCase(JMTestCase):

    def check_offers_callback(self, *args):
        print('check_offers_callback', args)

    def taker_info_callback(self, *args):
        print('taker_info_callback', args)

    def taker_finished_callback(self, *args):
        print('taker_finished_callback', args)

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


class ClientProtocolTestCase(BaseClientProtocolTestCase):

    async def test_on_JM_INIT_PROTO(self):
        await self.client_proto.on_JM_INIT_PROTO(
            nick_hash_length=NICK_HASH_LENGTH,
            nick_max_encoded=NICK_MAX_ENCODED,
            joinmarket_nick_header=JOINMARKET_NICK_HEADER,
            joinmarket_version=JM_VERSION)

    async def test_on_JM_REQUEST_MSGSIG(self):
        self.client_proto.nick_hashlen = NICK_HASH_LENGTH
        self.client_proto.nick_maxencoded = NICK_MAX_ENCODED
        self.client_proto.nick_header = JOINMARKET_NICK_HEADER
        self.client_proto.jm_version = JM_VERSION
        self.client_proto.connectionMade()
        self.client_proto.set_nick()
        await self.client_proto.on_JM_REQUEST_MSGSIG(
           nick="dummynickforsign", cmd="command1", msg="msgforsign",
           msg_to_be_signed="fullmsgforsign", hostid="hostid1")

    async def test_on_JM_REQUEST_MSGSIG_VERIFY(self):
        await self.client_proto.on_JM_INIT_PROTO(
            nick_hash_length=NICK_HASH_LENGTH,
            nick_max_encoded=NICK_MAX_ENCODED,
            joinmarket_nick_header=JOINMARKET_NICK_HEADER,
            joinmarket_version=JM_VERSION)
        fullmsg = "fullmsgforverify"
        priv = b"\xaa"*32 + b"\x01"
        pub = bintohex(bitcoin.privkey_to_pubkey(priv).get_public_key_bytes())
        sig = bitcoin.ecdsa_sign(fullmsg, priv)
        await self.client_proto.on_JM_REQUEST_MSGSIG_VERIFY(
            msg="msgforverify",
            fullmsg=fullmsg,
            sig=sig,
            pubkey=pub,
            nick="dummynickforverify",
            hashlen=4,
            max_encoded=5,
            hostid="hostid2")

    async def test_make_tx(self):
        await self.client_proto.on_JM_INIT_PROTO(
            nick_hash_length=NICK_HASH_LENGTH,
            nick_max_encoded=NICK_MAX_ENCODED,
            joinmarket_nick_header=JOINMARKET_NICK_HEADER,
            joinmarket_version=JM_VERSION)
        nick_list = ['nick1', 'nick2']
        tx = b'deadbeaf'
        await self.client_proto.make_tx(nick_list=nick_list, tx=tx)

    async def test_request_mc_shutdown(self):
        await self.client_proto.on_JM_INIT_PROTO(
            nick_hash_length=NICK_HASH_LENGTH,
            nick_max_encoded=NICK_MAX_ENCODED,
            joinmarket_nick_header=JOINMARKET_NICK_HEADER,
            joinmarket_version=JM_VERSION)
        await self.client_proto.request_mc_shutdown()


class TakerClientProtocolTestCase(BaseClientProtocolTestCase):

    async def test_clientStart(self):
        await self.client_proto.clientStart()

    async def test_stallMonitor(self):
        self.client_proto.stallMonitor(0)

    async def test_on_JM_UP(self):
        await self.client_proto.on_JM_UP()

    async def test_on_JM_SETUP_DONE(self):
        await self.client_proto.on_JM_SETUP_DONE()

    async def test_on_JM_FILL_RESPONSE(self):
        await self.client_proto.on_JM_FILL_RESPONSE(
            success=True, ioauth_data={'dummy': 'ioauth'})

    async def test_on_JM_OFFERS(self):
        orderbook = ["aaaa" for _ in range(15)]
        fidelitybonds = ["bbbb" for _ in range(15)]
        await self.client_proto.on_JM_OFFERS(
            orderbook=json.dumps(orderbook),
            fidelitybonds=json.dumps(fidelitybonds))

    async def test_on_JM_SIG_RECEIVED(self):
        await self.client_proto.on_JM_SIG_RECEIVED(
            nick="dummynick", sig="xxxsig")

    async def test_get_offers(self):
        await self.client_proto.get_offers()

    async def test_push_tx(self):
        await self.client_proto.push_tx("dummynick", b"deadbeef")
