# -*- coding: utf-8 -*-

'''test daemon-protocol interfacae.'''

import base64

from electrum.logging import get_logger, ShortcutInjectingFilter

from electrum.plugins.joinmarket.jmdaemon import MessageChannelCollection
from electrum.plugins.joinmarket.jmdaemon import OrderbookWatch
from electrum.plugins.joinmarket.jmdaemon.daemon_protocol import (
    JMDaemonServerProtocol)
from electrum.plugins.joinmarket.jmdaemon.protocol import (
    NICK_HASH_LENGTH, NICK_MAX_ENCODED, JM_VERSION, JOINMARKET_NICK_HEADER)
from electrum.plugins.joinmarket.jmbase import commands
from electrum.plugins.joinmarket.tests import JMTestCase

from .dummy_mc import DummyMessageChannel
from .msgdata import t_orderbook, t_chosen_orders


LOGGING_SHORTCUT = 'J'
jlog = get_logger(__name__)
jlog.addFilter(ShortcutInjectingFilter(shortcut=LOGGING_SHORTCUT))


test_completed = False
end_early = False


class DummyMC(DummyMessageChannel):
    # override run() for twisted compatibility
    def run(self):
        if self.on_welcome:
            commands.callLater(1, self.on_welcome, self)


class JMProtocolError(Exception):
    pass


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

    def clientStart(self):
        self.sigs_received = 0
        chan_configs = list(self.jmman.jmconf.get_msg_channels().values())[0]
        d = self.callRemote(commands.JMInit,
                            bcsource="dummyblockchain",
                            network="dummynetwork",
                            chan_configs=chan_configs,
                            minmakers=2,
                            maker_timeout_sec=3,
                            dust_threshold=27300,
                            blacklist_location=".")
        self.defaultCallbacks(d)

    @commands.JMInitProto.responder
    def on_JM_INIT_PROTO(self, nick_hash_length, nick_max_encoded,
                         joinmarket_nick_header, joinmarket_version):
        show_receipt("JMINITPROTO", nick_hash_length, nick_max_encoded,
                     joinmarket_nick_header, joinmarket_version)
        d = self.callRemote(commands.JMStartMC,
                            nick="dummynick")
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMUp.responder
    def on_JM_UP(self):
        show_receipt("JMUP")
        d = self.callRemote(commands.JMSetup,
                            role="TAKER",
                            initdata=None,
                            use_fidelity_bond=False)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSetupDone.responder
    def on_JM_SETUP_DONE(self):
        show_receipt("JMSETUPDONE")
        d = self.callRemote(commands.JMRequestOffers)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMFillResponse.responder
    def on_JM_FILL_RESPONSE(self, success, ioauth_data):
        show_receipt("JMFILLRESPONSE", success, ioauth_data)
        commands.callLater(1, self.maketx, ioauth_data)
        return {'accepted': True}

    def maketx(self, ioauth_data):
        nl = list(ioauth_data)
        d = self.callRemote(commands.JMMakeTx,
                            nick_list=nl,
                            tx=b"deadbeef")
        self.defaultCallbacks(d)

    @commands.JMOffers.responder
    def on_JM_OFFERS(self, orderbook, fidelitybonds):
        if end_early:
            return {'accepted': True}
        jlog.debug("JMOFFERS" + str(orderbook))
        # Trigger receipt of verified privmsgs, including unverified
        nick = str(list(t_chosen_orders.keys())[0])
        b64tx = base64.b64encode(b"deadbeef").decode('ascii')
        d1 = self.callRemote(commands.JMMsgSignatureVerify,
                             verif_result=True,
                             nick=nick,
                             fullmsg="!push " + b64tx + " abc def",
                             hostid="dummy")
        self.defaultCallbacks(d1)
        # unverified
        d2 = self.callRemote(commands.JMMsgSignatureVerify,
                             verif_result=False,
                             nick=nick,
                             fullmsg="!push " + b64tx + " abc def",
                             hostid="dummy")
        self.defaultCallbacks(d2)
        d = self.callRemote(commands.JMFill,
                            amount=100,
                            commitment="dummycommitment",
                            revelation="dummyrevelation",
                            filled_offers=t_chosen_orders)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSigReceived.responder
    def on_JM_SIG_RECEIVED(self, nick, sig):
        show_receipt("JMSIGRECEIVED", nick, sig)
        self.sigs_received += 1
        if self.sigs_received == 3:
            # end of test
            commands.callLater(1, end_test)
        return {'accepted': True}

    @commands.JMRequestMsgSig.responder
    def on_JM_REQUEST_MSGSIG(self, nick, cmd, msg, msg_to_be_signed, hostid):
        show_receipt("JMREQUESTMSGSIG", nick, cmd, msg, msg_to_be_signed,
                     hostid)
        d = self.callRemote(commands.JMMsgSignature,
                            nick=nick,
                            cmd=cmd,
                            msg_to_return="xxxcreatedsigxx",
                            hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMRequestMsgSigVerify.responder
    def on_JM_REQUEST_MSGSIG_VERIFY(self, msg, fullmsg, sig, pubkey, nick,
                                    hashlen, max_encoded, hostid):
        show_receipt("JMREQUESTMSGSIGVERIFY", msg, fullmsg, sig, pubkey,
                     nick, hashlen, max_encoded, hostid)
        d = self.callRemote(commands.JMMsgSignatureVerify,
                            verif_result=True,
                            nick=nick,
                            fullmsg=fullmsg,
                            hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}


class JMTestClientProtocolFactory:

    protocol = JMTestClientProtocol


def show_receipt(name, *args):
    jlog.debug("Received msgtype: " + name + ", args: " +
               ",".join([str(x) for x in args]))


def end_test():
    global test_completed
    test_completed = True


class JMDaemonTestServerProtocol(JMDaemonServerProtocol):

    def __init__(self, factory):
        super().__init__(factory)
        # respondtoioauths should do nothing unless jmstate = 2
        self.respondToIoauths(True)
        # calling on_JM_MAKE_TX should also do nothing in wrong state
        assert super().on_JM_MAKE_TX(1, 2) == {'accepted': False}
        # calling on_JM_FILL with negative amount should reject
        assert super().on_JM_FILL(-1000, 2, 3, 4) == {'accepted': False}
        # checkutxos also does nothing for rejection at the moment
        self.checkUtxosAccepted(False)
        # None should be returned requesting a cryptobox for an unknown cp
        assert self.get_crypto_box_from_nick("notrealcp") is not None
        # does nothing yet
        self.on_error("dummy error")

    @commands.JMRequestOffers.responder
    def on_JM_REQUEST_OFFERS(self):
        for o in t_orderbook:
            # counterparty, oid, ordertype, minsize, maxsize,txfee, cjfee):
            self.on_order_seen(o["counterparty"], o["oid"], o["ordertype"],
                               o["minsize"], o["maxsize"],
                               o["txfee"], o["cjfee"])
        return super().on_JM_REQUEST_OFFERS()

    @commands.JMInit.responder
    def on_JM_INIT(self, bcsource, network, chan_configs, minmakers,
                   maker_timeout_sec, dust_threshold, blacklist_location):
        self.maker_timeout_sec = maker_timeout_sec
        self.dust_threshold = int(dust_threshold)
        self.minmakers = minmakers
        mcs = [DummyMC(None)]
        self.mcc = MessageChannelCollection(mcs)
        # The following is a hack to get the counterparties marked seen/active;
        # note it must happen before callign set_msgchan for OrderbookWatch
        self.mcc.on_order_seen = None
        for c in [o['counterparty'] for o in t_orderbook]:
            self.mcc.on_order_seen_trigger(
                mcs[0], c, "a", "b", "c", "d", "e", "f")
        OrderbookWatch.set_msgchan(self, self.mcc)
        # register taker-specific msgchan callbacks here
        self.mcc.register_taker_callbacks(self.on_error, self.on_pubkey,
                                          self.on_ioauth, self.on_sig)
        self.mcc.set_daemon(self)
        self.restart_mc_required = True
        d = self.callRemote(commands.JMInitProto,
                            nick_hash_length=NICK_HASH_LENGTH,
                            nick_max_encoded=NICK_MAX_ENCODED,
                            joinmarket_nick_header=JOINMARKET_NICK_HEADER,
                            joinmarket_version=JM_VERSION)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMFill.responder
    def on_JM_FILL(self, amount, commitment, revelation, filled_offers):
        dummypub = ("073732a7ca60470f709f23c602b2b8a6"
                    "b1ba62ee8f3f83a61e5484ab5cbf9c3d")
        # trigger invalid on_pubkey conditions
        commands.callLater(1, self.on_pubkey, "notrealcp", dummypub)
        commands.callLater(2, self.on_pubkey, list(filled_offers)[0],
                           dummypub + "deadbeef")
        # trigger invalid on_ioauth condition
        commands.callLater(2, self.on_ioauth, "notrealcp", 1, 2, 3, 4, 5)
        # trigger msg sig verify request operation for a dummy message
        # currently a pass-through
        commands.callLater(1, self.request_signature_verify, "1",
                           "!push abcd abc def", "3", "4",
                           str(list(filled_offers)[0]), 6, 7,
                           self.mcc.mchannels[0].hostid)
        # send "valid" onpubkey, onioauth messages
        for k, v in filled_offers.items():
            commands.callLater(1, self.on_pubkey, k, dummypub)
            commands.callLater(2, self.on_ioauth, k, ['a', 'b'], "auth_pub",
                               "cj_addr", "change_addr", "btc_sig")
        return super().on_JM_FILL(amount, commitment, revelation,
                                  filled_offers)

    @commands.JMMakeTx.responder
    def on_JM_MAKE_TX(self, nick_list, tx):
        for n in nick_list:
            commands.callLater(1, self.on_sig, n, "dummytxsig")
        return super().on_JM_MAKE_TX(nick_list, tx)


class TrialTestJMDaemonProto(JMTestCase):

    async def test_waiter(self):
        return commands.deferLater(12, self._called_by_deffered)

    async def _called_by_deffered(self):
        pass


class TestJMDaemonProtoInit(JMTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        global end_early
        end_early = True

    async def test_waiter(self):
        return commands.deferLater(5, self._called_by_deffered)

    async def _called_by_deffered(self):
        global end_early
        end_early = False
