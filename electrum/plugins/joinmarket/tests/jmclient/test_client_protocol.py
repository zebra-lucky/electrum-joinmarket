# -*- coding: utf-8 -*-

'''test client-protocol interfacae.'''

import json
import base64

from electrum.logging import get_logger, ShortcutInjectingFilter

from electrum.plugins.joinmarket.jmbase import commands
from electrum.plugins.joinmarket.jmbase import bintohex
from electrum.plugins.joinmarket import jmbitcoin as bitcoin
from electrum.plugins.joinmarket.jmclient import (
    Taker, JMClientProtocolFactory, JMTakerClientProtocol)

from electrum.plugins.joinmarket.tests import JMTestCase

from .taker_test_data import t_raw_signed_tx
from .commontest import default_max_cj_fee


test_completed = False
clientfactory = None

LOGGING_SHORTCUT = 'J'
jlog = get_logger(__name__)
jlog.addFilter(ShortcutInjectingFilter(shortcut=LOGGING_SHORTCUT))


def dummy_taker_finished(res, fromtx, waittime=0.0):
    pass


class DummyTaker(Taker):

    def set_fail_init(self, val):
        self.failinit = val

    def set_fail_utxos(self, val):
        self.failutxos = val

    def default_taker_info_callback(self, infotype, msg):
        jlog.debug(infotype + ":" + msg)

    def initialize(self, orderbook, fidelity_bonds_info):
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

    def receive_utxos(self, ioauth_data):
        """Triggered when the daemon returns utxo data from
        makers who responded; this is the completion of phase 1
        of the protocol
        """
        if self.failutxos:
            return (False, "dummyreason")
        else:
            return (True, [x*64 + ":01" for x in ["a", "b", "c"]],
                    base64.b16decode(t_raw_signed_tx, casefold=True))

    def on_sig(self, nick, sigb64):
        """For test, we exit 'early' on first message, since this marks the end
        of client-server communication with the daemon.
        """
        jlog.debug("We got a sig: " + sigb64)
        end_test()
        return None


class DummyWallet(object):
    def get_wallet_id(self):
        return 'aaaa'


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


def end_client(client):
    pass


def end_test():
    global test_completed
    test_completed = True
    client = clientfactory.getClient()
    commands.callLater(1, end_client, client)


class JMTestServerProtocol(JMBaseProtocol):

    @commands.JMInit.responder
    def on_JM_INIT(self, bcsource, network, chan_configs, minmakers,
                   maker_timeout_sec, dust_threshold, blacklist_location):
        show_receipt("JMINIT", bcsource, network, chan_configs, minmakers,
                     maker_timeout_sec, dust_threshold, blacklist_location)
        d = self.callRemote(commands.JMInitProto,
                            nick_hash_length=1,
                            nick_max_encoded=2,
                            joinmarket_nick_header="J",
                            joinmarket_version=5)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMStartMC.responder
    def on_JM_START_MC(self, nick):
        show_receipt("STARTMC", nick)
        d = self.callRemote(commands.JMUp)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSetup.responder
    def on_JM_SETUP(self, role, initdata, use_fidelity_bond):
        show_receipt("JMSETUP", role, initdata, use_fidelity_bond)
        d = self.callRemote(commands.JMSetupDone)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMRequestOffers.responder
    def on_JM_REQUEST_OFFERS(self):
        show_receipt("JMREQUESTOFFERS")
        # build a huge orderbook to test BigString Argument
        orderbook = ["aaaa" for _ in range(15)]
        fidelitybonds = ["bbbb" for _ in range(15)]
        d = self.callRemote(commands.JMOffers,
                            orderbook=json.dumps(orderbook),
                            fidelitybonds=json.dumps(fidelitybonds))
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMFill.responder
    def on_JM_FILL(self, amount, commitment, revelation, filled_offers):
        success = False if amount == -1 else True
        show_receipt("JMFILL", amount, commitment, revelation, filled_offers)
        d = self.callRemote(commands.JMFillResponse,
                            success=success,
                            ioauth_data=['dummy', 'list'])
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMMakeTx.responder
    def on_JM_MAKE_TX(self, nick_list, tx):
        show_receipt("JMMAKETX", nick_list, tx)
        d = self.callRemote(commands.JMSigReceived,
                            nick="dummynick",
                            sig="xxxsig")
        self.defaultCallbacks(d)
        # add dummy calls to check message sign and message verify
        d2 = self.callRemote(commands.JMRequestMsgSig,
                             nick="dummynickforsign",
                             cmd="command1",
                             msg="msgforsign",
                             msg_to_be_signed="fullmsgforsign",
                             hostid="hostid1")
        self.defaultCallbacks(d2)
        # To test, this must include a valid ecdsa sig
        fullmsg = "fullmsgforverify"
        priv = b"\xaa"*32 + b"\x01"
        pub = bintohex(bitcoin.privkey_to_pubkey(priv))
        sig = bitcoin.ecdsa_sign(fullmsg, priv)
        d3 = self.callRemote(commands.JMRequestMsgSigVerify,
                             msg="msgforverify",
                             fullmsg=fullmsg,
                             sig=sig,
                             pubkey=pub,
                             nick="dummynickforverify",
                             hashlen=4,
                             max_encoded=5,
                             hostid="hostid2")
        self.defaultCallbacks(d3)
        d4 = self.callRemote(commands.JMSigReceived,
                             nick="dummynick",
                             sig="dummysig")
        self.defaultCallbacks(d4)
        return {'accepted': True}

    @commands.JMMsgSignature.responder
    def on_JM_MSGSIGNATURE(self, nick, cmd, msg_to_return, hostid):
        show_receipt("JMMSGSIGNATURE", nick, cmd, msg_to_return, hostid)
        return {'accepted': True}

    @commands.JMMsgSignatureVerify.responder
    def on_JM_MSGSIGNATURE_VERIFY(self, verif_result, nick, fullmsg, hostid):
        show_receipt("JMMSGSIGVERIFY", verif_result, nick, fullmsg, hostid)
        return {'accepted': True}


class JMTestServerProtocolFactory:

    protocol = JMTestServerProtocol


class DummyClientProtocolFactory(JMClientProtocolFactory):

    def buildProtocol(self):
        return JMTakerClientProtocol(self, self.client,
                                     nick_priv=b"\xaa"*32 + b"\x01")


class TrialTestJMClientProto(JMTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()

        global clientfactory
        params = [[False, False], [True, False], [False, True], [-1, False]]
        self.jmman.maker_timeout_sec = 1
        clientfactories = []
        takers = [
            DummyTaker(
                self.jmman,
                ["a", "b"], default_max_cj_fee,
                callbacks=(None, None, dummy_taker_finished))
            for _ in range(len(params))]
        for i, p in enumerate(params):
            takers[i].set_fail_init(p[0])
            takers[i].set_fail_utxos(p[1])
            takers[i].testflag = True
            if i != 0:
                clientfactories.append(JMClientProtocolFactory(takers[i]))
            else:
                clientfactories.append(DummyClientProtocolFactory(takers[i]))
                clientfactory = clientfactories[0]

    async def test_waiter(self):
        return commands.deferLater(3, self._called_by_deffered)

    async def _called_by_deffered(self):
        pass
