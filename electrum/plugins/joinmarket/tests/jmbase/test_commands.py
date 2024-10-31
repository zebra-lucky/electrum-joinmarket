# -*- coding: utf-8 -*-

import json

from electrum.plugins.joinmarket.jmbase import commands
from electrum.plugins.joinmarket.tests import JMTestCase


test_completed = False


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


def show_receipt(name, *args):
    print("Received msgtype: " + name + ", args: " +
          ",".join([str(x) for x in args]))


def end_test():
    global test_completed
    test_completed = True


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
        orderbook = ["aaaa" for _ in range(2**15)]
        d = self.callRemote(commands.JMOffers,
                            orderbook=json.dumps(orderbook),
                            fidelitybonds="dummyfidelitybonds")
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMFill.responder
    def on_JM_FILL(self, amount, commitment, revelation, filled_offers):
        show_receipt("JMFILL", amount, commitment, revelation, filled_offers)
        d = self.callRemote(commands.JMFillResponse,
                            success=True,
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
        d3 = self.callRemote(commands.JMRequestMsgSigVerify,
                             msg="msgforverify",
                             fullmsg="fullmsgforverify",
                             sig="xxxsigforverify",
                             pubkey="pubkey1",
                             nick="dummynickforverify",
                             hashlen=4,
                             max_encoded=5,
                             hostid="hostid2")
        self.defaultCallbacks(d3)
        # d4 = self.callRemote(commands.JMTXBroadcast, tx=b"deadbeef")
        # FIXME self.defaultCallbacks(d4)
        return {'accepted': True}

    @commands.JMMsgSignature.responder
    def on_JM_MSGSIGNATURE(self, nick, cmd, msg_to_return, hostid):
        show_receipt("JMMSGSIGNATURE", nick, cmd, msg_to_return, hostid)
        return {'accepted': True}

    @commands.JMMsgSignatureVerify.responder
    def on_JM_MSGSIGNATURE_VERIFY(self, verif_result, nick, fullmsg, hostid):
        show_receipt("JMMSGSIGVERIFY", verif_result, nick, fullmsg, hostid)
        return {'accepted': True}


class JMTestClientProtocol(JMBaseProtocol):

    def connectionMade(self):
        self.clientStart()

    def clientStart(self):
        d = self.callRemote(commands.JMInit,
                            bcsource="dummyblockchain",
                            network="dummynetwork",
                            chan_configs=['dummy', 'irc', 'config'],
                            minmakers=7,
                            maker_timeout_sec=8,
                            dust_threshold=1500,
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
        d = self.callRemote(commands.JMMakeTx,
                            nick_list=['nick1', 'nick2', 'nick3'],
                            tx=b"deadbeef")
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMOffers.responder
    def on_JM_OFFERS(self, orderbook, fidelitybonds):
        show_receipt("JMOFFERS", orderbook, fidelitybonds)
        d = self.callRemote(commands.JMFill,
                            amount=100,
                            commitment="dummycommitment",
                            revelation="dummyrevelation",
                            filled_offers=['list', 'of', 'filled', 'offers'])
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSigReceived.responder
    def on_JM_SIG_RECEIVED(self, nick, sig):
        show_receipt("JMSIGRECEIVED", nick, sig)
        # end of test
        commands.callLater(1, end_test)
        return {'accepted': True}

    @commands.JMRequestMsgSig.responder
    def on_JM_REQUEST_MSGSIG(self, nick, cmd, msg, msg_to_be_signed, hostid):
        show_receipt(
            "JMREQUESTMSGSIG", nick, cmd, msg, msg_to_be_signed, hostid)
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

    # @commands.JMTXBroadcast.responder  FIXME
    # def on_JM_TX_BROADCAST(self, tx):
    #     show_receipt("JMTXBROADCAST", tx)
    #     return {"accepted": True}


class JMTestClientProtocolFactory:

    protocol = JMTestClientProtocol


class JMTestServerProtocolFactory:

    protocol = JMTestServerProtocol


class TrialTestJMProto(JMTestCase):

    async def test_waiter(self):
        return commands.deferLater(3, self._called_by_deffered)

    async def _called_by_deffered(self):
        pass
