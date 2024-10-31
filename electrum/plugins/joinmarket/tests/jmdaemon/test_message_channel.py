# -*- coding: utf-8 -*-

'''test messagechannel management code.'''

import asyncio
import hashlib
import base64
import struct
import traceback
import threading

from unittest_parametrize import parametrize, ParametrizedTestCase

from electrum.bitcoin import base_encode
from electrum.logging import get_logger, ShortcutInjectingFilter

from electrum.plugins.joinmarket.jmdaemon import MessageChannelCollection
from electrum.plugins.joinmarket.jmdaemon.orderbookwatch import OrderbookWatch
from electrum.plugins.joinmarket.jmdaemon.protocol import (
    COMMAND_PREFIX, NICK_HASH_LENGTH, NICK_MAX_ENCODED, JM_VERSION,
    JOINMARKET_NICK_HEADER)
from electrum.plugins.joinmarket import jmbitcoin as bitcoin
from electrum.plugins.joinmarket.jmbase import bintohex
from electrum.plugins.joinmarket.jmclient import JMClientProtocolFactory
from electrum.plugins.joinmarket.tests import JMTestCase

from .msgdata import t_orderbook, t_chosen_orders
from .dummy_mc import DummyMessageChannel


# note: completely invalid sig is fine, as long as it's encoded right:
dummy_sig_str = (bintohex(b"\x02"*33) + " " +
                 base64.b64encode(b"\x01"*72).decode())


LOGGING_SHORTCUT = 'J'
jlog = get_logger(__name__)
jlog.addFilter(ShortcutInjectingFilter(shortcut=LOGGING_SHORTCUT))


def make_valid_nick(i=0):
    nick_priv = hashlib.sha256(struct.pack(b'B', i)*16).digest() + b"\x01"
    nick_pubkey = bitcoin.privkey_to_pubkey(nick_priv)
    nick_pkh_raw = hashlib.sha256(
        nick_pubkey.get_public_key_hex().encode()
    ).digest()[:NICK_HASH_LENGTH]
    nick_pkh = base_encode(nick_pkh_raw, base=58)
    # right pad to maximum possible; b58 is not fixed length.
    # Use 'O' as one of the 4 not included chars in base58.
    nick_pkh += 'O' * (NICK_MAX_ENCODED - len(nick_pkh))
    # The constructed length will be 1 + 1 + NICK_MAX_ENCODED
    return JOINMARKET_NICK_HEADER + str(JM_VERSION) + nick_pkh


class DummyClient:

    def __init__(self, jmman):
        self.jmman = jmman


class DummyBox(object):

    def encrypt(self, msg):
        return msg

    def decrypt(self, msg):
        return msg


class DaemonForSigns(object):
    """The following functions handle requests and responses
    from client for messaging signing and verifying.
    """
    def __init__(self, mcc):
        self.siglock = threading.Lock()
        self.mcc = mcc
        self.crypto_boxes = {}

    async def request_signed_message(self, nick, cmd, msg, msg_to_be_signed,
                                     hostid):
        with self.siglock:
            # Here we have to pretend we signed it and
            # send it to privmsg
            await self.mcc.privmsg(nick, cmd, msg, mc=hostid)

    async def request_signature_verify(self, msg, fullmsg, sig, pubkey, nick,
                                       hashlen, max_encoded, hostid):
        with self.siglock:
            # Here we must pretend we verified it and send it
            # to on_verified_privmsg
            await self.mcc.on_verified_privmsg(nick, fullmsg, hostid)

    def get_crypto_box_from_nick(self, nick):
        if nick in self.crypto_boxes and self.crypto_boxes[nick] is not None:
            return self.crypto_boxes[nick][1]  # libsodium encryption object
        else:
            jlog.debug('something wrong, no crypto object, nick=' + nick +
                       ', message will be dropped')


async def dummy_on_welcome():
    jlog.debug("On welcome called")


async def don_error():
    jlog.debug("called: " + traceback.extract_stack(None, 2)[0][2])


async def don_ioauth(nick, utxo_list, auth_pub, cj_addr, change_addr, btc_sig):
    jlog.debug("onioauth callback")
    jlog.debug("Args are: " + ",".join([str(x) for x in (nick,
                                        utxo_list, auth_pub, cj_addr,
                                        change_addr, btc_sig)]))


async def don_sig(nick, sig):
    jlog.debug("calledback on-sig")


don_pubkey = don_sig


class MsgChannelTestCase(JMTestCase, ParametrizedTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()

    async def test_setup_mc(self):
        ob = OrderbookWatch()
        ob.on_welcome = dummy_on_welcome
        dmcs = [DummyMessageChannel(self.jmman, None, hostid="hostid"+str(x))
                for x in range(3)]
        mcc = MessageChannelCollection(dmcs, self.jmman)
        # this sets orderbookwatch callbacks
        ob.set_msgchan(mcc)
        # we want to set all the callbacks, maker and taker
        mcc.register_taker_callbacks(don_error, don_pubkey, don_ioauth,
                                     don_sig)
        mcc.set_nick("testnick")
        dummydaemon = DaemonForSigns(mcc)
        dummy_client = DummyClient(self.jmman)
        clientfactory = JMClientProtocolFactory(dummy_client)
        self.jmman.set_client_factory(clientfactory)
        self.jmman.client_factory.proto_daemon = dummydaemon
        for mc in dmcs:
            await mc.on_welcome(mc)
        # instead of calling mcc.run, we'll start threads for mcs manually so
        # we can probe them

        async def run_mc(mc):
            asyncio.create_task(mc.run())

        for mc in dmcs:
            await run_mc(mc)
        for m in dmcs:
            await m.on_pubmsg("testmaker", "!orderbook")
        # receive invalid pubmsgs
        for msg in ["!orderbook!orderbook", "!notacommand a b c",
                    "no command prefix", "!reloffer 0 4000 5000 100"]:
            await dmcs[2].on_pubmsg("testmaker", msg)

        await mcc.request_orderbook()
        await mcc.pubmsg("outward pubmsg")
        # now create a verifiable counterparty nick;
        # to get it into active state, need to receive an orderbook from it
        cp1 = make_valid_nick()
        # Simulate order receipt on 2 of 3 msgchans from this nick;
        # note that it will have its active chan set to mc "1" because that
        # is the last it was seen on:
        await dmcs[0].on_privmsg(cp1, "!reloffer 0 4000 5000 100 0.2 " +
                                      dummy_sig_str)
        await dmcs[1].on_privmsg(cp1, "!reloffer 0 4000 5000 100 0.2 " +
                                      dummy_sig_str)
        await asyncio.sleep(0.5)
        # send back a response
        await mcc.privmsg(cp1, "fill", "0")
        # trigger failure to find nick in privmsg
        await mcc.privmsg(cp1+"XXX", "fill", "0")
        # trigger check_privmsg decorator
        await mcc.send_error(cp1, "errormsg")
        await mcc.push_tx(cp1, b"deadbeef")
        # kill the chan on which the cp is marked active;
        # note dummychannel has no actual shutdown (call it anyway),
        # so change its status manually.
        await dmcs[1].shutdown()
        mcc.mc_status[dmcs[1]] = 2
        await asyncio.sleep(0.5)
        # Flush removes references to inactive channels (in this case dmcs[1]).
        # Dynamic switching of cp1 should occur to the other
        # seen channel (dmcs[0]).
        mcc.flush_nicks()
        # force cp1 to be unseen on mc 0:
        await mcc.unsee_nick(cp1, dmcs[0])
        del mcc.active_channels[cp1]
        # try sending a privmsg again; this time it should just print a
        # warning, as cp1 is not seen anywhere
        await mcc.send_error(cp1, "error")
        # simulate order cancels (even though we have none)
        await mcc.cancel_orders([0, 1, 2])

        # let cp1 be seen on mc2 without having got into active channels;
        # note that this is an illegal pubmsg and is ignored for everything
        # *except* nick_seen (what we need here)
        await dmcs[2].on_pubmsg(cp1, "random")
        await mcc.send_error(cp1, "error")
        # Try using the proper way of setting up privsmgs
        # first try without box
        await mcc.prepare_privmsg(cp1, "auth", "a b c")
        dummydaemon.crypto_boxes[cp1] = ["a", DummyBox()]
        # now conditions are correct, should succeed:
        await mcc.prepare_privmsg(cp1, "auth", "a b c")
        # try again but this time there is no active channel
        del mcc.active_channels[cp1]
        await mcc.prepare_privmsg(cp1, "auth", "a b c")
        # try announcing orders; first public
        await mcc.announce_orders(t_orderbook, nick=None,
                                  fidelity_bond_proof_msg=None, new_mc=None)
        # try on fake mc
        await mcc.announce_orders(t_orderbook, nick=None,
                                  fidelity_bond_proof_msg=None,
                                  new_mc="fakemc")
        # direct to one cp
        await mcc.announce_orders(t_orderbook, nick=cp1,
                                  fidelity_bond_proof_msg=None,
                                  new_mc=None)
        # direct to one cp on one mc
        await mcc.announce_orders(t_orderbook, nick=cp1,
                                  fidelity_bond_proof_msg=None,
                                  new_mc=dmcs[0])
        # Next, set up 6 counterparties and fill their offers,
        # send txs to them
        cps = [make_valid_nick(i) for i in range(1, 7)]
        # reuse t_chosen_orders data, but swap out the counterparty names
        offervals = t_chosen_orders.values()
        new_offers = dict(zip(cps, offervals))
        # first, pretend they all showed up on all 3 mcs:
        for m in dmcs:
            for cp in cps:
                await m.on_privmsg(cp, "!reloffer 0 400000 500000 100 0.002 " +
                                   dummy_sig_str)
        await asyncio.sleep(0.5)
        # next, call main fill function
        await mcc.fill_orders(new_offers, 1000, "dummypubkey", "dummycommit")
        # now send a dummy transaction to this same set.
        # first fails with no crypto box.
        await mcc.send_tx(cps, b"deadbeef")
        # Now initialize the boxes
        for c in cps:
            dummydaemon.crypto_boxes[c] = ["a", DummyBox()]
        await mcc.send_tx(cps, b"deadbeef")
        # try to send the transaction to a wrong cp:
        await mcc.send_tx(["notrealcp"], b"deadbeef")

        # At this stage, dmcs0,2 should be "up" and 1 should be "down":
        assert mcc.mc_status[dmcs[0]] == 1
        assert mcc.mc_status[dmcs[1]] == 2
        assert mcc.mc_status[dmcs[2]] == 1
        # Not currently used:
        # simulate re-connection of dmcs[1] ; note that this code isn't used
        # atm
        # mcc.on_connect_trigger(dmcs[1])
        # assert mcc.mc_status[dmcs[1]] == 1
        # Now trigger disconnection code; each mc one by one;
        # the last should trigger on_disconnect callback
        for m in dmcs:
            await mcc.on_disconnect_trigger(m)
        # reconnect; effect is all nick references are flushed
        for m in dmcs:
            await mcc.on_connect_trigger(m)
        assert mcc.active_channels == {}
        # have the cps rearrive
        for m in dmcs:
            for cp in cps:
                await m.on_privmsg(cp, "!reloffer 0 4000 5000 100 0.2 " +
                                       dummy_sig_str)

        #####################################################################
        # next series of messages are to test various normal and abnormal
        # message receipts under normal connection conditions
        #####################################################################

        # simulate receipt of commitments
        # valid
        await dmcs[0].on_pubmsg(cps[2], "!hp2 deadbeef")
        # invalid missing field
        await dmcs[0].on_pubmsg(cps[2], "!hp2")
        # receive commitment via privmsg to trigger commitment_transferred
        await dmcs[0].on_privmsg(cps[2], "!hp2 deadbeef " + dummy_sig_str)
        # simulate receipt of order cancellation
        # valid
        await dmcs[0].on_pubmsg(cps[2], "!cancel 2")
        # invalid oid
        await dmcs[0].on_pubmsg(cps[2], "!cancel x")
        # too short privmsg (can't even have a signature)
        await dmcs[0].on_privmsg(cps[2], COMMAND_PREFIX)
        # not using correct protocol start character
        await dmcs[0].on_privmsg(cps[2], "A B C")
        # unrecognized command
        await dmcs[0].on_privmsg(cps[2], "!fakecommand A B C D")
        # Perhaps dubious, but currently msg after command must be non-zero
        await dmcs[0].on_privmsg(cps[2], "!reloffer sig1 sig2")
        # Simulating receipt of encrypted messages:
        # ioauth
        dummy_on_ioauth_msg = (b"deadbeef:0,deadbeef:1 XauthpubX"
                               b" XcjaddrX XchangeaddrX XbtcsigX")
        b64dummyioauth = base64.b64encode(dummy_on_ioauth_msg).decode('ascii')
        await dmcs[0].on_privmsg(cps[3], "!ioauth " + b64dummyioauth +
                                         " sig1 sig2")
        # Try with a garbage b64 (but decodable); should throw index error
        # at least
        await dmcs[0].on_privmsg(cps[3], "!ioauth _*_ sig1 sig2")
        # Try also for receipt from an unknown counterparty; should fail
        # with no enc box
        await dmcs[0].on_privmsg("notrealcp", "!ioauth " + b64dummyioauth +
                                              " sig1 sig2")
        # Try same message from valid cp but with corrupted b64
        b64dummyioauth = "999"
        await dmcs[0].on_privmsg(cps[3], "!ioauth " + b64dummyioauth +
                                         " sig1 sig2")
        # sig
        dummy_on_sig_msg = b"dummysig"
        b64dummysig = base64.b64encode(dummy_on_sig_msg).decode('ascii')
        await dmcs[0].on_privmsg(cps[3], "!sig " + b64dummysig + " sig1 sig2")
        # auth
        dummy_auth_msg = b"dummyauth"
        b64dummyauth = base64.b64encode(dummy_auth_msg).decode('ascii')
        await dmcs[0].on_privmsg(cps[2], "!auth " + b64dummyauth +
                                         " sig1 sig2")
        # invalid auth (only no message is invalid)
        await dmcs[0].on_privmsg(cps[3],
                                 "!auth " +
                                 base64.b64encode(b"").decode('ascii') +
                                 " sig1 sig2")
        # tx
        # valid
        dummy_tx = b"deadbeefdeadbeef"
        b64dummytx = base64.b64encode(dummy_tx)
        b642dummytx = base64.b64encode(b64dummytx).decode('ascii')
        await dmcs[0].on_privmsg(cps[2], "!tx " + b642dummytx + " sig1 sig2")
        badbase64tx = b"999"
        badbase64tx2 = base64.b64encode(badbase64tx).decode('ascii')
        # invalid txhex; here the first round will work (msg decryption),
        # second shouldn't
        await dmcs[0].on_privmsg(cps[2], "!tx " + badbase64tx2 + " sig1 sig2")
        # push
        # valid
        await dmcs[0].on_privmsg(cps[2], "!push " + b642dummytx + " sig1 sig2")
        # invalid
        await dmcs[0].on_privmsg(cps[2], "!push 999 sig1 sig2")
        # fill
        # valid, no commit
        await dmcs[0].on_privmsg(cps[4], "!fill 0 4000 dummypub sig1 sig2")
        # valid with commit
        await dmcs[0].on_privmsg(cps[4], "!fill 0 4000 dummypub dummycommit"
                                         " sig1 sig2")
        # invalid length
        await dmcs[0].on_privmsg(cps[4], "!fill 0 sig1 sig2")
        # pubkey
        await dmcs[0].on_privmsg(cps[4], "!pubkey dummypub sig1 sig2")
        ##############################################################
        # End message receipts
        ##############################################################

        # simulate loss of conncetion to cp[0]
        for m in dmcs[::-1]:
            await mcc.on_nick_leave_trigger(cps[0], m)
        # call onnickleave for something not in the ac list
        await mcc.on_nick_leave_trigger("notrealcp", dmcs[0])
        # make mcs 0,1 go down so that when cp[1] tries to dynamic switch,
        # it fails
        await mcc.on_disconnect_trigger(dmcs[0])
        await mcc.on_disconnect_trigger(dmcs[1])
        await mcc.on_nick_leave_trigger(cps[1], dmcs[2])
        await mcc.shutdown()

    @parametrize(
        "failuretype, mcindex, wait",
        [("shutdown", 0, 1),
         ("break", 1, 1),
         ("bad", 1, 1),
         ])
    async def test_mc_run(self, failuretype, mcindex, wait):
        ob = OrderbookWatch()
        ob.on_welcome = dummy_on_welcome
        dmcs = [DummyMessageChannel(self.jmman, None, hostid="hostid"+str(x))
                for x in range(3)]
        mcc = MessageChannelCollection(dmcs, self.jmman)
        # this sets orderbookwatch callbacks
        ob.set_msgchan(mcc)
        dummydaemon = DaemonForSigns(mcc)
        dummy_client = DummyClient(self.jmman)
        clientfactory = JMClientProtocolFactory(dummy_client)
        self.jmman.set_client_factory(clientfactory)
        self.jmman.client_factory.proto_daemon = dummydaemon

        async def run_mc(mcc):
            asyncio.create_task(mcc.run())

        await run_mc(mcc)
        await asyncio.sleep(wait+0.5)
