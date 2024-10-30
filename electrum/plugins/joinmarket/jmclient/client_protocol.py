# -*- coding: utf-8 -*-

import json
import hashlib
import os

from electrum.bitcoin import base_encode

from .. import jmbitcoin as btc
from ..jmbase import commands
from ..jmbase import hextobin, bintohex
from ..jmdaemon import JMDaemonServerProtocol


class BaseClientProtocol(commands.CallRemoteMock):

    def checkClientResponse(self, response):
        """A generic check of client acceptance; any failure
        is considered criticial.
        """
        if 'accepted' not in response or not response['accepted']:
            self.logger.error(f'checkClientResponse not accepted: {response}')
            raise Exception(response)

    def defaultErrback(self, failure):
        raise failure

    def defaultCallbacks(self, d):
        d.addCallback(self.checkClientResponse)
        d.addErrback(self.defaultErrback)


class JMClientProtocol(BaseClientProtocol):

    def __init__(self, factory, client, nick_priv=None):
        self.client = client
        self.factory = factory
        if not nick_priv:
            self.nick_priv = hashlib.sha256(
                os.urandom(16)).digest() + b"\x01"
        else:
            self.nick_priv = nick_priv

    def connectionMade(self):
        self.logger.debug('connection was made, starting client.')

    def set_nick(self):
        """ Algorithm: take pubkey and hex-serialized it;
        then SHA2(hexpub) but truncate output to nick_hashlen.
        Then encode to a base58 string (no check).
        Then prepend J and version char (e.g. '5').
        Finally append padding to nick_maxencoded (+2).
        """
        self.nick_pubkey = btc.privkey_to_pubkey(self.nick_priv)
        # note we use binascii hexlify directly here because input
        # to hashing must be encoded.
        self.nick_pkh_raw = hashlib.sha256(
            self.nick_pubkey.get_public_key_hex().encode()
        ).digest()[:self.nick_hashlen]
        self.nick_pkh = base_encode(self.nick_pkh_raw, base=58)
        # right pad to maximum possible; b58 is not fixed length.
        # Use 'O' as one of the 4 not included chars in base58.
        self.nick_pkh += 'O' * (self.nick_maxencoded - len(self.nick_pkh))
        # The constructed length will be 1 + 1 + NICK_MAX_ENCODED
        self.nick = self.nick_header + str(self.jm_version) + self.nick_pkh
        informuser = getattr(self.client, "inform_user_details", None)
        if callable(informuser):
            informuser()

    @commands.JMInitProto.responder
    async def on_JM_INIT_PROTO(self, nick_hash_length, nick_max_encoded,
                               joinmarket_nick_header, joinmarket_version):
        """Daemon indicates init-ed status and passes back protocol constants.
        Use protocol settings to set actual nick from nick private key,
        then call setup to instantiate message channel connections
        in the daemon.
        """
        self.nick_hashlen = nick_hash_length
        self.nick_maxencoded = nick_max_encoded
        self.nick_header = joinmarket_nick_header
        self.jm_version = joinmarket_version
        self.set_nick()
        d = await self.callRemote(commands.JMStartMC, self.proto_daemon,
                                  nick=self.nick)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMRequestMsgSig.responder
    async def on_JM_REQUEST_MSGSIG(self, nick, cmd, msg, msg_to_be_signed,
                                   hostid):
        sig = btc.ecdsa_sign(str(msg_to_be_signed), self.nick_priv)
        msg_to_return = (str(msg) + " " +
                         bintohex(self.nick_pubkey.get_public_key_bytes()) +
                         " " + sig)
        d = await self.callRemote(commands.JMMsgSignature, self.proto_daemon,
                                  nick=nick,
                                  cmd=cmd,
                                  msg_to_return=msg_to_return,
                                  hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMRequestMsgSigVerify.responder
    async def on_JM_REQUEST_MSGSIG_VERIFY(self, msg, fullmsg, sig, pubkey,
                                          nick, hashlen, max_encoded, hostid):
        pubkey_bin = hextobin(pubkey)
        verif_result = True
        if not btc.ecdsa_verify(str(msg), sig, pubkey_bin):
            # workaround for hostid, which sometimes is lowercase-only
            # for some IRC connections
            if (not btc.ecdsa_verify(str(msg[:-len(hostid)] + hostid.lower()),
                                     sig, pubkey_bin)):
                self.logger.debug("nick signature verification failed,"
                                  " ignoring: " + str(nick))
                verif_result = False
        # check that nick matches hash of pubkey
        nick_pkh_raw = hashlib.sha256(
            pubkey.encode("ascii")
        ).digest()[:hashlen]
        nick_stripped = nick[2:2 + max_encoded]
        # strip right padding
        nick_unpadded = ''.join([x for x in nick_stripped if x != 'O'])
        if not nick_unpadded == base_encode(nick_pkh_raw, base=58):
            self.logger.debug("Nick hash check failed, expected: " +
                              str(nick_unpadded) + ", got: " +
                              str(btc.base58.encode(nick_pkh_raw)))
            verif_result = False
        d = await self.callRemote(commands.JMMsgSignatureVerify,
                                  self.proto_daemon,
                                  verif_result=verif_result,
                                  nick=nick,
                                  fullmsg=fullmsg,
                                  hostid=hostid)
        self.defaultCallbacks(d)
        return {'accepted': True}

    async def make_tx(self, nick_list, tx):
        d = await self.callRemote(commands.JMMakeTx, self.proto_daemon,
                                  nick_list=nick_list,
                                  tx=tx)
        self.defaultCallbacks(d)

    async def request_mc_shutdown(self):
        """ To ensure that lingering message channel
        connections are shut down when the client itself
        is shutting down.
        """
        d = await self.callRemote(commands.JMShutdown, self.proto_daemon)
        self.defaultCallbacks(d)
        return {'accepted': True}


class JMTakerClientProtocol(JMClientProtocol):

    def __init__(self, factory, client, nick_priv=None):
        self.orderbook = None
        self.jmman = client.jmman
        self.logger = self.jmman.logger
        self.proto_daemon = factory.proto_daemon
        JMClientProtocol.__init__(self, factory, client, nick_priv)

    async def clientStart(self):
        """Upon confirmation of network connection
        to daemon, request message channel initialization
        with relevant config data for our message channels
        """
        if self.client.aborted:
            return
        jmman = self.jmman
        # needed only for naming convention in IRC currently
        blockchain_source = jmman.jmconf.BLOCKCHAIN_SOURCE
        # needed only for channel naming convention
        network = jmman.jmconf.blockchain_network
        chan_configs = self.factory.get_mchannels(mode="TAKER")
        minmakers = jmman.jmconf.minimum_makers
        maker_timeout_sec = jmman.jmconf.maker_timeout_sec

        # To avoid creating yet another config variable, we set the timeout
        # to 20 * maker_timeout_sec.
        if not hasattr(self.client, 'testflag'):  # pragma: no cover
            commands.callLater(20*maker_timeout_sec, self.stallMonitor,
                               self.client.schedule_index+1)

        d = await self.callRemote(commands.JMInit, self.proto_daemon,
                                  bcsource=blockchain_source,
                                  network=network,
                                  chan_configs=chan_configs,
                                  minmakers=minmakers,
                                  maker_timeout_sec=maker_timeout_sec,
                                  dust_threshold=jmman.jmconf.DUST_THRESHOLD,
                                  blacklist_location=None)
        self.defaultCallbacks(d)

    def stallMonitor(self, schedule_index):
        """Diagnoses whether long wait is due to any kind of failure;
        if so, calls the taker on_finished_callback with a failure
        flag so that the transaction can be re-tried or abandoned, as desired.
        Note that this *MUST* not trigger any action once the
        coinjoin transaction is seen on the network (hence waiting_for_conf).
        The schedule index parameter tells us whether the processing has moved
        on to the next item before we were woken up.
        """
        self.logger.info("STALL MONITOR:")
        if self.client.aborted:
            self.logger.info("Transaction was aborted.")
            return
        if not self.client.schedule_index == schedule_index:
            # TODO pre-initialize() ?
            self.logger.info("No stall detected, continuing")
            return
        if self.client.waiting_for_conf:
            # Don't restart if the tx is already on the network!
            self.logger.info("No stall detected, continuing")
            return
        if not self.client.txid:
            # txid is set on pushing; if it's not there, we have failed.
            self.logger.info("Stall detected. Retrying transaction"
                             " if possible ...")
            self.client.on_finished_callback(False, True, 0.0)
        else:
            # This shouldn't really happen; if the tx confirmed,
            # the finished callback should already be called.
            self.logger.info("Tx was already pushed; ignoring")

    @commands.JMUp.responder
    async def on_JM_UP(self):
        d = await self.callRemote(commands.JMSetup, self.proto_daemon,
                                  role="TAKER",
                                  initdata=None,
                                  use_fidelity_bond=False)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSetupDone.responder
    async def on_JM_SETUP_DONE(self):
        self.logger.info("JM daemon setup complete")
        # The daemon is ready and has requested the orderbook
        # from the pit; we can request the entire orderbook
        # and filter it as we choose.
        commands.callLater(self.jmman.jmconf.maker_timeout_sec,
                           self.get_offers)
        return {'accepted': True}

    @commands.JMFillResponse.responder
    async def on_JM_FILL_RESPONSE(self, success, ioauth_data):
        """Receives the entire set of phase 1 data (principally utxos)
        from the counterparties and passes through to the Taker for
        tx construction. If there were sufficient makers, data is passed
        over for exactly those makers that responded. If not, the list
        of non-responsive makers is added to the permanent "ignored_makers"
        list, but the Taker processing is bypassed and the transaction
        is abandoned here (so will be picked up as stalled in multi-join
        schedules).
        In the first of the above two cases, after the Taker processes
        the ioauth data and returns the proposed
        transaction, passes the phase 2 initiating data to the daemon.
        """
        if not success:
            self.logger.info("Makers who didnt respond: " + str(ioauth_data))
            self.client.add_ignored_makers(ioauth_data)
            return {'accepted': True}
        else:
            self.logger.info("Makers responded with: " + str(ioauth_data))
            retval = await self.client.receive_utxos(ioauth_data)
            if not retval[0]:
                self.logger.info("Taker is not continuing, phase 2 abandoned.")
                self.logger.info("Reason: " + str(retval[1]))
                if len(self.client.schedule) == 1:
                    # see comment for the same invocation in on_JM_OFFERS;
                    # the logic here is the same.
                    self.client.on_finished_callback(False, False, 0.0)
                return {'accepted': False}
            else:
                nick_list, tx = retval[1:]
                commands.callLater(0, self.make_tx, nick_list, tx)
                return {'accepted': True}

    @commands.JMOffers.responder
    async def on_JM_OFFERS(self, orderbook, fidelitybonds):
        self.orderbook = json.loads(orderbook)
        fidelity_bonds_list = json.loads(fidelitybonds)
        # Removed for now, as judged too large, even for DEBUG:
        # self.logger.debug("Got the orderbook: " + str(self.orderbook))
        retval = await self.client.initialize(self.orderbook,
                                              fidelity_bonds_list)
        # format of retval is:
        # True, self.cjamount, commitment, revelation, self.filtered_orderbook)
        if not retval[0]:
            self.logger.info("Taker not continuing after receipt of orderbook")
            if len(self.client.schedule) == 1:
                # In single sendpayments, allow immediate quit.
                # This could be an optional feature also for multi-entry
                # schedules, but is not the functionality
                # desiredin general (tumbler).
                self.client.on_finished_callback(False, False, 0.0)
            return {'accepted': True}
        elif retval[0] == "commitment-failure":
            # This case occurs if we cannot find any utxos for reasons
            # other than age, which is a permanent failure
            self.client.on_finished_callback(False, False, 0.0)
            return {'accepted': True}
        amt, cmt, rev, foffers = retval[1:]
        d = await self.callRemote(commands.JMFill, self.proto_daemon,
                                  amount=amt,
                                  commitment=str(cmt),
                                  revelation=str(rev),
                                  filled_offers=foffers)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMSigReceived.responder
    async def on_JM_SIG_RECEIVED(self, nick, sig):
        retval = await self.client.on_sig(nick, sig)
        if retval:
            nick_to_use, tx = retval
            await self.push_tx(nick_to_use, tx)
        return {'accepted': True}

    async def get_offers(self):
        d = await self.callRemote(commands.JMRequestOffers, self.proto_daemon)
        self.defaultCallbacks(d)

    async def push_tx(self, nick_to_push, tx):
        d = await self.callRemote(commands.JMPushTx, self.proto_daemon,
                                  nick=str(nick_to_push), tx=tx)
        self.defaultCallbacks(d)


class JMClientProtocolFactory:

    protocol = JMTakerClientProtocol

    def __init__(self, client, proto_type="TAKER"):
        self.client = client
        self.jmman = client.jmman
        self.proto_client = None
        self.proto_daemon = JMDaemonServerProtocol(self, client.jmman)
        self.proto_type = proto_type
        self.setClient(self.buildProtocol())

    def setClient(self, client):
        self.proto_client = client

    def getClient(self):
        return self.proto_client

    def buildProtocol(self):
        proto_client = self.protocol(self, self.client)
        proto_client.connectionMade()
        return proto_client

    def get_mchannels(self, mode):
        """ A transparent wrapper that allows override,
        so that a script can return a customised set of
        message channel configs; currently used for testing
        multiple bots on regtest.
        """
        return list(self.jmman.jmconf.get_msg_channels().values())
