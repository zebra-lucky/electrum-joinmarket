# -*- coding: utf-8 -*-

import asyncio
import json
from functools import wraps

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..jmbase import commands
from .message_channel import MessageChannelCollection
from .orderbookwatch import OrderbookWatch
from .enc_wrapper import (as_init_encryption, init_keypair, init_pubkey,
                          X25519Error)
from .protocol import (COMMAND_PREFIX, FIDELITY_BOND_KEYS, ORDER_KEYS,
                       NICK_HASH_LENGTH, NICK_MAX_ENCODED, JM_VERSION,
                       JOINMARKET_NICK_HEADER)
from .irc import IRCMessageChannel
from .onionmc import OnionMessageChannel


def taker_only(func):
    @wraps(func)
    async def func_wrapper(inst, *args, **kwargs):
        if inst.role == "TAKER":
            return await func(inst, *args, **kwargs)
        return None
    return func_wrapper


class BaseServerProtocol(commands.CallRemoteMock):
    pass


class JMDaemonServerProtocol(BaseServerProtocol, OrderbookWatch):

    def __init__(self, factory, jmman):
        self.factory = factory
        self.jmman = jmman
        self.logger = jmman.logger
        self.jm_state = 0
        self.restart_mc_required = False
        self.chan_configs = None
        self.mcc = None
        # Default role is TAKER; must be overriden to MAKER in JMSetup message.
        self.role = "TAKER"
        self.crypto_boxes = {}
        self.sig_lock = asyncio.Lock()
        self.active_orders = {}
        self.use_fidelity_bond = False
        self.offerlist = None
        self.kp = None

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

    @commands.JMInit.responder
    async def on_JM_INIT(self, bcsource, network, chan_configs, minmakers,
                         maker_timeout_sec, dust_threshold,
                         blacklist_location):
        """Reads in required configuration from client for a new
        session; feeds back joinmarket messaging protocol constants
        (required for nick creation).
        If a new message channel configuration is required, the current
        one is shutdown in preparation.
        """
        self.maker_timeout_sec = maker_timeout_sec
        self.minmakers = minmakers
        self.dust_threshold = int(dust_threshold)
        # (bitcoin) network only referenced in channel name construction
        self.network = network
        if chan_configs == self.chan_configs:
            self.restart_mc_required = False
            self.logger.info("New init received did not require a new message"
                             " channel setup.")
        else:
            if self.chan_configs:
                # close the existing connections
                await self.mc_shutdown()
            self.chan_configs = chan_configs
            self.restart_mc_required = True
            mcs = []
            for c in self.chan_configs:
                if not c["enabled"]:
                    continue
                if "type" in c and c["type"] == "onion":
                    mcs.append(
                        OnionMessageChannel(self.jmman, c)
                    )
                else:
                    # default is IRC
                    mcs.append(
                        IRCMessageChannel(self.jmman, c,
                                          realname='btcint=' + bcsource)
                    )
            self.mcc = MessageChannelCollection(mcs, self.jmman)
            OrderbookWatch.set_msgchan(self, self.mcc)
            # register taker-specific msgchan callbacks here
            self.mcc.register_taker_callbacks(self.on_error, self.on_pubkey,
                                              self.on_ioauth, self.on_sig)
        d = await self.callRemote(
            commands.JMInitProto,
            self.factory.proto_client,
            nick_hash_length=NICK_HASH_LENGTH,
            nick_max_encoded=NICK_MAX_ENCODED,
            joinmarket_nick_header=JOINMARKET_NICK_HEADER,
            joinmarket_version=JM_VERSION
        )
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMStartMC.responder
    async def on_JM_START_MC(self, nick):
        """Starts message channel threads, if we are working with
        a new message channel configuration. Sets new nick if required.
        JM_UP will be called when the welcome messages are received.
        """
        await self.init_connections(nick)
        return {'accepted': True}

    @commands.JMSetup.responder
    async def on_JM_SETUP(self, role, initdata, use_fidelity_bond):
        assert self.jm_state == 0
        self.role = role
        self.crypto_boxes = {}
        self.kp = init_keypair()
        d = await self.callRemote(commands.JMSetupDone,
                                  self.factory.proto_client)
        self.defaultCallbacks(d)
        # Request orderbook here, on explicit setup request from client,
        # assumes messagechannels are in "up" state. Orders are read
        # in the callback on_order_seen in OrderbookWatch.
        # TODO: pubmsg should not (usually?) fire if already up
        # from previous run.
        if self.role == "TAKER":
            await self.mcc.pubmsg(COMMAND_PREFIX + "orderbook")
        elif self.role == "MAKER":
            self.offerlist = initdata
            self.use_fidelity_bond = use_fidelity_bond
            self.mcc.announce_orders(self.offerlist, None, None, None)
        self.jm_state = 1
        return {'accepted': True}

    @commands.JMMsgSignature.responder
    async def on_JM_MSGSIGNATURE(self, nick, cmd, msg_to_return, hostid):
        await self.mcc.privmsg(nick, cmd, msg_to_return, mc=hostid)
        return {'accepted': True}

    @commands.JMMsgSignatureVerify.responder
    async def on_JM_MSGSIGNATURE_VERIFY(self, verif_result, nick, fullmsg,
                                        hostid):
        if not verif_result:
            self.logger.info("Verification failed for nick: " + str(nick))
        else:
            await self.mcc.on_verified_privmsg(nick, fullmsg, hostid)
        return {'accepted': True}

    @commands.JMShutdown.responder
    async def on_JM_SHUTDOWN(self):
        await self.mc_shutdown()
        self.jm_state = 0
        return {'accepted': True}

    """Taker specific responders
    """

    @commands.JMRequestOffers.responder
    async def on_JM_REQUEST_OFFERS(self):
        """Reports the current state of the orderbook.
        This call is stateless."""
        self.orderbook = []
        for by_counterparty in self.ob.values():
            for by_oid in by_counterparty.values():
                self.orderbook.append(dict(zip(ORDER_KEYS, by_oid)))
        string_orderbook = json.dumps(self.orderbook)

        fidelitybonds = []
        for by_nick in self.fb.values():
            fidelitybonds.append(dict(zip(FIDELITY_BOND_KEYS, by_nick)))
        string_fidelitybonds = json.dumps(fidelitybonds)

        self.logger.info(f"About to send orderbook "
                         f"(size={len(self.orderbook)}) with fidelity bonds "
                         f"(size={len(fidelitybonds)})")
        d = await self.callRemote(commands.JMOffers,
                                  self.factory.proto_client,
                                  orderbook=string_orderbook,
                                  fidelitybonds=string_fidelitybonds)
        self.defaultCallbacks(d)
        return {'accepted': True}

    @commands.JMFill.responder
    async def on_JM_FILL(self, amount, commitment, revelation, filled_offers):
        """Takes the necessary data from the Taker and initiates the Stage 1
        interaction with the Makers.
        """
        if self.jm_state != 1 or amount < 0:
            return {'accepted': False}
        self.cjamount = amount
        self.commitment = commitment
        self.revelation = revelation
        # Reset utxo data to null for this new transaction
        self.ioauth_data = {}
        self.active_orders = filled_offers
        for nick, offer_dict in self.active_orders.items():
            pubk = self.kp.public_key()
            pubk_hex = pubk.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            offer_fill_msg = " ".join([
                str(offer_dict["oid"]),
                str(amount), pubk_hex,
                str(commitment)
            ])
            await self.mcc.prepare_privmsg(nick, "fill", offer_fill_msg)
        commands.callLater(self.maker_timeout_sec, self.completeStage1)
        self.jm_state = 2
        return {'accepted': True}

    @commands.JMMakeTx.responder
    async def on_JM_MAKE_TX(self, nick_list, tx):
        """Taker sends the prepared unsigned transaction
        to all the Makers in nick_list
        """
        if not self.jm_state == 4:
            self.logger.info("Make tx was called in wrong state, rejecting")
            return {'accepted': False}
        await self.mcc.send_tx(nick_list, tx)
        return {'accepted': True}

    @commands.JMPushTx.responder
    async def on_JM_PushTx(self, nick, tx):
        await self.mcc.push_tx(nick, tx)
        return {'accepted': True}

    """Message channel callbacks
    """

    async def on_welcome(self):
        """Fired when channel indicated state readiness
        """
        d = await self.callRemote(commands.JMUp, self.factory.proto_client)
        self.defaultCallbacks(d)

    @taker_only
    async def on_pubkey(self, nick, maker_pk):
        """This is handled locally in the daemon; set up e2e
        encrypted messaging with this counterparty
        """
        if nick not in self.active_orders.keys():
            self.logger.info("Counterparty not part of this transaction."
                             " Ignoring")
            return
        try:
            self.crypto_boxes[nick] = [maker_pk, as_init_encryption(
                self.kp, init_pubkey(maker_pk))]
        except X25519Error as e:
            print("Unable to setup crypto box with " + nick + ": " + repr(e))
            self.mcc.send_error(nick, "invalid nacl pubkey: " + maker_pk)
            return
        await self.mcc.prepare_privmsg(nick, "auth", str(self.revelation))

    @taker_only
    async def on_ioauth(self, nick, utxo_list, auth_pub, cj_addr, change_addr,
                        btc_sig):
        """Passes through to Taker the information from counterparties once
        they've all been received; note that we must also pass back
        the maker_pk so it can be verified against the btc-sigs for anti-MITM
        """
        if nick not in self.active_orders.keys():
            print("Got an unexpected ioauth from nick: " + str(nick))
            return
        self.ioauth_data[nick] = [utxo_list, auth_pub, cj_addr, change_addr,
                                  btc_sig, self.crypto_boxes[nick][0]]
        if self.ioauth_data.keys() == self.active_orders.keys():
            # Finish early if we got all
            await self.respondToIoauths(True)

    @taker_only
    async def on_sig(self, nick, sig):
        """Pass signature through to Taker.
        """
        d = await self.callRemote(commands.JMSigReceived,
                                  self.factory.proto_client,
                                  nick=nick, sig=sig)
        self.defaultCallbacks(d)

    def on_error(self, msg):
        self.logger.info("Received error: " + str(msg))

    """The following 2 functions handle requests and responses
    from client for messaging signing and verifying.
    """

    async def request_signed_message(self, nick, cmd, msg, msg_to_be_signed,
                                     hostid):
        """The daemon passes the nick and cmd fields
        to the client so it can be echoed back to the privmsg
        after return (with signature); note that the cmd is already
        inside "msg" after having been parsed in MessageChannel; this
        duplication is so that the client does not need to know the
        message syntax.
        """
        async with self.sig_lock:
            d = await self.callRemote(commands.JMRequestMsgSig,
                                      self.factory.proto_client,
                                      nick=str(nick),
                                      cmd=str(cmd),
                                      msg=str(msg),
                                      msg_to_be_signed=str(msg_to_be_signed),
                                      hostid=str(hostid))
            self.defaultCallbacks(d)

    async def request_signature_verify(self, msg, fullmsg, sig, pubkey, nick,
                                       hashlen, max_encoded, hostid):
        async with self.sig_lock:
            d = await self.callRemote(commands.JMRequestMsgSigVerify,
                                      self.factory.proto_client,
                                      msg=msg,
                                      fullmsg=fullmsg,
                                      sig=sig,
                                      pubkey=pubkey,
                                      nick=nick,
                                      hashlen=hashlen,
                                      max_encoded=max_encoded,
                                      hostid=hostid)
            self.defaultCallbacks(d)

    async def init_connections(self, nick):
        """Sets up message channel connections
        if they are not already up; re-sets joinmarket state to 0
        for a new transaction; effectively means any previous
        incomplete transaction is wiped.
        """
        self.jm_state = 0
        self.mcc.set_nick(nick)
        if self.restart_mc_required:
            await self.mcc.run()
            self.restart_mc_required = False
        else:
            # if we are not restarting the MC,
            # we must simulate the on_welcome message:
            await self.on_welcome()

    async def respondToIoauths(self, accepted):
        """Sends the full set of data from the Makers to the
        Taker after processing of first stage is completed,
        using the JMFillResponse command. But if the responses
        were not accepted (including, not sufficient number
        of responses), we send the list of Makers who did not
        respond to the Taker, instead of the ioauth data,
        so that the Taker can keep track of non-responders
        (although note this code is not yet quite ideal, see
        comments below).
        """
        if self.jm_state != 2:
            # this can be called a second time on timeout, in which case we
            # do nothing
            return
        self.jm_state = 3
        if not accepted:
            # use ioauth data field to return the list of non-responsive makers
            nonresponders = [x for x in self.active_orders
                             if x not in self.ioauth_data]
        ioauth_data = self.ioauth_data if accepted else nonresponders
        d = await self.callRemote(commands.JMFillResponse,
                                  self.factory.proto_client, success=accepted,
                                  ioauth_data=ioauth_data)
        if not accepted:
            # Client simply accepts failure TODO
            self.defaultCallbacks(d)
        else:
            # Act differently if *we* provided utxos, but
            # client does not accept for some reason
            d.addCallback(self.checkUtxosAccepted)
            d.addErrback(self.defaultErrback)

    async def completeStage1(self):
        """Timeout of stage 1 requests;
        either send success + ioauth data if enough makers,
        else send failure to client.
        """
        response = True if len(self.ioauth_data) >= self.minmakers else False
        await self.respondToIoauths(response)

    def checkUtxosAccepted(self, accepted):
        if not accepted:
            self.logger.info("Taker rejected utxos provided; resetting.")
            # TODO create re-set function to start again
        else:
            # only update state if client accepted
            self.jm_state = 4

    def get_crypto_box_from_nick(self, nick):
        """Retrieve the libsodium box object for the counterparty;
        stored differently for Taker and Maker
        """
        if nick in self.crypto_boxes and self.crypto_boxes[nick] is not None:
            return self.crypto_boxes[nick][1]
        elif (nick in self.active_orders
                and self.active_orders[nick] is not None
                and "crypto_box" in self.active_orders[nick]):
            return self.active_orders[nick]["crypto_box"]
        else:
            self.logger.info('something wrong, no crypto object, nick=' +
                             nick + ', message will be dropped')
            return None

    async def mc_shutdown(self, shutdown_unavailable=False):
        self.logger.info("Message channels being shutdown by daemon")
        if self.mcc:
            await self.mcc.shutdown(shutdown_unavailable=shutdown_unavailable)
