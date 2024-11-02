# -*- coding: utf-8 -*-

import asyncio
import json
import copy
import random

from typing import Callable, Union, Tuple, List
from aiorpcx import SOCKSFailure

from ..jmbase import JM_APP_NAME
from ..jmbase.commands import callLater
from .message_channel import MessageChannel
from .protocol import COMMAND_PREFIX, JM_VERSION
from .twisted_line_receiver import LineReceiver
from .onionmc_support import TorClientService


NOT_SERVING_ONION_HOSTNAME = "NOT-SERVING-ONION"

# LongLivedPort
ONION_VIRTUAL_PORT = 5222

# How many seconds to wait before treating an onion
# as unreachable
CONNECT_TO_ONION_TIMEOUT = 60


def location_tuple_to_str(t: Tuple[str, int]) -> str:
    return f"{t[0]}:{t[1]}"


"""
Messaging protocol (which wraps the underlying Joinmarket
messaging protocol) used here is documented in:
Joinmarket-Docs/onion-messaging.md
"""

LOCAL_CONTROL_MESSAGE_TYPES = {
    "connect": 785,
    "disconnect": 787,
    "connect-in": 797,
}
CONTROL_MESSAGE_TYPES = {
    "peerlist": 789,
    "getpeerlist": 791,
    "handshake": 793,
    "dn-handshake": 795,
    "ping": 797,
    "pong": 799,
    "disconnect": 801,
}
JM_MESSAGE_TYPES = {
    "privmsg": 685,
    "pubmsg": 687,
}


# Used for some control message construction, as detailed below.
NICK_PEERLOCATOR_SEPARATOR = ";"


# location_string, nick and network must be set before sending,
# otherwise invalid:
client_handshake_json = {
    "app-name": JM_APP_NAME,
    "directory": False,
    "location-string": "",
    "proto-ver": JM_VERSION,
    "features": {},
    "nick": "",
    "network": "",
}


# default acceptance false; code must switch it on:
server_handshake_json = {
    "app-name": JM_APP_NAME,
    "directory": True,
    "proto-ver-min": JM_VERSION,
    "proto-ver-max": JM_VERSION,
    "features": {},
    "accepted": False,
    "nick": "",
    "network": "",
    "motd": "Default MOTD, replace with information for the directory."
}


# states that keep track of relationship to a peer
PEER_STATUS_UNCONNECTED, PEER_STATUS_CONNECTED, PEER_STATUS_HANDSHAKED, \
    PEER_STATUS_DISCONNECTED = range(4)


class OnionPeerError(Exception):
    pass


class OnionPeerDirectoryWithoutHostError(OnionPeerError):
    pass


class OnionPeerConnectionError(OnionPeerError):
    pass


class OnionCustomMessageDecodingError(Exception):
    pass


class InvalidLocationStringError(Exception):
    pass


class OnionDirectoryPeerNotFound(Exception):
    pass


class OnionCustomMessage(object):
    """ Encapsulates the messages passed over the wire
    to and from other onion peers
    """
    def __init__(self, text: str, msgtype: int):
        self.text = text
        self.msgtype = msgtype

    def encode(self) -> bytes:
        self.encoded = json.dumps({
            "type": self.msgtype,
            "line": self.text,
        }).encode("utf-8")
        return self.encoded

    @classmethod
    def from_string_decode(cls, msg: bytes) -> 'OnionCustomMessage':
        """ Build a custom message from a json-ified string.
        """
        try:
            msg_obj = json.loads(msg)
            text = msg_obj["line"]
            msgtype = msg_obj["type"]
            # we insist on integer but not a valid msgtype,
            # crudely 'syntax, not semantics':
            # semantics is the job of the OnionMessageChannel object.
            assert isinstance(msgtype, int)
            assert isinstance(text, str)
        except BaseException:
            # this blanket catch and re-raise:
            # we must handle untrusted input bytes without
            # crashing under any circumstance.
            raise OnionCustomMessageDecodingError
        return cls(text, msgtype)


class OnionLineProtocol(LineReceiver):
    # there are messages requiring more than LineReceiver's 16KB,
    # specifically, large coinjoin transaction `pushtx` messages.
    # 40K is finger in the air for: 500bytes per participant, 40
    # participants, and a double base64 expansion (x1.33 and x1.33)
    # which gives 35.5K, add a little breathing room.
    MAX_LENGTH = 40000

    def connection_made(self, transport):
        self.transport = transport
        self.factory.register_connection(self)
        LineReceiver.connection_made(self, transport)

    def connection_lost(self, exc):
        self.factory.register_disconnection(self)
        LineReceiver.connection_lost(self, exc)

    def line_received(self, line: bytes) -> None:
        try:
            msg = OnionCustomMessage.from_string_decode(line)
        except OnionCustomMessageDecodingError:
            self.factory.logger.debug(f"Received invalid message: {line},"
                                      f" dropping connection.")
            self.transport.close()
            return
        self.factory.receive_message(msg, self)

    def message(self, message: OnionCustomMessage) -> None:
        self.send_line(message.encode())


class OnionClientFactory:
    """ We define a distinct protocol factory for outbound connections.
    Notably, this factory supports only *one* protocol instance at a time.
    """
    protocol = OnionLineProtocol

    def __init__(self, message_receive_callback: Callable,
                 connection_callback: Callable,
                 disconnection_callback: Callable,
                 message_not_sendable_callback: Callable,
                 directory: bool,
                 mc: 'OnionMessageChannel'):
        self.proto_client = None
        # callback takes OnionCustomMessage as arg and returns None
        self.message_receive_callback = message_receive_callback
        # connection callback, no args, returns None
        self.connection_callback = connection_callback
        # disconnection the same
        self.disconnection_callback = disconnection_callback
        # a callback that can be fired if we are not able to send messages,
        # no args, returns None
        self.message_not_sendable_callback = message_not_sendable_callback
        # is this connection to a directory?
        self.directory = directory
        # to keep track of state of overall messagechannel
        self.mc = mc
        self.jmman = mc.jmman
        self.logger = mc.logger

    def buildProtocol(self):
        p = self.protocol()
        p.factory = self
        return p

    def register_connection(self, p: OnionLineProtocol) -> None:
        self.proto_client = p
        callLater(0, self.connection_callback)

    def register_disconnection(self, p: OnionLineProtocol) -> None:
        self.proto_client = None
        callLater(0, self.disconnection_callback)

    def send(self, msg: OnionCustomMessage) -> bool:
        # we may be sending at the time the counterparty
        # disconnected
        if not self.proto_client:
            self.message_not_sendable_callback()
            return False
        self.proto_client.message(msg)
        # Unlike the serving protocol, the client protocol
        # is never in a condition of not knowing the counterparty
        return True

    def receive_message(self, message: OnionCustomMessage,
                        p: OnionLineProtocol) -> None:
        callLater(0, self.message_receive_callback, message)


class OnionPeer:
    """ Class encapsulating a peer we connect to.
    """

    def __init__(self, messagechannel: 'OnionMessageChannel',
                 socks5_host: str, socks5_port: int,
                 location_tuple: Tuple[str, int],
                 directory: bool = False, nick: str = "",
                 handshake_callback: Callable = None):
        self.client_service_cls = TorClientService
        # reference to the managing OnionMessageChannel instance is
        # needed so that we know where to send the messages received
        # from this peer:
        self.jmman = messagechannel.jmman
        self.logger = messagechannel.logger
        self.messagechannel = messagechannel
        self.nick = nick
        # client side net config:
        self.socks5_host = socks5_host
        self.socks5_port = socks5_port
        # remote net config:
        self.hostname = location_tuple[0]
        self.port = location_tuple[1]
        # alternate location strings are used for inbound
        # connections for this peer (these will be used by
        # directories and onion-serving peers, sending
        # messages backwards on a connection created towards them).
        self.alternate_location = ""
        self.directory = directory
        self._status = PEER_STATUS_UNCONNECTED
        # A function to be called to initiate a handshake;
        # it should take a single argument, an OnionPeer object,
        # and return None.
        self.handshake_callback = handshake_callback
        # Keep track of the protocol factory used to connect
        # to the remote peer. Note that this won't always be used,
        # if we have an inbound connection from this peer:
        self.factory = None
        # the reconnecting service allows auto-reconnection to
        # some peers:
        self.reconnecting_service = None
        # don't try to connect more than once
        # TODO: prefer state machine update
        self.connecting = False

    def update_status(self, destn_status: int) -> None:
        """ Wrapping state updates to enforce:
        (a) that the handshake is triggered by connection
        outwards, and (b) to ensure no illegal state transitions.
        """
        assert destn_status in range(4)
        ignored_updates = []
        if self._status == PEER_STATUS_UNCONNECTED:
            allowed_updates = [PEER_STATUS_CONNECTED]
        elif self._status == PEER_STATUS_CONNECTED:
            # updates from connected->connected are harmless
            allowed_updates = [PEER_STATUS_CONNECTED,
                               PEER_STATUS_DISCONNECTED,
                               PEER_STATUS_HANDSHAKED]
        elif self._status == PEER_STATUS_HANDSHAKED:
            allowed_updates = [PEER_STATUS_DISCONNECTED]
            ignored_updates = [PEER_STATUS_CONNECTED]
        elif self._status == PEER_STATUS_DISCONNECTED:
            allowed_updates = [PEER_STATUS_CONNECTED]
            ignored_updates = [PEER_STATUS_DISCONNECTED]
        if destn_status in ignored_updates:
            self.logger.debug(f"Attempt to update status of peer from"
                              f" {self._status} to {destn_status} ignored.")
            return
        assert destn_status in allowed_updates, (f"couldn't update state from"
                                                 f" {self._status} to"
                                                 f" {destn_status}")
        self._status = destn_status
        # the handshakes are always initiated by a client:
        if destn_status == PEER_STATUS_CONNECTED:
            self.connecting = False
            self.logger.info(
                f"We, {self.messagechannel.self_as_peer.peer_location()},"
                f" are calling the handshake callback as client.")
            self.handshake_callback(self)

    def status(self) -> int:
        """ Simple getter function for the wrapped _status:
        """
        return self._status

    def set_nick(self, nick: str) -> None:
        self.nick = nick

    def get_nick_peerlocation_ser(self) -> str:
        if not self.nick:
            raise OnionPeerError("Cannot serialize "
                                 "identifier string without nick.")
        return (self.nick + NICK_PEERLOCATOR_SEPARATOR +
                self.peer_location())

    @classmethod
    def from_location_string(
            cls, mc: 'OnionMessageChannel',
            location: str,
            socks5_host: str,
            socks5_port: int,
            directory: bool = False,
            handshake_callback: Callable = None) -> 'OnionPeer':
        """ Allows construction of an OnionPeer from the
        connection information given by the network interface.
        TODO: special handling for inbound is needed.
        """
        try:
            host, port = location.split(":")
            portint = int(port)
        except BaseException:
            raise InvalidLocationStringError(location)
        return cls(mc, socks5_host, socks5_port,
                   (host, portint), directory=directory,
                   handshake_callback=handshake_callback)

    def set_location(self, location_string: str) -> bool:
        """ Allows setting location from an unchecked
        input string argument.
        If the location is specified as the 'no serving' case,
        we put the currently existing inbound connection as the alternate
        location, and the NOT_SERVING const as the 'location', returning True.
        If the string does not have the required format, will return False,
        otherwise self.hostname, self.port are
        updated for future `peer_location` calls, and True is returned.
        """
        if location_string == NOT_SERVING_ONION_HOSTNAME:
            self.set_alternate_location(location_tuple_to_str(
                (self.hostname, self.port)))
            self.hostname = NOT_SERVING_ONION_HOSTNAME
            self.port = -1
            return True
        try:
            host, port = location_string.split(":")
            portint = int(port)
            assert portint > 0
        except Exception as e:
            self.logger.debug(f"Failed to update host and port of this peer,"
                              f" error: {repr(e)}")
            return False
        self.hostname = host
        self.port = portint
        return True

    def peer_location(self) -> str:
        if self.hostname == NOT_SERVING_ONION_HOSTNAME:
            # special case for non-reachable peers, which can include
            # self_as_peer: we just return this string constant
            return NOT_SERVING_ONION_HOSTNAME
        # in every other case we need a sensible port/host combo:
        assert (self.port > 0 and self.hostname)
        return location_tuple_to_str((self.hostname, self.port))

    def send(self, message: OnionCustomMessage) -> bool:
        """ If the message can be sent on either an inbound or
        outbound connection, True is returned, else False.
        """
        return self.factory.send(message)

    async def receive_message(self, message: OnionCustomMessage) -> None:
        await self.messagechannel.receive_msg(message, self.peer_location())

    def notify_message_unsendable(self):
        """ Triggered by a failure to send a message on the network,
        by the encapsulated ClientFactory. Just used to notify calling
        code; no action is triggered.
        """
        name = "directory" if self.directory else "peer"
        self.logger.warning(f"Failure to send message to {name}:"
                            f" {self.peer_location()}.")

    def connect(self) -> None:
        """ This method is called to connect, over Tor, to the remote
        peer at the given onion host/port.
        """
        if self.connecting:
            return
        self.connecting = True
        if self._status in [PEER_STATUS_HANDSHAKED, PEER_STATUS_CONNECTED]:
            return
        if not (self.hostname and self.port > 0):
            raise OnionPeerConnectionError(
                "Cannot connect without host, port info")

        self.factory = OnionClientFactory(
            self.receive_message, self.register_connection,
            self.register_disconnection, self.notify_message_unsendable,
            self.directory, self.messagechannel)
        # non-default timeout; needs to be much lower than our
        # 'wait at least a minute for the IRC connections to come up',
        # which is used for *all* message channels, together.
        self.reconnecting_service = self.client_service_cls(
            self.factory, CONNECT_TO_ONION_TIMEOUT,
            self.socks5_host, self.socks5_port, self.hostname, self.port)
        # if we want to actually do something about an unreachable host,
        # we have to force t.a.i.ClientService to give up after the timeout
        d = self.reconnecting_service.whenConnected(failAfterFailures=1)
        d.addCallbacks(self.respond_to_connection_success,
                       self.respond_to_connection_failure)
        self.reconnecting_service.startService()

    def respond_to_connection_success(self, proto) -> None:
        self.connecting = False

    def respond_to_connection_failure(self, failure) -> None:
        self.connecting = False
        # the error will be one of these if we just fail
        # to connect to the other side.
        if not isinstance(failure, (ConnectionRefusedError, SOCKSFailure)):
            raise failure
        comment = "" if self.directory else "; giving up."
        self.logger.info(f"Failed to connect to peer"
                         f" {self.peer_location()}{comment}")
        self.reconnecting_service.stopService()

    async def register_connection(self) -> None:
        await self.messagechannel.register_connection(self.peer_location(),
                                                      direction=1)

    async def register_disconnection(self) -> None:
        # for non-directory peers, just stop
        self.reconnecting_service.stopService()
        await self.messagechannel.register_disconnection(self.peer_location())

    def try_to_connect(self) -> None:
        """ This method wraps OnionPeer.connect and accepts
        any error if that fails.
        """
        try:
            self.connect()
        except OnionPeerConnectionError as e:
            # Note that this will happen naturally for non-serving peers.
            # TODO remove message or change it.
            self.logger.debug(f"Tried to connect but failed: {repr(e)}")
        except Exception as e:
            self.logger.warning(f"Got unexpected exception in connect"
                                f" attempt: {repr(e)}")

    def disconnect(self) -> None:
        if self._status in [PEER_STATUS_UNCONNECTED, PEER_STATUS_DISCONNECTED]:
            return
        if not (self.hostname and self.port > 0):
            raise OnionPeerConnectionError(
                "Cannot disconnect without host, port info")
        d = self.reconnecting_service.stopService()
        d.addCallback(self.complete_disconnection)

    def complete_disconnection(self, r) -> None:
        self.logger.debug(f"Disconnected from peer: {self.peer_location()}")
        self.update_status(PEER_STATUS_DISCONNECTED)
        self.factory = None


class OnionPeerPassive(OnionPeer):
    """ a type of remote peer that we are
        not interested in connecting outwards to.
    """
    def try_to_connect(self) -> None:
        pass


class OnionDirectoryPeer(OnionPeer):
    delay = 4.0

    def try_to_connect(self) -> None:
        # Delay deliberately expands out to very
        # long times as yg-s tend to be very long
        # running bots:
        # We will only expand delay 20 times max
        # (4 * 1.5^19 = 8867.3)
        if self.delay < 8868:
            self.delay *= 1.5
        # randomize by a few seconds to minimize bursty-ness locally
        jitter = random.randint(-1, 5)
        self.logger.info(
            f"Going to reattempt connection to {self.peer_location()} in "
            f"{self.delay + jitter} seconds.")
        callLater(self.delay + jitter, self.connect)

    async def register_connection(self) -> None:
        self.messagechannel.update_directory_map(self, connected=True)
        await super().register_connection()

    async def register_disconnection(self) -> None:
        self.messagechannel.update_directory_map(self, connected=False)
        await super().register_disconnection()

        if self.messagechannel.give_up:
            return
        # for directory peers, we persist in trying to establish
        # a connection, but with backoff:
        self.try_to_connect()

    def respond_to_connection_failure(self, failure) -> None:
        super().respond_to_connection_failure(failure)

        if self.messagechannel.give_up:
            return
        # same logic as for register_disconnection
        self.try_to_connect()


class OnionMessageChannel(MessageChannel):
    """ Sends messages to other nodes of the same type over Tor
    via SOCKS5.
    *Optionally*: Receives messages via a Torv3 hidden/onion service.
    If no onion service, it means we only have connections outbound
    to other onion services (directory nodes first, others if and
    when they send us a privmsg.).
    Uses one or more configured "directory nodes" (which could be us)
    to access a list of current active nodes, and updates
    dynamically from messages seen.
    """

    def __init__(self, jmman, configdata):
        self.jmman = jmman
        self.logger = jmman.logger
        MessageChannel.__init__(self)
        # hostid is a feature to avoid replay attacks across message channels;
        # TODO investigate, but for now, treat onion-based as one "server".
        self.hostid = "onion-network"
        self.btc_network = jmman.jmconf.blockchain_network
        # receives notification that we are shutting down
        self.give_up = False
        # for backwards compat: make sure MessageChannel log can refer to
        # this in dynamic switch message:
        self.serverport = self.hostid
        # client side config:
        self.socks5_host = configdata["socks5_host"]
        self.socks5_port = configdata["socks5_port"]
        # passive configuration is for bots who never need/want to connect
        # to peers (apart from directories)
        self.passive = False
        if "passive" in configdata:
            self.passive = configdata["passive"]
        # keep track of peers. the list will be instances
        # of OnionPeer:
        self.peers = set()
        for dn in [x.strip()
                   for x in configdata["directory_nodes"].split(",")]:
            # note we don't use a nick for directories:
            try:
                self.peers.add(
                    OnionDirectoryPeer.from_location_string(
                        self, dn, self.socks5_host, self.socks5_port,
                        directory=True,
                        handshake_callback=self.handshake_as_client))
            except InvalidLocationStringError as e:
                self.logger.error(f"Failed to load directory nodes: {repr(e)}")
                return
        # dummy 'hostname' to indicate we can start running immediately:
        self.onion_hostname = NOT_SERVING_ONION_HOSTNAME

        # waiting loop for all directories to have
        # connected (note we could use a deferred but
        # the rpc connection calls are not using twisted)
        self.wait_for_directories_fut = jmman.loop.create_future()

        # this dict plays the same role as `active_channels` in
        # `MessageChannelCollection`.
        # it has structure {nick1: {}, nick2: {}, ...} where the inner dicts
        # are: # {OnionDirectoryPeer1: bool, OnionDirectoryPeer2: bool, ...}.
        # Entries get updated with changing connection status of directories,
        # allowing us to decide where to send each message we want to send when
        # we have no direct connection.
        self.active_directories = {}

    def info_callback(self, msg: str) -> None:
        self.logger.info(msg)

    def setup_error_callback(self, msg: str) -> None:
        self.logger.error(msg)

    def shutdown_callback(self, msg: str) -> None:
        self.logger.info("in shutdown callback: {}".format(msg))

# ABC implementation section
    async def run(self, for_obwatch=False) -> None:
        while True:
            if not self.peers:
                break

            if self.check_onion_hostname():
                # at this point the only peers added are directory
                # nodes from config; we try to connect to all.
                # We will get other peers to add to our list once they
                # start sending us messages.
                if not await self.connect_to_directories() and for_obwatch:
                    await self.shutdown()
                break
            await asyncio.sleep(0.5)

    async def shutdown(self) -> None:
        self.give_up = True
        for p in self.peers:
            if p.reconnecting_service:
                p.reconnecting_service.stopService()

    def get_pubmsg(self, msg: str, source_nick: str = "") -> str:
        """ Converts a message into the known format for
        pubmsgs; if we are not sending this (because we
        are a directory, forwarding it), `source_nick` must be set.
        Note that pubmsg does NOT prefix the *message* with COMMAND_PREFIX.
        """
        nick = source_nick if source_nick else self.nick
        return nick + COMMAND_PREFIX + "PUBLIC" + msg

    def get_privmsg(self, nick: str, cmd: str, message: str,
                    source_nick=None) -> str:
        """ See `get_pubmsg` for comment on `source_nick`.
        """
        from_nick = source_nick if source_nick else self.nick
        return (from_nick + COMMAND_PREFIX + nick + COMMAND_PREFIX +
                cmd + " " + message)

    async def _pubmsg(self, msg: str) -> None:
        """ Best effort broadcast of message `msg`:
        send the message to every known directory node,
        with the PUBLIC message type and nick.
        """
        dps = self.get_directory_peers()
        msg = OnionCustomMessage(self.get_pubmsg(msg),
                                 JM_MESSAGE_TYPES["pubmsg"])
        for dp in dps:
            self._send(dp, msg)

    def should_try_to_connect(self, peer: OnionPeer) -> bool:
        if not peer:
            return False
        if peer.peer_location() == NOT_SERVING_ONION_HOSTNAME:
            return False
        if peer.directory:
            return False
        if peer == self.self_as_peer:
            return False
        if peer.status() in [PEER_STATUS_CONNECTED, PEER_STATUS_HANDSHAKED]:
            return False
        return True

    async def _privmsg(self, nick: str, cmd: str, msg: str) -> None:
        encoded_privmsg = OnionCustomMessage(
            self.get_privmsg(nick, cmd, msg), JM_MESSAGE_TYPES["privmsg"])
        peer_exists = self.get_peer_by_nick(nick, conn_only=False)
        peer_sendable = self.get_peer_by_nick(nick)
        # opportunistically connect to peers that have talked to us
        # (evidenced by the peer existing, which must be because we got
        # a `peerlist` message for it), and that we want to talk to
        # (evidenced by the call to this function)
        if self.should_try_to_connect(peer_exists):
            callLater(0.0, peer_exists.try_to_connect)
        if not peer_sendable:
            # If we are trying to message a peer via their nick, we
            # may not yet have a connection; then we just
            # forward via directory nodes.
            self.logger.debug(f"Privmsg peer: {nick} but don't have peerid;"
                              f" sending via directory.")
            try:
                peer_sendable = self.get_directory_for_nick(nick)
            except OnionDirectoryPeerNotFound:
                self.logger.warning("Failed to send privmsg because no"
                                    " directory peer is connected.")
                return
        self._send(peer_sendable, encoded_privmsg)

    async def _announce_orders(self, offerlist: list) -> None:
        for offer in offerlist:
            await self._pubmsg(offer)

# End ABC implementation section

    def check_onion_hostname(self) -> bool:
        if not self.onion_hostname:
            return False
        # now our hidden service is up, we must check our peer status
        # then set up directories.
        self.get_our_peer_info()
        return True

    def get_my_location_tuple(self) -> Tuple[str, int]:
        return (self.onion_hostname, -1)

    def get_our_peer_info(self) -> None:
        """ Create a special OnionPeer object,
        outside of our peerlist, to refer to ourselves.
        """
        self_dir = False
        # only for publicly exposed onion does the 'virtual port' exist;
        # for local tests we always connect to an actual machine port:
        my_location_tuple = self.get_my_location_tuple()
        self.self_as_peer = OnionPeer(self, self.socks5_host, self.socks5_port,
                                      my_location_tuple,
                                      self_dir, nick=self.nick,
                                      handshake_callback=None)

    async def connect_to_directories(self) -> bool:
        # the remaining code is only executed by non-directories:
        for p in self.peers:
            self.logger.info(f"Trying to connect to node: {p.peer_location()}")
            try:
                p.connect()
            except OnionPeerConnectionError:
                pass
        # do not trigger on_welcome event until all directories
        # configured are ready:
        self.on_welcome_sent = False
        self.directory_wait_counter = 0
        while True:
            await self.wait_for_directories()
            if self.wait_for_directories_fut.done():
                return self.wait_for_directories_fut.result()
            await asyncio.sleep(2.0)

    def handshake_as_client(self, peer: OnionPeer) -> None:
        assert peer.status() == PEER_STATUS_CONNECTED
        our_hs = copy.deepcopy(client_handshake_json)
        our_hs["location-string"] = self.self_as_peer.peer_location()
        our_hs["nick"] = self.nick
        our_hs["network"] = self.btc_network
        our_hs_json = json.dumps(our_hs)
        self.logger.info("Sending this handshake: {} to peer {}".format(
            our_hs_json, peer.peer_location()))
        self._send(peer,
                   OnionCustomMessage(our_hs_json,
                                      CONTROL_MESSAGE_TYPES["handshake"]))

    def get_directory_peers(self) -> list:
        return [p for p in self.peers if p.directory is True]

    def get_peer_by_nick(self, nick: str,
                         conn_only: bool = True) -> Union[OnionPeer, None]:
        """ Return an OnionPeer object matching the given Joinmarket
        nick; if `conn_only` is True, we restrict to only those peers
        in state PEER_STATUS_HANDSHAKED, else we allow any peer.
        If no such peer can be found, return None.
        """
        plist = self.get_all_connected_peers() if conn_only else self.peers
        for p in plist:
            if p.nick == nick:
                return p

    def _send(self, peer: OnionPeer, message: OnionCustomMessage) -> bool:
        try:
            return peer.send(message)
        except Exception as e:
            # This can happen when a peer disconnects, depending
            # on the timing:
            self.logger.warning(f"Failed to send message to: "
                                f"{peer.peer_location()}, error: {repr(e)}")
            return False

    async def receive_msg(self, message: OnionCustomMessage,
                          peer_location: str) -> None:
        """ Messages from peers and also connection related control
        messages. These messages either come via OnionPeer.
        """
        peer = self.get_peer_by_id(peer_location)
        if not peer:
            self.logger.warning(f"Received message but could not find peer:"
                                f" {peer_location}")
            return
        msgtype = message.msgtype
        msgval = message.text
        if msgtype in LOCAL_CONTROL_MESSAGE_TYPES.values():
            await self.process_control_message(peer_location, msgtype, msgval)
            # local control messages are processed first.
            # TODO this is a historical artifact, we can simplify.
            return

        if await self.process_control_message(peer_location, msgtype, msgval):
            # will return True if it is, elsewise, a control message.
            return

        # ignore non-JM messages:
        if msgtype not in JM_MESSAGE_TYPES.values():
            self.logger.debug(f"Invalid message type, ignoring: {msgtype}")
            return

        # real JM message; should be: from_nick, to_nick, cmd, message
        try:
            nicks_msgs = msgval.split(COMMAND_PREFIX)
            from_nick, to_nick = nicks_msgs[:2]
            msg = COMMAND_PREFIX + COMMAND_PREFIX.join(nicks_msgs[2:])
            if to_nick == "PUBLIC":
                await self.on_pubmsg(from_nick, msg)
            elif to_nick != self.nick:
                self.logger.debug(f"Ignoring message, not for us: {msg}")
            else:
                await self.on_privmsg(from_nick, msg)
        except Exception as e:
            self.logger.debug(f"Invalid Joinmarket message: {msgval},"
                              f" error was: {repr(e)}")
        # add the nick to the directories map, whether pubmsg or privmsg, but
        # only if it passed the above syntax Exception catch:
        if peer.directory:
            if from_nick not in self.active_directories:
                self.active_directories[from_nick] = {}
            self.active_directories[from_nick][peer] = True

    def update_directory_map(self, p: OnionDirectoryPeer,
                             connected: bool) -> None:
        nicks = []
        for nick in self.active_directories:
            if p in self.active_directories[nick]:
                nicks.append(nick)
        for nick in nicks:
            self.active_directories[nick][p] = connected

    def get_directory_for_nick(self, nick: str) -> OnionDirectoryPeer:
        if nick not in self.active_directories:
            raise OnionDirectoryPeerNotFound
        adn = self.active_directories[nick]
        if len(adn) == 0:
            raise OnionDirectoryPeerNotFound
        candidates = [x for x in list(adn) if adn[x] is True]
        if len(candidates) == 0:
            raise OnionDirectoryPeerNotFound
        return random.choice(candidates)

    async def on_nick_leave_directory(self, nick: str,
                                      dir_peer: OnionPeer) -> None:
        """ This is called in response to a disconnection control
        message from a directory, telling us that a certain nick has left.
        We update this connection status in the active_directories map,
        and fire the MessageChannel.on_nick_leave when we see all the
        connections are lost.
        Note that `on_nick_leave` can be triggered in two ways; both here,
        and also via `self.register_disconnection`, which occurs for peers
        to whom we are directly connected. Calling it multiple times is not
        harmful, but remember that the on_nick_leave event only bubbles up
        above the message channel layer once *all* message channels trigger
        on_nick_leave (in case we are using another message channel as well
        as this one, like IRC).
        """
        if nick not in self.active_directories:
            return
        if dir_peer not in self.active_directories[nick]:
            self.logger.debug(f"Directory {dir_peer.peer_location()} is"
                              f" telling us that {nick} has left, but we"
                              f" didn't know about them. Ignoring.")
            return
        self.logger.debug(f"Directory {dir_peer.peer_location()} has lost"
                          f" connection to: {nick}")
        self.active_directories[nick][dir_peer] = False
        if not any(self.active_directories[nick].values()):
            await self.on_nick_leave(nick, self)

    async def process_control_message(self, peerid: str, msgtype: int,
                                      msgval: str) -> bool:
        """ Triggered by a directory node feeding us
        peers, or by a connect/disconnect hook; this is our housekeeping
        to try to create, and keep track of, useful connections.
        The returned boolean indicates whether we succeeded in processing
        the message or whether it must be analyzed again (note e.g. that
        we return True for a rejected message!)
        """
        all_ctrl = list(LOCAL_CONTROL_MESSAGE_TYPES.values(
            )) + list(CONTROL_MESSAGE_TYPES.values())
        if msgtype not in all_ctrl:
            return False
        # this is too noisy, but TODO, investigate allowing
        # some kind of control message monitoring e.g. default-off
        # log-to-file (we don't currently have a 'TRACE' level debug).
        # self.logger.debug(f"received control message: {msgtype},{msgval}")
        if msgtype == CONTROL_MESSAGE_TYPES["peerlist"]:
            # This is the base method of seeding connections;
            # a directory node can send this any time.
            # These messages can only be accepted from directory peers
            # (which we have configured ourselves):
            peer = self.get_peer_by_id(peerid)
            if not peer or not peer.directory:
                return True
            try:
                peerlist = msgval.split(",")
                for peer_in_list in peerlist:
                    # directories should send us peerstrings that include
                    # nick;host:port;D where "D" indicates that the directory
                    # is signalling this peer as having left. Otherwise,
                    # without # the third field, we treat it as a "join" event.
                    try:
                        nick, hostport, disconnect_code = peer_in_list.split(
                            NICK_PEERLOCATOR_SEPARATOR)
                        if disconnect_code != "D":
                            continue
                        await self.on_nick_leave_directory(nick, peer)
                        continue
                    except ValueError:
                        # just means this message is not of the
                        # 'disconnect' type
                        pass
                    # defaults mean we just add the peer, not
                    # add or alter its connection status:
                    self.add_peer(peer_in_list, with_nick=True)
            except Exception as e:
                self.logger.debug(f"Incorrectly formatted peer list:"
                                  f" {msgval}, ignoring, {e}")
            # returning True whether raised or not - see docstring
            return True
        elif msgtype == CONTROL_MESSAGE_TYPES["getpeerlist"]:
            self.logger.warning("getpeerlist request received, currently"
                                " not supported.")
            return True
        elif msgtype == CONTROL_MESSAGE_TYPES["handshake"]:
            # sent by non-directory peers on startup, also to
            # other non-dn peers during tx flow
            self.process_handshake(peerid, msgval)
            return True
        elif msgtype == CONTROL_MESSAGE_TYPES["dn-handshake"]:
            self.process_handshake(peerid, msgval, dn=True)
            return True
        elif msgtype == LOCAL_CONTROL_MESSAGE_TYPES["connect"]:
            self.add_peer(msgval, connection=True,
                          overwrite_connection=True)
        elif msgtype == LOCAL_CONTROL_MESSAGE_TYPES["connect-in"]:
            self.add_peer(msgval, connection=True,
                          overwrite_connection=True)
        elif msgtype == LOCAL_CONTROL_MESSAGE_TYPES["disconnect"]:
            self.logger.debug("We got a disconnect event: {}".format(msgval))
            if msgval in [x.peer_location()
                          for x in self.get_connected_directory_peers()]:
                # we need to use the full peer locator string, so that
                # add_peer knows it can try to reconnect:
                msgval = self.get_peer_by_id(msgval).peer_location()
            self.add_peer(msgval, connection=False,
                          overwrite_connection=True)
            # bubble up the disconnection event to the abstract
            # message channel logic:
            if self.on_nick_leave:
                p = self.get_peer_by_id(msgval)
                if p and p.nick:
                    callLater(0.0, self.on_nick_leave, p.nick, self)
        else:
            assert False
        # If we got here it is *not* a non-local control message;
        # so we must process it as a Joinmarket message.
        return False

    def process_handshake(self, peerid: str, message: str,
                          dn: bool = False) -> None:
        peer = self.get_peer_by_id(peerid)
        if not peer:
            # rando sent us a handshake?
            self.logger.warning(f"Unexpected handshake from unknown peer:"
                                f" {peerid}, ignoring.")
            return
        assert isinstance(peer, OnionPeer)
        if not peer.status() == PEER_STATUS_CONNECTED:
            # we were not waiting for it:
            self.logger.warning(f"Unexpected handshake from peer: {peerid},"
                                f" ignoring. Peer's current status is:"
                                f" {peer.status()}")
            return
        if dn:
            # it means, we are a non-dn and we are expecting
            # a returned `dn-handshake` message:
            # (currently dns don't talk to other dns):
            if not peer.directory:
                # got dn-handshake from non-dn:
                self.logger.warning(f"Unexpected dn-handshake from non-dn "
                                    f"node: {peerid}, ignoring.")
                return
            # we got the right message from the right peer;
            # check it is formatted correctly and represents
            # acceptance of the connection
            try:
                handshake_json = json.loads(message)
                app_name = handshake_json["app-name"]
                is_directory = handshake_json["directory"]
                proto_min = handshake_json["proto-ver-min"]
                proto_max = handshake_json["proto-ver-max"]
                features = handshake_json["features"]
                accepted = handshake_json["accepted"]
                nick = handshake_json["nick"]
                net = handshake_json["network"]
                assert isinstance(proto_max, int)
                assert isinstance(proto_min, int)
                assert isinstance(features, dict)
                assert isinstance(nick, str)
                assert isinstance(net, str)
            except Exception as e:
                self.logger.warning(f"Invalid handshake message from: "
                                    f"{peerid}, exception: {repr(e)}, "
                                    f"message: {message}, ignoring")
                return
            # currently we are not using any features, but the intention
            # is forwards compatibility, so we don't check its contents
            # at all.
            if not accepted:
                self.logger.warning(f"Directory: {peerid} rejected"
                                    f" our handshake.")
                # explicitly choose to disconnect (if other side already did,
                # this is no-op).
                peer.disconnect()
                return
            if not (app_name == JM_APP_NAME and is_directory and JM_VERSION
                    <= proto_max and JM_VERSION >= proto_min and accepted):
                self.logger.warning(f"Handshake from directory is incompatible"
                                    f" or rejected: {handshake_json}")
                peer.disconnect()
                return
            if not net == self.btc_network:
                self.logger.warning(f"Handshake from directory is on an"
                                    f" incompatible network: {net}")
                return
            # We received a valid, accepting dn-handshake. Update the peer.
            peer.update_status(PEER_STATUS_HANDSHAKED)
            peer.set_nick(nick)
        else:
            # it means, we are receiving an initial handshake
            # message from a 'client' (non-dn) peer.
            # dns don't talk to each other:
            assert not peer.directory
            accepted = True
            try:
                handshake_json = json.loads(message)
                app_name = handshake_json["app-name"]
                is_directory = handshake_json["directory"]
                proto_ver = handshake_json["proto-ver"]
                features = handshake_json["features"]
                full_location_string = handshake_json["location-string"]
                nick = handshake_json["nick"]
                net = handshake_json["network"]
                assert isinstance(proto_ver, int)
                assert isinstance(features, dict)
                assert isinstance(nick, str)
                assert isinstance(net, str)
            except Exception as e:
                self.logger.warning(f"(not dn) Invalid handshake message from:"
                                    f" {peerid}, exception: {repr(e)}, "
                                    f"message: {message}, ignoring")
                # just ignore, since a syntax failure could lead to a crash
                return
            if not (app_name == JM_APP_NAME and proto_ver == JM_VERSION
                    and not is_directory):
                self.logger.warning(f"Invalid handshake name/version data: "
                                    f"{message}, from peer: {peerid}, "
                                    f"rejecting.")
                accepted = False
            if not net == self.btc_network:
                self.logger.warning(f"Handshake from peer is on an "
                                    f"incompatible network: {net}")
                accepted = False
            # If accepted, we should update the peer to have the full
            # location which in general will not yet be present, so as to
            # allow publishing their location via `getpeerlist`. Note
            # that if the peer declares itself as not serving, we do
            # nothing here:
            if not peer.set_location(full_location_string):
                accepted = False
            if peerid != full_location_string:
                peer.set_alternate_location(peerid)
            peer.set_nick(nick)
            # client peer's handshake message was valid; send ours, and
            # then mark this peer as successfully handshaked:
            our_hs = copy.deepcopy(server_handshake_json)
            our_hs["nick"] = self.nick
            our_hs["accepted"] = accepted
            if accepted:
                peer.update_status(PEER_STATUS_HANDSHAKED)

    def get_peer_by_id(self, p: str) -> Union[OnionPeer, bool]:
        """ Returns the OnionPeer with peer location p,
        if it is in self.peers, otherwise returns False.
        """
        if p == "00":
            return self.self_as_peer
        for x in self.peers:
            if x.peer_location() == p and p != NOT_SERVING_ONION_HOSTNAME:
                return x
            # non-reachable peers can only match on their inbound
            # connection port
            if x.alternate_location == p:
                return x
        return False

    async def register_connection(self, peer_location: str,
                                  direction: int) -> None:
        """ We send ourselves a local control message indicating
        the new connection.
        If the connection is inbound, direction == 0, else 1.
        """
        assert direction in range(2)
        if direction == 1:
            msgtype = LOCAL_CONTROL_MESSAGE_TYPES["connect"]
        else:
            msgtype = LOCAL_CONTROL_MESSAGE_TYPES["connect-in"]
        msg = OnionCustomMessage(peer_location, msgtype)
        await self.receive_msg(msg, "00")

    async def register_disconnection(self, peer_location: str) -> None:
        """ We send ourselves a local control message indicating
        the disconnection.
        """
        msg = OnionCustomMessage(
            peer_location, LOCAL_CONTROL_MESSAGE_TYPES["disconnect"])
        await self.receive_msg(msg, "00")

    def add_peer(self, peerdata: str, connection: bool = False,
                 overwrite_connection: bool = False,
                 with_nick=False) -> Union[OnionPeer, None]:
        """ add non-directory peer from (nick, peer) serialization `peerdata`,
        where "peer" is host:port;
        return the created OnionPeer object. Or, with_nick=False means
        that `peerdata` has only the peer location.
        If the peer is already in our peerlist it can be updated in
        one of these ways:
        * the nick can be added
        * it can be marked as 'connected' if it was previously unconnected,
        with this conditional on whether the flag `overwrite_connection` is
        set. Note that this peer removal, unlike the peer addition above,
        can also occur for directory nodes, if we lose connection (and then
        we persistently try to reconnect; see OnionDirectoryPeer).
        """
        if with_nick:
            try:
                nick, peer = peerdata.split(NICK_PEERLOCATOR_SEPARATOR)
            except Exception as e:
                # old code does not recognize messages with "D" as a third
                # field; they will swallow the message here, ignoring
                # the message as invalid because it has three fields
                # instead of two.
                # (We still use the catch-all `Exception`, for the usual reason
                # of not wanting to make assumptions about external input).
                self.logger.debug(f"Received invalid peer identifier string:"
                                  f" {peerdata}, {e}")
                return
        else:
            peer = peerdata

        cls = OnionPeerPassive if self.passive else OnionPeer
        # assumed that it's passing a full string
        try:
            temp_p = cls.from_location_string(
                self, peer, self.socks5_host, self.socks5_port,
                handshake_callback=self.handshake_as_client)
        except Exception as e:
            # There are currently a few ways the location
            # parsing and Peer object construction can fail;
            # TODO specify exception types.
            self.logger.warning(f"Failed to add peer: {peer},"
                                f" exception: {repr(e)}")
            return
        if not self.get_peer_by_id(temp_p.peer_location()):
            self.peers.add(temp_p)
            if connection:
                self.logger.info(f"Updating status of peer: "
                                 f"{temp_p.peer_location()} to connected.")
                temp_p.update_status(PEER_STATUS_CONNECTED)
            else:
                if overwrite_connection:
                    temp_p.update_status(PEER_STATUS_DISCONNECTED)
            if with_nick:
                temp_p.set_nick(nick)
            return temp_p
        else:
            p = self.get_peer_by_id(temp_p.peer_location())
            if overwrite_connection:
                if connection:
                    self.logger.info(f"Updating status to connected for peer"
                                     f" {temp_p.peer_location()}.")
                    p.update_status(PEER_STATUS_CONNECTED)
                else:
                    p.update_status(PEER_STATUS_DISCONNECTED)
            if with_nick:
                p.set_nick(nick)
            return p

    def get_all_connected_peers(self) -> list:
        return (self.get_connected_directory_peers() +
                self.get_connected_nondirectory_peers())

    def get_connected_directory_peers(self) -> list:
        return [p for p in self.peers if p.directory and p.status() ==
                PEER_STATUS_HANDSHAKED]

    def get_connected_nondirectory_peers(self) -> List[OnionPeer]:
        return [p for p in self.peers if (not p.directory) and p.status() ==
                PEER_STATUS_HANDSHAKED]

    async def wait_for_directories(self) -> None:
        # Notice this is checking for *handshaked* dps;
        # the handshake will have been initiated once a
        # connection was seen.
        # Note also that this is *only* called on startup,
        # so we are guaranteed to have only directory peers.
        if len(self.get_connected_directory_peers()) < len(self.peers):
            self.directory_wait_counter += 1
            # Keep trying until the timeout.
            # Note RHS need not be an integer.
            if self.directory_wait_counter < CONNECT_TO_ONION_TIMEOUT/2 + 1:
                return
        if len(self.get_connected_directory_peers()) == 0:
            # at least one handshake must have succeeded, for us
            # to continue.
            self.logger.error(
                "We failed to connect and handshake with "
                "ANY directories; onion messaging is not functioning.")
            self.wait_for_directories_fut.set_result(False)
            # notice that in this failure mode, we do *not* shut down
            # the entire process, as this is only a failure to connect
            # to one message channel, and others (e.g. IRC) may be working.
            return
        # This is what triggers the start of taker/maker workflows.
        # Note that even if the preceding (max) 50 seconds failed to
        # connect all our configured dps, we will keep trying and they
        # can still be used.
        if not self.on_welcome_sent:
            await self.on_welcome(self)
            self.on_welcome_sent = True
            self.wait_for_directories_fut.set_result(True)
