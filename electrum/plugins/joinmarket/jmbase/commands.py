# -*- coding: utf-8 -*-

import asyncio


"""
Commands defining client-server (daemon)
messaging protocol (*not* Joinmarket p2p protocol).
Used for AMP asynchronous messages.
"""


class CommandMock:

    commands = {}  # command -> responder

    @classmethod
    def responder(cls, func):
        cls.commands[cls] = func
        return func


def callLater(timeout, func, *args, **kwargs):
    async def coro():
        await asyncio.sleep(timeout)
        try:
            if asyncio.iscoroutinefunction(func):
                await func(*args, **kwargs)
            else:
                func(*args, **kwargs)
        except BaseException as err:
            try:
                logger = func.__self__.logger
                logger.error(f"callLater exception: {err}")
            except AttributeError:
                pass

    return asyncio.create_task(coro())


def deferLater(timeout, task_fn, *args, **kwargs):
    return DeferredMock(timeout, task_fn, None, *args, **kwargs)


class DeferredMock:

    def __init__(self, timeout, task_fn, real_self, *args, **kwargs):
        self.timeout = timeout
        self.task_fn = task_fn
        self.real_self = real_self
        self.args = args
        self.kwargs = kwargs
        self.callbacks = []
        self.errbacks = []
        self.run()

    def run(self):

        async def task_fn_with_callbacks():
            func = self.task_fn
            await asyncio.sleep(self.timeout)
            try:
                if asyncio.iscoroutinefunction(func):
                    if self.real_self:
                        res = await func(self.real_self,
                                         *self.args, **self.kwargs)
                    else:
                        res = await func(*self.args, **self.kwargs)
                else:
                    if self.real_self:
                        res = func(self.real_self, *self.args, **self.kwargs)
                    else:
                        res = func(*self.args, **self.kwargs)
                for res_fn, args, kwargs in self.callbacks:
                    res_fn(res, *args, **kwargs)
            except BaseException as err:
                try:
                    logger = func.__self__.logger
                    logger.error(f"DeferredMock exception: {err}")
                except AttributeError:
                    pass
                for err_fn, args, kwargs in self.errbacks:
                    err_fn(err, *args, **kwargs)

        asyncio.create_task(task_fn_with_callbacks())

    def addCallback(self, res_fn, *args, **kwargs):
        self.callbacks.append((res_fn, args, kwargs))

    def addErrback(self, err_fn, *args, **kwargs):
        self.errbacks.append((err_fn, args, kwargs))


class LoopingCall:

    def __init__(self, task_fn, *args, **kwargs):
        self.task_fn = task_fn
        self.args = args
        self.kwargs = kwargs
        self.is_started = False

    def start(self, interval):
        self.is_started = True

        async def task_fn():
            func = self.task_fn
            while self.is_started:
                try:
                    if asyncio.iscoroutinefunction(func):
                        await func(*self.args, **self.kwargs)
                    else:
                        func(*self.args, **self.kwargs)
                except BaseException as err:
                    try:
                        logger = func.__self__.logger
                        logger.error(f"LoopingCall exception: {err}")
                    except AttributeError:
                        pass
                await asyncio.sleep(interval)

        asyncio.create_task(task_fn())

    def stop(self):
        self.is_started = False


class CallRemoteMock:

    async def callRemote(self, remote_cmd, real_self, *args, **kwargs):
        return DeferredMock(0, CommandMock.commands[remote_cmd],
                            real_self, *args, **kwargs)


class TwistedTypeMock:

    def __init__(*args, **kwargs):
        pass


class Boolean(TwistedTypeMock):
    ...


class Integer(TwistedTypeMock):
    ...


class Unicode(TwistedTypeMock):
    ...


class ListOf(TwistedTypeMock):
    ...


class String(TwistedTypeMock):
    ...


class BigUnicode(TwistedTypeMock):
    ...


class JsonEncodable(TwistedTypeMock):
    ...


class JMCommand(CommandMock):
    # a default response type
    response = [(b'accepted', Boolean())]


"""COMMANDS FROM CLIENT TO DAEMON
=================================
"""

"""Messages used by both MAKER and TAKER
"""


class JMInit(JMCommand):
    """Communicates the client's required setup
    configuration.
    Blockchain source is communicated only as a naming
    tag for messagechannels (for IRC, 'realname' field).
    """
    arguments = [(b'bcsource', Unicode()),
                 (b'network', Unicode()),
                 (b'chan_configs', JsonEncodable()),
                 (b'minmakers', Integer()),
                 (b'maker_timeout_sec', Integer()),
                 (b'dust_threshold', Integer()),
                 (b'blacklist_location', Unicode())]


class JMStartMC(JMCommand):
    """Will restart message channel connections if config
    has changed; otherwise will only change nym/nick on MCs.
    """
    arguments = [(b'nick', Unicode())]


class JMSetup(JMCommand):
    """Communicates which of "MAKER" or "TAKER"
    roles are to be taken by this client; for MAKER
    role, passes initial offers for announcement (for TAKER, this data
    is "none")
    """
    arguments = [(b'role', Unicode()),
                 (b'initdata', JsonEncodable()),
                 (b'use_fidelity_bond', Boolean())]


class JMMsgSignature(JMCommand):
    """A response to a request for a bitcoin signature
    on a message-channel layer message from the daemon
    """
    arguments = [(b'nick', Unicode()),
                 (b'cmd', Unicode()),
                 (b'msg_to_return', Unicode()),
                 (b'hostid', Unicode())]


class JMMsgSignatureVerify(JMCommand):
    """A response to a request to verify the bitcoin signature
    of a message-channel layer message from the daemon
    """
    arguments = [(b'verif_result', Boolean()),
                 (b'nick', Unicode()),
                 (b'fullmsg', Unicode()),
                 (b'hostid', Unicode())]


class JMShutdown(JMCommand):
    """ Requests shutdown of the current
    message channel connections (to be used
    when the client is shutting down).
    """
    arguments = []


"""TAKER specific commands
"""


class JMRequestOffers(JMCommand):
    """Get orderbook from daemon
    """
    arguments = []


class JMFill(JMCommand):
    """Fill an offer/order
    """
    arguments = [(b'amount', Integer()),
                 (b'commitment', Unicode()),
                 (b'revelation', Unicode()),
                 (b'filled_offers', JsonEncodable())]


class JMMakeTx(JMCommand):
    """Send a hex encoded raw bitcoin transaction
    to a set of counterparties
    """
    arguments = [(b'nick_list', ListOf(Unicode())),
                 (b'tx', String())]


class JMPushTx(JMCommand):
    """Pass a raw hex transaction to a specific
    counterparty (maker) for pushing (anonymity feature in JM)
    """
    arguments = [(b'nick', Unicode()),
                 (b'tx', String())]


"""COMMANDS FROM DAEMON TO CLIENT
=================================
"""


class JMInitProto(JMCommand):
    """Pass to the client the messaging protocol parameters
    (which are defined in daemon package), required to construct
    the user nick, given the bitcoin private key used for authentication
    (that key being controlled by the client; the daemon knows nothing
    about bitcoin).
    """
    arguments = [(b'nick_hash_length', Integer()),
                 (b'nick_max_encoded', Integer()),
                 (b'joinmarket_nick_header', Unicode()),
                 (b'joinmarket_version', Integer())]


class JMUp(JMCommand):
    """Used to signal readiness of message channels to client.
    """
    arguments = []


class JMSetupDone(JMCommand):
    """Used to signal that initial setup action
    has been taken (e.g. !orderbook call).
    """
    arguments = []


class JMRequestMsgSig(JMCommand):
    """Request the client to sign a message-channel
    layer message with the bitcoin key for the nick
    """
    arguments = [(b'nick', Unicode()),
                 (b'cmd', Unicode()),
                 (b'msg', Unicode()),
                 (b'msg_to_be_signed', Unicode()),
                 (b'hostid', Unicode())]


class JMRequestMsgSigVerify(JMCommand):
    """Request the client to verify a counterparty's
    message-channel layer message against the provided nick
    """
    arguments = [(b'msg', Unicode()),
                 (b'fullmsg', Unicode()),
                 (b'sig', Unicode()),
                 (b'pubkey', Unicode()),
                 (b'nick', Unicode()),
                 (b'hashlen', Integer()),
                 (b'max_encoded', Integer()),
                 (b'hostid', Unicode())]


""" TAKER-specific commands
"""


class JMOffers(JMCommand):
    """Return the entire contents of the
    orderbook to TAKER, as a json-ified dict.
    """
    arguments = [(b'orderbook', BigUnicode()),
                 (b'fidelitybonds', BigUnicode())]


class JMFillResponse(JMCommand):
    """Returns ioauth data from MAKER if successful.
    """
    arguments = [(b'success', Boolean()),
                 (b'ioauth_data', JsonEncodable())]


class JMSigReceived(JMCommand):
    """Returns an individual bitcoin transaction signature
    from a MAKER
    """
    arguments = [(b'nick', Unicode()),
                 (b'sig', Unicode())]
