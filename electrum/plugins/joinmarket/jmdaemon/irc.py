# -*- coding: utf-8 -*-

from ..jmbase import commands
from ..jmbase.support import chunks
from .message_channel import MessageChannel
from .protocol import COMMAND_PREFIX, NICK_MAX_ENCODED
from .twisted_irc import IRCClient
from .irc_support import IRCClientService


MAX_PRIVMSG_LEN = 450


def wlog(log, *x):
    """Simplifier to add lists to the debug log
    """
    def conv(s):
        if isinstance(s, str):
            return s
        elif isinstance(s, bytes):
            return s.decode('utf-8', errors='ignore')
        else:
            return str(s)

    if x[0] == "WARNING":
        msg = " ".join([conv(a) for a in x[1:]])
        log.warning(msg)
    elif x[0] == "INFO":
        msg = " ".join([conv(a) for a in x[1:]])
        log.info(msg)
    else:
        msg = " ".join([conv(a) for a in x])
        log.debug(msg)


def get_irc_text(line):
    return line[line[1:].find(':') + 2:]


def get_irc_nick(source):
    full_nick = source[0:source.find('!')]
    return full_nick[:NICK_MAX_ENCODED+2]


def get_config_irc_channel(chan_name, btcnet):
    channel = "#" + chan_name
    if btcnet == "testnet":
        channel += "-test"
    elif btcnet == "signet":
        channel += "-sig"
    return channel


class TxIRCFactory:

    def __init__(self, wrapper):
        self.jmman = wrapper.jmman
        self.logger = wrapper.logger
        self.wrapper = wrapper
        self.channel = self.wrapper.channel

    def buildProtocol(self):
        p = txIRC_Client(self.wrapper, self.jmman)
        p.factory = self
        self.wrapper.set_tx_irc_client(p)
        return p

    def clientConnectionLost(self, reason):
        self.logger.debug('IRC connection lost' +
                          f': {reason}' if reason else '')
        wrapper = self.wrapper
        if not wrapper.give_up:
            wrapper.logger.info('Attempting to reconnect...')
            wrapper.client_service.stopService()
            wrapper.client_service.startService()

    def clientConnectionFailed(self, reason):
        self.logger.debug('IRC connection failed' +
                          f': {reason}' if reason else '')
        wrapper = self.wrapper
        if not self.wrapper.give_up:
            self.logger.info('Attempting to reconnect...')
            wrapper.client_service.stopService()
            wrapper.client_service.startService()


class IRCMessageChannel(MessageChannel):

    def __init__(self,
                 jmman,
                 configdata,
                 username='username',
                 realname='realname',
                 password=None):
        self.jmman = jmman
        self.loop = jmman.loop
        self.logger = jmman.logger
        MessageChannel.__init__(self)
        self.give_up = True
        self.host = configdata['host']
        self.port = configdata['port']
        # default hostid for use with miniircd which doesnt send NETWORK
        self.hostid = configdata['host'] + str(configdata['port'])
        self.serverport = self.hostid
        self.socks5 = configdata["socks5"]
        self.usessl = configdata["usessl"]
        self.socks5_host = configdata["socks5_host"]
        self.socks5_port = configdata["socks5_port"]
        blockchain_network = jmman.jmconf.blockchain_network
        self.channel = get_config_irc_channel(configdata["channel"],
                                              blockchain_network)
        self.userrealname = (username, realname)
        if password and len(password) == 0:
            password = None
        self.password = password

        self.tx_irc_client = None
        # TODO can be configuration var, how long between reconnect attempts:
        self.reconnect_interval = 10

        # service is used to wrap endpoints for Tor connections:
        self.client_service = None
        # TxIRCFactory
        self.irc_factory = None
        # Future done after on_welcome triggered and possibly awaited in run
        self.wait_for_welcome_fut = None

    # implementation of abstract base class methods;
    # these are mostly but not exclusively acting as pass through
    # to the wrapped twisted IRC client protocol
    async def run(self, for_obwatch=False):
        self.give_up = False
        await self.build_irc()
        if for_obwatch:
            self.wait_for_welcome_fut = self.jmman.loop.create_future()
            await self.wait_for_welcome_fut
            self.wait_for_welcome_fut = None

    async def shutdown(self):
        self.tx_irc_client.quit()
        self.give_up = True
        if self.client_service:
            self.client_service.stopService()

    async def _pubmsg(self, msg):
        self.tx_irc_client._pubmsg(msg)

    async def _privmsg(self, nick, cmd, msg):
        self.tx_irc_client._privmsg(nick, cmd, msg)

    def change_nick(self, new_nick):
        self.tx_irc_client.setNick(new_nick)

    async def _announce_orders(self, offerlist):
        self.tx_irc_client._announce_orders(offerlist)
    # end ABC impl.

    def set_tx_irc_client(self, txircclt):
        self.tx_irc_client = txircclt

    async def build_irc(self):
        """The main starting method that creates a protocol object
        according to the config variables, ready for whenever
        the reactor starts running.
        """
        wlog(self.logger, 'building irc')
        if self.tx_irc_client:
            raise Exception('irc already built')
        try:
            self.irc_factory = TxIRCFactory(self)
            wlog(
                self.logger,
                f'build_irc: host={self.host}, port={self.port}, '
                f'channel={self.channel}, usessl={self.usessl}, '
                f'socks5={self.socks5}, socks5_host={self.socks5_host}, '
                f'socks5_port={self.socks5_port}')
            self.client_service = IRCClientService(
                self.irc_factory, host=self.host, port=self.port,
                loop=self.loop, usessl=self.usessl, socks5=self.socks5,
                socks5_host=self.socks5_host, socks5_port=self.socks5_port)
            self.client_service.startService()
            await self.client_service.srv_task
        except Exception as e:
            wlog(self.logger, 'error in buildirc: ' + repr(e))


class txIRC_Client(IRCClient):
    """
    lineRate is a class variable in the superclass used to limit
    messages / second.  heartbeat is what you'd think.
    """
    # In previous implementation, 450 bytes per second over the last 4 seconds
    # was used as the rate limiter/throttle parameter.
    # Since we still have max_privmsg_len = 450, that corresponds to a lineRate
    # value of 1.0 (seconds). Bumped to 1.3 here for breathing room.
    lineRate = 1.3
    heartbeatinterval = 60

    def __init__(self, wrapper, jmman):
        self.wrapper = wrapper
        self.channel = self.wrapper.channel
        self.nickname = self.wrapper.nick
        self.password = self.wrapper.password
        self.hostname = self.wrapper.serverport
        self.built_privmsg = {}
        # todo: build pong timeout watchdot

        self.logger = jmman.logger
        self.jmman = jmman

    def irc_unknown(self, prefix, command, params):
        pass

    def irc_PONG(self, *args, **kwargs):
        # todo: pong called getattr() style. use for health
        pass

    def connection_made(self, transport):
        self.transport = transport
        IRCClient.connection_made(self, transport)

    def connection_lost(self, reason):
        msg = f'Lost IRC connection to: {self.hostname}.'
        if not self.wrapper.give_up:
            msg += ' Should reconnect automatically soon.'
        wlog(self.logger, "INFO", msg)
        if not self.wrapper.give_up and self.wrapper.on_disconnect:
            commands.callLater(0.0, self.wrapper.on_disconnect, self.wrapper)
        IRCClient.connection_lost(self, reason)
        self.factory.clientConnectionLost(reason)

    def send(self, send_to, msg):
        # todo: use proper twisted IRC support (encoding + sendCommand)
        omsg = 'PRIVMSG %s :' % (send_to,) + msg
        self.sendLine(omsg)

    def _pubmsg(self, message):
        self.send(self.channel, message)

    def _privmsg(self, nick, cmd, message):
        header = "PRIVMSG " + nick + " :"
        max_chunk_len = MAX_PRIVMSG_LEN - len(header) - len(cmd) - 4
        # 1 for command prefix 1 for space 2 for trailer
        if len(message) > max_chunk_len:
            message_chunks = chunks(message, max_chunk_len)
        else:
            message_chunks = [message]
        for m in message_chunks:
            trailer = ' ~' if m == message_chunks[-1] else ' ;'
            if m == message_chunks[0]:
                m = COMMAND_PREFIX + cmd + ' ' + m
            self.send(nick, m + trailer)

    def _announce_orders(self, offerlist):
        """This publishes orders to the pit and to
        counterparties. Note that it does *not* use chunking.
        So, it tries to optimise space usage thusly:
        As many complete orderlines are fit onto one line
        as possible, and overflow goes onto another line.
        Each list entry in orderlist must have format:
        !ordername <parameters>

        Then, what is published is lines of form:
        !ordername <parameters>!ordername <parameters>..

        fitting as many list entries as possible onto one line,
        up to the limit of the IRC parameters (see MAX_PRIVMSG_LEN).

        Order announce in private is handled by privmsg/_privmsg
        using chunking, no longer using this function.
        """
        header = 'PRIVMSG ' + self.channel + ' :'
        offerlines = []
        for i, offer in enumerate(offerlist):
            offerlines.append(offer)
            line = header + ''.join(offerlines) + ' ~'
            if len(line) > MAX_PRIVMSG_LEN or i == len(offerlist) - 1:
                if i < len(offerlist) - 1:
                    line = header + ''.join(offerlines[:-1]) + ' ~'
                self.sendLine(line)
                offerlines = [offerlines[-1]]
    # ---------------------------------------------
    # general callbacks from superclass
    # ---------------------------------------------

    def signedOn(self):
        wlog(self.logger, 'signedOn: ', self.hostname)
        self.join(self.factory.channel)

    async def joined(self, channel):
        wlog(self.logger, "INFO",
             "joined: " + str(channel) + " " + str(self.hostname))
        # for admin purposes, IRC servers *usually* require bots to identify
        # themselves as such:
        self.sendLine("MODE " + self.nickname + " +B")
        # Use as trigger for start to mcc:
        await self.wrapper.on_welcome(self.wrapper)
        wait_for_welcome_fut = self.wrapper.wait_for_welcome_fut
        if wait_for_welcome_fut:
            wait_for_welcome_fut.set_result(True)

    def privmsg(self, userIn, channel, msg):
        commands.callLater(0.0, self.handle_privmsg, userIn, channel, msg)

    def __on_privmsg(self, nick, msg):
        commands.callLater(0.0, self.wrapper.on_privmsg, nick, msg)

    def __on_pubmsg(self, nick, msg):
        commands.callLater(0.0, self.wrapper.on_pubmsg, nick, msg)

    def handle_privmsg(self, sent_from, sent_to, message):
        try:
            nick = get_irc_nick(sent_from)
            # todo: kludge - we need this elsewhere. rearchitect!!
            self.from_to = (nick, sent_to)
            if sent_to == self.wrapper.nick:
                if nick not in self.built_privmsg:
                    if message[0] != COMMAND_PREFIX:
                        wlog(self.logger, 'bad command ', message)
                        return

                    # new message starting
                    cmd_string = message[1:].split(' ')[0]
                    self.built_privmsg[nick] = [cmd_string, message[:-2]]
                else:
                    self.built_privmsg[nick][1] += message[:-2]
                if message[-1] == ';':
                    pass
                elif message[-1] == '~':
                    parsed = self.built_privmsg[nick][1]
                    # wipe the message buffer waiting for the next one
                    del self.built_privmsg[nick]
                    self.__on_privmsg(nick, parsed)
                else:
                    # drop the bad nick
                    del self.built_privmsg[nick]
            elif sent_to == self.channel:
                self.__on_pubmsg(nick, message)
            else:
                wlog(self.logger, 'what is this?: ',
                     sent_from, sent_to, message[:80])
        except BaseException:
            wlog(self.logger, 'unable to parse privmsg, msg: ', message)

    def action(self, user, channel, msg):
        pass
        # wlog('unhandled action: ', user, channel, msg)

    def irc_ERR_NICKNAMEINUSE(self, prefix, params):
        """
        Called when we try to register or change to a nickname that is already
        taken.
        This is overriden from base class to insist on retrying with the same
        nickname, after a hardcoded 10s timeout. The user is amply warned at
        WARNING logging level, and can just restart if they are around to
        see it.
        """
        wlog(self.logger, "WARNING",
             "Your nickname is in use. This usually happens "
             "as a result of a network failure. You are recommended to "
             "restart, otherwise you should regain your nick after "
             "some time. This is not a security risk, but you may lose "
             "access to coinjoins during this period.")
        commands.callLater(10.0, self.setNick, self._attemptedNick)

    def modeChanged(self, user, channel, _set, modes, args):
        pass
        # wlog('(unhandled) modeChanged: ', user, channel, _set, modes, args)

    def pong(self, user, secs):
        pass
        # wlog('pong: ', user, secs)

    def userJoined(self, user, channel):
        pass
        # wlog('user joined: ', user, channel)

    def userKicked(self, kickee, channel, kicker, message):
        # wlog(self.logger, 'kicked: ', kickee, channel, kicker, message)
        if self.wrapper.on_nick_leave:
            commands.callLater(0.0, self.wrapper.on_nick_leave, kickee,
                               self.wrapper)

    def userLeft(self, user, channel):
        # wlog(self.logger, 'left: ', user, channel)
        if self.wrapper.on_nick_leave:
            commands.callLater(0.0, self.wrapper.on_nick_leave, user,
                               self.wrapper)

    def userRenamed(self, oldname, newname):
        wlog('rename: ', oldname, newname)
        # TODO nick change handling

    def userQuit(self, user, quitMessage):
        # wlog(self.logger, 'userQuit: ', user, quitMessage)
        if self.wrapper.on_nick_leave:
            commands.callLater(0.0, self.wrapper.on_nick_leave, user,
                               self.wrapper)

    def topicUpdated(self, user, channel, newTopic):
        wlog(self.logger, 'topicUpdated: ', user, channel, newTopic)
        if self.wrapper.on_set_topic:
            commands.callLater(0.0, self.wrapper.on_set_topic,
                               newTopic,
                               self.logger)

    def receivedMOTD(self, motd):
        pass
        # wlog('motd: ', motd)

    def created(self, when):
        pass
        # wlog('(unhandled) created: ', when)

    def yourHost(self, info):
        pass
        # wlog('(unhandled) yourhost: ', info)

    def isupport(self, options):
        """Used to set the name of the IRC *network*
        (as distinct from the individual server), used
        for signature replay defence (see signing code in message_channel.py).
        If this option ("NETWORK") is not found, we fallback to the default
        hostid = servername+port as shown in IRCMessageChannel (should only
        happen in testing).
        """
        for o in options:
            try:
                k, v = o.split('=')
                if k == 'NETWORK':
                    self.wrapper.hostid = v
            except Exception:
                pass
                # wlog(self.logger,
                #      'failed to parse isupport option, ignoring')

    def myInfo(self, servername, version, umodes, cmodes):
        pass
        # wlog('(unhandled) myInfo: ', servername, version, umodes, cmodes)

    def luserChannels(self, channels):
        pass
        # wlog('(unhandled) luserChannels: ', channels)

    def bounce(self, info):
        pass
        # wlog('(unhandled) bounce: ', info)

    def left(self, channel):
        pass
        # wlog('(unhandled) left: ', channel)

    def noticed(self, user, channel, message):
        wlog(self.logger, '(unhandled) noticed: ', user, channel, message)

    # added to eliminate warnings from IRCClient.handleCommand
    def luserClient(self, info):
        pass
        # wlog('(unhandled) luserClient: ', info)

    def luserMe(self, info):
        pass
        # wlog('(unhandled) luserMe: ', info)
