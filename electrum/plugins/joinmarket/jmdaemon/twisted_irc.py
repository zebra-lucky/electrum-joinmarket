# -*- coding: utf-8 -*-

# modified IRCClient from twisted.words.protocols.irc
# https://github.com/twisted/twisted

# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
# https://github.com/twisted/twisted/blob/trunk/LICENSE

import random
import re
import string
import sys
import textwrap
import time
import traceback
from typing import Optional

from .twisted_line_receiver import LineReceiver
from ..jmbase.commands import LoopingCall, callLater


NUL = chr(0)
CR = chr(0o15)
NL = chr(0o12)
LF = NL
SPC = chr(0o40)

# This includes the CRLF terminator characters.
MAX_COMMAND_LENGTH = 512

CHANNEL_PREFIXES = "&#!+"


class IRCBadMessage(Exception):
    pass


class IRCPasswordMismatch(Exception):
    pass


class IRCBadModes(ValueError):
    """A malformed mode was encountered while attempting to parse
    a mode string.
    """


def parsemsg(s):
    prefix = ""
    trailing = []
    if not s:
        raise IRCBadMessage("Empty line.")
    if s[0:1] == ":":
        prefix, s = s[1:].split(" ", 1)
    if s.find(" :") != -1:
        s, trailing = s.split(" :", 1)
        args = s.split()
        args.append(trailing)
    else:
        args = s.split()
    command = args.pop(0)
    return prefix, command, args


def split(str, length=80):
    """Split a string into multiple lines."""
    return [chunk for line in str.split("\n")
            for chunk in textwrap.wrap(line, length)]


def _intOrDefault(value, default=None):
    """Convert a value to an integer if possible. """
    if value:
        try:
            return int(value)
        except (TypeError, ValueError):
            pass
    return default


class UnhandledCommand(RuntimeError):
    """A command dispatcher could not locate an appropriate command handler."""


class _CommandDispatcherMixin:

    prefix: Optional[str] = None

    def dispatch(self, commandName, *args):
        """
        Perform actual command dispatch.
        """

        def _getMethodName(command):
            return f"{self.prefix}_{command}"

        def _getMethod(name):
            return getattr(self, _getMethodName(name), None)

        method = _getMethod(commandName)
        if method is not None:
            return method(*args)

        method = _getMethod("unknown")
        if method is None:
            raise UnhandledCommand(
                f"No handler for "
                f"{_getMethodName(commandName)!r} could be found")
        return method(commandName, *args)


def parseModes(modes, params, paramModes=("", "")):
    if len(modes) == 0:
        raise IRCBadModes("Empty mode string")

    if modes[0] not in "+-":
        raise IRCBadModes(f"Malformed modes string: {modes!r}")

    changes = ([], [])

    direction = None
    count = -1
    for ch in modes:
        if ch in "+-":
            if count == 0:
                raise IRCBadModes(f"Empty mode sequence: {modes!r}")
            direction = "+-".index(ch)
            count = 0
        else:
            param = None
            if ch in paramModes[direction]:
                try:
                    param = params.pop(0)
                except IndexError:
                    raise IRCBadModes(f"Not enough parameters: {ch!r}")
            changes[direction].append((ch, param))
            count += 1

    if len(params) > 0:
        raise IRCBadModes(f"Too many parameters: {modes!r} {params!r}")

    if count == 0:
        raise IRCBadModes(f"Empty mode sequence: {modes!r}")

    return changes


class ServerSupportedFeatures(_CommandDispatcherMixin):

    prefix = "isupport"

    def __init__(self):
        self._features = {
            "CHANNELLEN": 200,
            "CHANTYPES": tuple("#&"),
            "MODES": 3,
            "NICKLEN": 9,
            "PREFIX": self._parsePrefixParam("(ovh)@+%"),
            # The ISUPPORT draft explicitly says that there is no default for
            # CHANMODES, but we're defaulting it here to handle the case where
            # the IRC server doesn't send us any ISUPPORT information, since
            # IRCClient.getChannelModeParams relies on this value.
            "CHANMODES": self._parseChanModesParam(["b", "", "lk", ""]),
        }

    @classmethod
    def _splitParamArgs(cls, params, valueProcessor=None):
        if valueProcessor is None:

            def _v_processor(x):
                return x
            valueProcessor = _v_processor

        def _parse():
            for param in params:
                if ":" not in param:
                    param += ":"
                a, b = param.split(":", 1)
                yield a, valueProcessor(b)

        return list(_parse())

    @classmethod
    def _unescapeParamValue(cls, value):

        def _unescape():
            parts = value.split("\\x")
            # The first part can never be preceded by the escape.
            yield parts.pop(0)
            for s in parts:
                octet, rest = s[:2], s[2:]
                try:
                    octet = int(octet, 16)
                except ValueError:
                    raise ValueError(f"Invalid hex octet: {octet!r}")
                yield chr(octet) + rest

        if "\\x" not in value:
            return value
        return "".join(_unescape())

    @classmethod
    def _splitParam(cls, param):
        if "=" not in param:
            param += "="
        key, value = param.split("=", 1)
        return key, [cls._unescapeParamValue(v) for v in value.split(",")]

    @classmethod
    def _parsePrefixParam(cls, prefix):
        if not prefix:
            return None
        if prefix[0] != "(" and ")" not in prefix:
            raise ValueError("Malformed PREFIX parameter")
        modes, symbols = prefix.split(")", 1)
        symbols = zip(symbols, range(len(symbols)))
        modes = modes[1:]
        return dict(zip(modes, symbols))

    @classmethod
    def _parseChanModesParam(self, params):
        names = ("addressModes", "param", "setParam", "noParam")
        if len(params) > len(names):
            raise ValueError(
                "Expecting a maximum of %d channel mode parameters, got %d"
                % (len(names), len(params))
            )
        items = map(lambda key, value: (key, value or ""), names, params)
        return dict(items)

    def getFeature(self, feature, default=None):
        return self._features.get(feature, default)

    def hasFeature(self, feature):
        return self.getFeature(feature) is not None

    def parse(self, params):
        for param in params:
            key, value = self._splitParam(param)
            if key.startswith("-"):
                self._features.pop(key[1:], None)
            else:
                self._features[key] = self.dispatch(key, value)

    def isupport_unknown(self, command, params):
        return tuple(params)

    def isupport_CHANLIMIT(self, params):
        return self._splitParamArgs(params, _intOrDefault)

    def isupport_CHANMODES(self, params):
        try:
            return self._parseChanModesParam(params)
        except ValueError:
            return self.getFeature("CHANMODES")

    def isupport_CHANNELLEN(self, params):
        return _intOrDefault(params[0], self.getFeature("CHANNELLEN"))

    def isupport_CHANTYPES(self, params):
        return tuple(params[0])

    def isupport_EXCEPTS(self, params):
        return params[0] or "e"

    def isupport_IDCHAN(self, params):
        return self._splitParamArgs(params)

    def isupport_INVEX(self, params):
        return params[0] or "I"

    def isupport_KICKLEN(self, params):
        return _intOrDefault(params[0])

    def isupport_MAXLIST(self, params):
        return self._splitParamArgs(params, _intOrDefault)

    def isupport_MODES(self, params):
        return _intOrDefault(params[0])

    def isupport_NETWORK(self, params):
        return params[0]

    def isupport_NICKLEN(self, params):
        return _intOrDefault(params[0], self.getFeature("NICKLEN"))

    def isupport_PREFIX(self, params):
        try:
            return self._parsePrefixParam(params[0])
        except ValueError:
            return self.getFeature("PREFIX")

    def isupport_SAFELIST(self, params):
        return True

    def isupport_STATUSMSG(self, params):
        return params[0]

    def isupport_TARGMAX(self, params):
        return dict(self._splitParamArgs(params, _intOrDefault))

    def isupport_TOPICLEN(self, params):
        return _intOrDefault(params[0])


class IRCClient(LineReceiver):

    hostname = None
    motd = None
    nickname = "irc"
    password = None
    realname = None
    username = None

    # If this is false, no attempt will be made to identify
    # ourself to the server.
    performLogin = 1

    lineRate = None
    _queue = None
    _queueEmptying = None

    delimiter = b"\n"  # b'\r\n' will also work (see dataReceived)

    __pychecker__ = "unusednames=params,prefix,channel"

    _registered = False
    _attemptedNick = ""
    erroneousNickFallback = "defaultnick"

    _heartbeat = None
    heartbeatInterval = 120

    def _reallySendLine(self, line):
        quoteLine = lowQuote(line)
        if isinstance(quoteLine, str):
            quoteLine = quoteLine.encode("utf-8")
        quoteLine += b"\r"
        return LineReceiver.send_line(self, quoteLine)

    def sendLine(self, line):
        if self.lineRate is None:
            self._reallySendLine(line)
        else:
            self._queue.append(line)
            if not self._queueEmptying:
                self._sendLine()

    def _sendLine(self):
        if self._queue:
            self._reallySendLine(self._queue.pop(0))
            self._queueEmptying = callLater(self.lineRate, self._sendLine)
        else:
            self._queueEmptying = None

    def connection_lost(self, reason):
        LineReceiver.connection_lost(self, reason)
        self.stopHeartbeat()

    def _createHeartbeat(self):
        return LoopingCall(self._sendHeartbeat)

    def _sendHeartbeat(self):
        self.sendLine("PING " + self.hostname)

    def stopHeartbeat(self):
        if self._heartbeat is not None:
            self._heartbeat.stop()
            self._heartbeat = None

    def startHeartbeat(self):
        self.stopHeartbeat()
        if self.heartbeatInterval is None:
            return
        self._heartbeat = self._createHeartbeat()
        # FIXME add now to LoopingCall
        # self._heartbeat.start(self.heartbeatInterval, now=False)
        self._heartbeat.start(self.heartbeatInterval)

    # Interface level client->user output methods

    def nickChanged(self, nick):
        self.nickname = nick

    # user input commands, client->server
    # Your client will want to invoke these.

    def join(self, channel, key=None):
        if channel[0] not in CHANNEL_PREFIXES:
            channel = "#" + channel
        if key:
            self.sendLine(f"JOIN {channel} {key}")
        else:
            self.sendLine(f"JOIN {channel}")

    def leave(self, channel, reason=None):
        if channel[0] not in CHANNEL_PREFIXES:
            channel = "#" + channel
        if reason:
            self.sendLine(f"PART {channel} :{reason}")
        else:
            self.sendLine(f"PART {channel}")

    def kick(self, channel, user, reason=None):
        if channel[0] not in CHANNEL_PREFIXES:
            channel = "#" + channel
        if reason:
            self.sendLine(f"KICK {channel} {user} :{reason}")
        else:
            self.sendLine(f"KICK {channel} {user}")

    part = leave

    def invite(self, user, channel):
        if channel[0] not in CHANNEL_PREFIXES:
            channel = "#" + channel
        self.sendLine(f"INVITE {user} {channel}")

    def topic(self, channel, topic=None):
        # << TOPIC #xtestx :fff
        if channel[0] not in CHANNEL_PREFIXES:
            channel = "#" + channel
        if topic is not None:
            self.sendLine(f"TOPIC {channel} :{topic}")
        else:
            self.sendLine(f"TOPIC {channel}")

    def mode(self, chan, set, modes, limit=None, user=None, mask=None):
        if set:
            line = f"MODE {chan} +{modes}"
        else:
            line = f"MODE {chan} -{modes}"
        if limit is not None:
            line = "%s %d" % (line, limit)
        elif user is not None:
            line = f"{line} {user}"
        elif mask is not None:
            line = f"{line} {mask}"
        self.sendLine(line)

    def say(self, channel, message, length=None):
        if channel[0] not in CHANNEL_PREFIXES:
            channel = "#" + channel
        self.msg(channel, message, length)

    def _safeMaximumLineLength(self, command):
        # :nickname!realname@hostname COMMAND ...
        theoretical = ":{}!{}@{} {}".format(
            "a" * self.supported.getFeature("NICKLEN"),
            # This value is based on observation.
            "b" * 10,
            # See <http://tools.ietf.org/html/rfc2812#section-2.3.1>.
            "c" * 63,
            command,
        )
        # Fingers crossed.
        fudge = 10
        return MAX_COMMAND_LENGTH - len(theoretical) - fudge

    def _sendMessage(self, msgType, user, message, length=None):
        fmt = f"{msgType} {user} :"

        if length is None:
            length = self._safeMaximumLineLength(fmt)

        # Account for the line terminator.
        minimumLength = len(fmt) + 2
        if length <= minimumLength:
            raise ValueError(
                "Maximum length must exceed %d for message "
                "to %s" % (minimumLength, user)
            )
        for line in split(message, length - minimumLength):
            self.sendLine(fmt + line)

    def msg(self, user, message, length=None):
        self._sendMessage("PRIVMSG", user, message, length)

    def notice(self, user, message, length=None):
        self._sendMessage("NOTICE", user, message, length)

    def away(self, message=""):
        self.sendLine("AWAY :%s" % message)

    def back(self):
        # An empty away marks us as back
        self.away()

    def whois(self, nickname, server=None):
        if server is None:
            self.sendLine("WHOIS " + nickname)
        else:
            self.sendLine(f"WHOIS {server} {nickname}")

    def register(self, nickname, hostname="foo", servername="bar"):
        if self.password is not None:
            self.sendLine("PASS %s" % self.password)
        self.setNick(nickname)
        if self.username is None:
            self.username = nickname
        self.sendLine(
            "USER {} {} {} :{}".format(
                self.username, hostname, servername, self.realname
            )
        )

    def setNick(self, nickname):
        self._attemptedNick = nickname
        self.sendLine("NICK %s" % nickname)

    def quit(self, message=""):
        self.sendLine("QUIT :%s" % message)

    # user input commands, client->client

    _pings = None
    _MAX_PINGRING = 12

    def ping(self, user, text=None):
        if self._pings is None:
            self._pings = {}

        if text is None:
            chars = string.ascii_letters + string.digits + string.punctuation
            key = "".join([random.choice(chars) for i in range(12)])
        else:
            key = str(text)
        self._pings[(user, key)] = time.time()
        self.ctcpMakeQuery(user, [("PING", key)])

        if len(self._pings) > self._MAX_PINGRING:
            # Remove some of the oldest entries.
            byValue = [(v, k) for (k, v) in self._pings.items()]
            byValue.sort()
            excess = len(self._pings) - self._MAX_PINGRING
            for i in range(excess):
                del self._pings[byValue[i][1]]

    # server->client messages
    # You might want to fiddle with these,
    # but it is safe to leave them alone.

    def irc_ERR_NICKNAMEINUSE(self, prefix, params):
        self._attemptedNick = self.alterCollidedNick(self._attemptedNick)
        self.setNick(self._attemptedNick)

    def alterCollidedNick(self, nickname):
        return nickname + "_"

    def irc_ERR_ERRONEUSNICKNAME(self, prefix, params):
        if not self._registered:
            self.setNick(self.erroneousNickFallback)

    def irc_ERR_PASSWDMISMATCH(self, prefix, params):
        raise IRCPasswordMismatch("Password Incorrect.")

    def irc_RPL_WELCOME(self, prefix, params):
        self.hostname = prefix
        self._registered = True
        self.nickname = self._attemptedNick
        self.signedOn()
        self.startHeartbeat()

    def irc_JOIN(self, prefix, params):
        nick = prefix.split("!")[0]
        channel = params[-1]
        if nick == self.nickname:
            callLater(0, self.joined, channel)
        else:
            self.userJoined(nick, channel)

    def irc_PART(self, prefix, params):
        nick = prefix.split("!")[0]
        channel = params[0]
        if nick == self.nickname:
            self.left(channel)
        else:
            self.userLeft(nick, channel)

    def irc_QUIT(self, prefix, params):
        nick = prefix.split("!")[0]
        self.userQuit(nick, params[0])

    def irc_MODE(self, user, params):
        channel, modes, args = params[0], params[1], params[2:]

        if modes[0] not in "-+":
            modes = "+" + modes

        if channel == self.nickname:
            # This is a mode change to our individual user, not a channel mode
            # that involves us.
            paramModes = self.getUserModeParams()
        else:
            paramModes = self.getChannelModeParams()

        try:
            added, removed = parseModes(modes, args, paramModes)
        except IRCBadModes:
            self.factory.logger.error(
                None,
                "An error occurred while parsing the following "
                "MODE message: MODE %s" % (" ".join(params),),
            )
        else:
            if added:
                modes, params = zip(*added)
                self.modeChanged(user, channel, True, "".join(modes), params)

            if removed:
                modes, params = zip(*removed)
                self.modeChanged(user, channel, False, "".join(modes), params)

    def irc_PING(self, prefix, params):
        self.sendLine("PONG %s" % params[-1])

    def irc_PRIVMSG(self, prefix, params):
        user = prefix
        channel = params[0]
        message = params[-1]

        if not message:
            # Don't raise an exception if we get blank message.
            return
        self.privmsg(user, channel, message)

    def irc_NOTICE(self, prefix, params):
        user = prefix
        channel = params[0]
        message = params[-1]
        self.noticed(user, channel, message)

    def irc_NICK(self, prefix, params):
        nick = prefix.split("!", 1)[0]
        if nick == self.nickname:
            self.nickChanged(params[0])
        else:
            self.userRenamed(nick, params[0])

    def irc_KICK(self, prefix, params):
        kicker = prefix.split("!")[0]
        channel = params[0]
        kicked = params[1]
        message = params[-1]
        if kicked.lower() == self.nickname.lower():
            # Yikes!
            self.kickedFrom(channel, kicker, message)
        else:
            self.userKicked(kicked, channel, kicker, message)

    def irc_TOPIC(self, prefix, params):
        user = prefix.split("!")[0]
        channel = params[0]
        newtopic = params[1]
        self.topicUpdated(user, channel, newtopic)

    def irc_RPL_TOPIC(self, prefix, params):
        user = prefix.split("!")[0]
        channel = params[1]
        newtopic = params[2]
        self.topicUpdated(user, channel, newtopic)

    def irc_RPL_NOTOPIC(self, prefix, params):
        user = prefix.split("!")[0]
        channel = params[1]
        newtopic = ""
        self.topicUpdated(user, channel, newtopic)

    def irc_RPL_MOTDSTART(self, prefix, params):
        if params[-1].startswith("- "):
            params[-1] = params[-1][2:]
        self.motd = [params[-1]]

    def irc_RPL_MOTD(self, prefix, params):
        if params[-1].startswith("- "):
            params[-1] = params[-1][2:]
        if self.motd is None:
            self.motd = []
        self.motd.append(params[-1])

    def irc_RPL_ENDOFMOTD(self, prefix, params):
        motd = self.motd
        self.motd = None
        self.receivedMOTD(motd)

    def irc_RPL_CREATED(self, prefix, params):
        self.created(params[1])

    def irc_RPL_YOURHOST(self, prefix, params):
        self.yourHost(params[1])

    def irc_RPL_MYINFO(self, prefix, params):
        info = params[1].split(None, 3)
        while len(info) < 4:
            info.append(None)
        self.myInfo(*info)

    def irc_RPL_BOUNCE(self, prefix, params):
        self.bounce(params[1])

    def irc_RPL_ISUPPORT(self, prefix, params):
        args = params[1:-1]
        # Several ISUPPORT messages, in no particular order, may be sent
        # to the client at any given point in time (usually only on connect,
        # though.) For this reason, ServerSupportedFeatures.parse is intended
        # to mutate the supported feature list.
        self.supported.parse(args)
        self.isupport(args)

    def irc_RPL_LUSERCLIENT(self, prefix, params):
        self.luserClient(params[1])

    def irc_RPL_LUSEROP(self, prefix, params):
        try:
            self.luserOp(int(params[1]))
        except ValueError:
            pass

    def irc_RPL_LUSERCHANNELS(self, prefix, params):
        try:
            self.luserChannels(int(params[1]))
        except ValueError:
            pass

    def irc_RPL_LUSERME(self, prefix, params):
        self.luserMe(params[1])

    def irc_unknown(self, prefix, command, params):
        pass

    # Error handlers
    # You may override these with something more appropriate to your UI.

    def badMessage(self, line, excType, excValue, tb):
        self.factory.logger.warning(line)
        self.factory.logger.warning(
            "".join(traceback.format_exception(excType, excValue, tb)))

    def quirkyMessage(self, s):
        self.factory.logger.warning(s + "\n")

    # Protocol methods

    def connection_made(self, transport):
        LineReceiver.connection_made(self, transport)
        self.supported = ServerSupportedFeatures()
        self._queue = []
        if self.performLogin:
            self.register(self.nickname)

    def data_received(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        data = data.replace(b"\r", b"")
        LineReceiver.data_received(self, data)

    def line_received(self, line):
        if bytes != str and isinstance(line, bytes):
            # decode bytes from transport to unicode
            line = line.decode("utf-8")

        line = lowDequote(line)
        try:
            prefix, command, params = parsemsg(line)
            if command in numeric_to_symbolic:
                command = numeric_to_symbolic[command]
            self.handleCommand(command, prefix, params)
        except IRCBadMessage:
            self.badMessage(line, *sys.exc_info())

    def getUserModeParams(self):
        return ["", ""]

    def getChannelModeParams(self):
        # PREFIX modes are treated as "type B" CHANMODES, they always take
        # parameter.
        params = ["", ""]
        prefixes = self.supported.getFeature("PREFIX", {})
        params[0] = params[1] = "".join(prefixes.keys())

        chanmodes = self.supported.getFeature("CHANMODES")
        if chanmodes is not None:
            params[0] += chanmodes.get("addressModes", "")
            params[0] += chanmodes.get("param", "")
            params[1] = params[0]
            params[0] += chanmodes.get("setParam", "")
        return params

    def handleCommand(self, command, prefix, params):
        method = getattr(self, "irc_%s" % command, None)
        try:
            if method is not None:
                method(prefix, params)
            else:
                self.irc_unknown(prefix, command, params)
        except BaseException as e:
            self.factory.logger.error(f'handleCommand: {repr(e)}')

    def __getstate__(self):
        dct = self.__dict__.copy()
        dct["_pings"] = None
        return dct


M_QUOTE = chr(0o20)

mQuoteTable = {
    NUL: M_QUOTE + "0",
    NL: M_QUOTE + "n",
    CR: M_QUOTE + "r",
    M_QUOTE: M_QUOTE + M_QUOTE,
}

mDequoteTable = {}
for k, v in mQuoteTable.items():
    mDequoteTable[v[-1]] = k
del k, v

mEscape_re = re.compile(f"{re.escape(M_QUOTE)}.", re.DOTALL)


def lowQuote(s):
    for c in (M_QUOTE, NUL, NL, CR):
        s = s.replace(c, mQuoteTable[c])
    return s


def lowDequote(s):
    def sub(matchobj, mDequoteTable=mDequoteTable):
        s = matchobj.group()[1]
        try:
            s = mDequoteTable[s]
        except KeyError:
            s = s
        return s

    return mEscape_re.sub(sub, s)


# Constants (from RFC 2812)
RPL_WELCOME = "001"
RPL_YOURHOST = "002"
RPL_CREATED = "003"
RPL_MYINFO = "004"
RPL_ISUPPORT = "005"
RPL_BOUNCE = "010"
RPL_USERHOST = "302"
RPL_ISON = "303"
RPL_AWAY = "301"
RPL_UNAWAY = "305"
RPL_NOWAWAY = "306"
RPL_WHOISUSER = "311"
RPL_WHOISSERVER = "312"
RPL_WHOISOPERATOR = "313"
RPL_WHOISIDLE = "317"
RPL_ENDOFWHOIS = "318"
RPL_WHOISCHANNELS = "319"
RPL_WHOWASUSER = "314"
RPL_ENDOFWHOWAS = "369"
RPL_LISTSTART = "321"
RPL_LIST = "322"
RPL_LISTEND = "323"
RPL_UNIQOPIS = "325"
RPL_CHANNELMODEIS = "324"
RPL_NOTOPIC = "331"
RPL_TOPIC = "332"
RPL_INVITING = "341"
RPL_SUMMONING = "342"
RPL_INVITELIST = "346"
RPL_ENDOFINVITELIST = "347"
RPL_EXCEPTLIST = "348"
RPL_ENDOFEXCEPTLIST = "349"
RPL_VERSION = "351"
RPL_WHOREPLY = "352"
RPL_ENDOFWHO = "315"
RPL_NAMREPLY = "353"
RPL_ENDOFNAMES = "366"
RPL_LINKS = "364"
RPL_ENDOFLINKS = "365"
RPL_BANLIST = "367"
RPL_ENDOFBANLIST = "368"
RPL_INFO = "371"
RPL_ENDOFINFO = "374"
RPL_MOTDSTART = "375"
RPL_MOTD = "372"
RPL_ENDOFMOTD = "376"
RPL_YOUREOPER = "381"
RPL_REHASHING = "382"
RPL_YOURESERVICE = "383"
RPL_TIME = "391"
RPL_USERSSTART = "392"
RPL_USERS = "393"
RPL_ENDOFUSERS = "394"
RPL_NOUSERS = "395"
RPL_TRACELINK = "200"
RPL_TRACECONNECTING = "201"
RPL_TRACEHANDSHAKE = "202"
RPL_TRACEUNKNOWN = "203"
RPL_TRACEOPERATOR = "204"
RPL_TRACEUSER = "205"
RPL_TRACESERVER = "206"
RPL_TRACESERVICE = "207"
RPL_TRACENEWTYPE = "208"
RPL_TRACECLASS = "209"
RPL_TRACERECONNECT = "210"
RPL_TRACELOG = "261"
RPL_TRACEEND = "262"
RPL_STATSLINKINFO = "211"
RPL_STATSCOMMANDS = "212"
RPL_ENDOFSTATS = "219"
RPL_STATSUPTIME = "242"
RPL_STATSOLINE = "243"
RPL_UMODEIS = "221"
RPL_SERVLIST = "234"
RPL_SERVLISTEND = "235"
RPL_LUSERCLIENT = "251"
RPL_LUSEROP = "252"
RPL_LUSERUNKNOWN = "253"
RPL_LUSERCHANNELS = "254"
RPL_LUSERME = "255"
RPL_ADMINME = "256"
RPL_ADMINLOC1 = "257"
RPL_ADMINLOC2 = "258"
RPL_ADMINEMAIL = "259"
RPL_TRYAGAIN = "263"
ERR_NOSUCHNICK = "401"
ERR_NOSUCHSERVER = "402"
ERR_NOSUCHCHANNEL = "403"
ERR_CANNOTSENDTOCHAN = "404"
ERR_TOOMANYCHANNELS = "405"
ERR_WASNOSUCHNICK = "406"
ERR_TOOMANYTARGETS = "407"
ERR_NOSUCHSERVICE = "408"
ERR_NOORIGIN = "409"
ERR_NORECIPIENT = "411"
ERR_NOTEXTTOSEND = "412"
ERR_NOTOPLEVEL = "413"
ERR_WILDTOPLEVEL = "414"
ERR_BADMASK = "415"
# Defined in errata.
# https://www.rfc-editor.org/errata_search.php?rfc=2812&eid=2822
ERR_TOOMANYMATCHES = "416"
ERR_UNKNOWNCOMMAND = "421"
ERR_NOMOTD = "422"
ERR_NOADMININFO = "423"
ERR_FILEERROR = "424"
ERR_NONICKNAMEGIVEN = "431"
ERR_ERRONEUSNICKNAME = "432"
ERR_NICKNAMEINUSE = "433"
ERR_NICKCOLLISION = "436"
ERR_UNAVAILRESOURCE = "437"
ERR_USERNOTINCHANNEL = "441"
ERR_NOTONCHANNEL = "442"
ERR_USERONCHANNEL = "443"
ERR_NOLOGIN = "444"
ERR_SUMMONDISABLED = "445"
ERR_USERSDISABLED = "446"
ERR_NOTREGISTERED = "451"
ERR_NEEDMOREPARAMS = "461"
ERR_ALREADYREGISTRED = "462"
ERR_NOPERMFORHOST = "463"
ERR_PASSWDMISMATCH = "464"
ERR_YOUREBANNEDCREEP = "465"
ERR_YOUWILLBEBANNED = "466"
ERR_KEYSET = "467"
ERR_CHANNELISFULL = "471"
ERR_UNKNOWNMODE = "472"
ERR_INVITEONLYCHAN = "473"
ERR_BANNEDFROMCHAN = "474"
ERR_BADCHANNELKEY = "475"
ERR_BADCHANMASK = "476"
ERR_NOCHANMODES = "477"
ERR_BANLISTFULL = "478"
ERR_NOPRIVILEGES = "481"
ERR_CHANOPRIVSNEEDED = "482"
ERR_CANTKILLSERVER = "483"
ERR_RESTRICTED = "484"
ERR_UNIQOPPRIVSNEEDED = "485"
ERR_NOOPERHOST = "491"
ERR_NOSERVICEHOST = "492"
ERR_UMODEUNKNOWNFLAG = "501"
ERR_USERSDONTMATCH = "502"

# And hey, as long as the strings are already intern'd...
symbolic_to_numeric = {
    "RPL_WELCOME": "001",
    "RPL_YOURHOST": "002",
    "RPL_CREATED": "003",
    "RPL_MYINFO": "004",
    "RPL_ISUPPORT": "005",
    "RPL_BOUNCE": "010",
    "RPL_USERHOST": "302",
    "RPL_ISON": "303",
    "RPL_AWAY": "301",
    "RPL_UNAWAY": "305",
    "RPL_NOWAWAY": "306",
    "RPL_WHOISUSER": "311",
    "RPL_WHOISSERVER": "312",
    "RPL_WHOISOPERATOR": "313",
    "RPL_WHOISIDLE": "317",
    "RPL_ENDOFWHOIS": "318",
    "RPL_WHOISCHANNELS": "319",
    "RPL_WHOWASUSER": "314",
    "RPL_ENDOFWHOWAS": "369",
    "RPL_LISTSTART": "321",
    "RPL_LIST": "322",
    "RPL_LISTEND": "323",
    "RPL_UNIQOPIS": "325",
    "RPL_CHANNELMODEIS": "324",
    "RPL_NOTOPIC": "331",
    "RPL_TOPIC": "332",
    "RPL_INVITING": "341",
    "RPL_SUMMONING": "342",
    "RPL_INVITELIST": "346",
    "RPL_ENDOFINVITELIST": "347",
    "RPL_EXCEPTLIST": "348",
    "RPL_ENDOFEXCEPTLIST": "349",
    "RPL_VERSION": "351",
    "RPL_WHOREPLY": "352",
    "RPL_ENDOFWHO": "315",
    "RPL_NAMREPLY": "353",
    "RPL_ENDOFNAMES": "366",
    "RPL_LINKS": "364",
    "RPL_ENDOFLINKS": "365",
    "RPL_BANLIST": "367",
    "RPL_ENDOFBANLIST": "368",
    "RPL_INFO": "371",
    "RPL_ENDOFINFO": "374",
    "RPL_MOTDSTART": "375",
    "RPL_MOTD": "372",
    "RPL_ENDOFMOTD": "376",
    "RPL_YOUREOPER": "381",
    "RPL_REHASHING": "382",
    "RPL_YOURESERVICE": "383",
    "RPL_TIME": "391",
    "RPL_USERSSTART": "392",
    "RPL_USERS": "393",
    "RPL_ENDOFUSERS": "394",
    "RPL_NOUSERS": "395",
    "RPL_TRACELINK": "200",
    "RPL_TRACECONNECTING": "201",
    "RPL_TRACEHANDSHAKE": "202",
    "RPL_TRACEUNKNOWN": "203",
    "RPL_TRACEOPERATOR": "204",
    "RPL_TRACEUSER": "205",
    "RPL_TRACESERVER": "206",
    "RPL_TRACESERVICE": "207",
    "RPL_TRACENEWTYPE": "208",
    "RPL_TRACECLASS": "209",
    "RPL_TRACERECONNECT": "210",
    "RPL_TRACELOG": "261",
    "RPL_TRACEEND": "262",
    "RPL_STATSLINKINFO": "211",
    "RPL_STATSCOMMANDS": "212",
    "RPL_ENDOFSTATS": "219",
    "RPL_STATSUPTIME": "242",
    "RPL_STATSOLINE": "243",
    "RPL_UMODEIS": "221",
    "RPL_SERVLIST": "234",
    "RPL_SERVLISTEND": "235",
    "RPL_LUSERCLIENT": "251",
    "RPL_LUSEROP": "252",
    "RPL_LUSERUNKNOWN": "253",
    "RPL_LUSERCHANNELS": "254",
    "RPL_LUSERME": "255",
    "RPL_ADMINME": "256",
    "RPL_ADMINLOC1": "257",
    "RPL_ADMINLOC2": "258",
    "RPL_ADMINEMAIL": "259",
    "RPL_TRYAGAIN": "263",
    "ERR_NOSUCHNICK": "401",
    "ERR_NOSUCHSERVER": "402",
    "ERR_NOSUCHCHANNEL": "403",
    "ERR_CANNOTSENDTOCHAN": "404",
    "ERR_TOOMANYCHANNELS": "405",
    "ERR_WASNOSUCHNICK": "406",
    "ERR_TOOMANYTARGETS": "407",
    "ERR_NOSUCHSERVICE": "408",
    "ERR_NOORIGIN": "409",
    "ERR_NORECIPIENT": "411",
    "ERR_NOTEXTTOSEND": "412",
    "ERR_NOTOPLEVEL": "413",
    "ERR_WILDTOPLEVEL": "414",
    "ERR_BADMASK": "415",
    "ERR_TOOMANYMATCHES": "416",
    "ERR_UNKNOWNCOMMAND": "421",
    "ERR_NOMOTD": "422",
    "ERR_NOADMININFO": "423",
    "ERR_FILEERROR": "424",
    "ERR_NONICKNAMEGIVEN": "431",
    "ERR_ERRONEUSNICKNAME": "432",
    "ERR_NICKNAMEINUSE": "433",
    "ERR_NICKCOLLISION": "436",
    "ERR_UNAVAILRESOURCE": "437",
    "ERR_USERNOTINCHANNEL": "441",
    "ERR_NOTONCHANNEL": "442",
    "ERR_USERONCHANNEL": "443",
    "ERR_NOLOGIN": "444",
    "ERR_SUMMONDISABLED": "445",
    "ERR_USERSDISABLED": "446",
    "ERR_NOTREGISTERED": "451",
    "ERR_NEEDMOREPARAMS": "461",
    "ERR_ALREADYREGISTRED": "462",
    "ERR_NOPERMFORHOST": "463",
    "ERR_PASSWDMISMATCH": "464",
    "ERR_YOUREBANNEDCREEP": "465",
    "ERR_YOUWILLBEBANNED": "466",
    "ERR_KEYSET": "467",
    "ERR_CHANNELISFULL": "471",
    "ERR_UNKNOWNMODE": "472",
    "ERR_INVITEONLYCHAN": "473",
    "ERR_BANNEDFROMCHAN": "474",
    "ERR_BADCHANNELKEY": "475",
    "ERR_BADCHANMASK": "476",
    "ERR_NOCHANMODES": "477",
    "ERR_BANLISTFULL": "478",
    "ERR_NOPRIVILEGES": "481",
    "ERR_CHANOPRIVSNEEDED": "482",
    "ERR_CANTKILLSERVER": "483",
    "ERR_RESTRICTED": "484",
    "ERR_UNIQOPPRIVSNEEDED": "485",
    "ERR_NOOPERHOST": "491",
    "ERR_NOSERVICEHOST": "492",
    "ERR_UMODEUNKNOWNFLAG": "501",
    "ERR_USERSDONTMATCH": "502",
}

numeric_to_symbolic = {}
for k, v in symbolic_to_numeric.items():
    numeric_to_symbolic[v] = k
