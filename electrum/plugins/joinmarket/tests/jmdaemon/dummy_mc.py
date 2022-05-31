# -*- coding: utf-8 -*-

import asyncio

from electrum.logging import get_logger, ShortcutInjectingFilter

from electrum.plugins.joinmarket.jmdaemon.message_channel import MessageChannel

from .msgdata import t_orderbook


LOGGING_SHORTCUT = 'J'
log = get_logger(__name__)
log.addFilter(ShortcutInjectingFilter(shortcut=LOGGING_SHORTCUT))


# handle one channel at a time
class DummyMessageChannel(MessageChannel):

    def __init__(self,
                 jmman,
                 configdata,
                 username='username',
                 realname='realname',
                 password=None,
                 hostid=None):
        MessageChannel.__init__(self)
        self.jmman = jmman
        self.logger = jmman.logger
        self.give_up = False
        self.counterparties = [x['counterparty'] for x in t_orderbook]
        self.hostid = "dummy"
        if hostid:
            self.hostid = hostid
        self.serverport = self.hostid

    def __str__(self):
        return self.hostid

    async def run(self):
        """Simplest possible event loop."""
        i = 0
        while True:
            if self.give_up:
                log.debug("shutting down a mc due to give up, name=" +
                          str(self))
                break
            await asyncio.sleep(0.5)
            if i == 1:
                if self.on_welcome:
                    log.debug("Calling on welcome")
            i += 1

    async def shutdown(self):
        self.give_up = True

    async def _pubmsg(self, msg):
        pass

    async def _privmsg(self, nick, cmd, message):
        """As for pubmsg
        """

    async def _announce_orders(self, orderlist):
        pass

    def change_nick(self, new_nick):
        print("Changing nick supposedly")
