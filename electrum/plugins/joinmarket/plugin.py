#!/usr/bin/env python
# -*- coding: utf-8 -*-

from electrum.i18n import _
from electrum.network import Network
from electrum.plugin import BasePlugin

from .jm_main import JMManager


class JoinMarketPlugin(BasePlugin):

    MSG_TITLE = _('JoinMarket')

    def __init__(self, parent, config, name):
        super(JoinMarketPlugin, self).__init__(parent, config, name)
        self._wallets = set()

    @property
    def title(self):
        return self.MSG_TITLE

    def is_available(self):
        if Network.get_instance():
            return True
        self.logger.warning(f'Plugin {self.name} unavailable in offline mode')
        return False

    def load_wallet(self, wallet):
        self._wallets.add(wallet)
        wallet.jmman = JMManager(wallet)
        network = wallet.network
        if network:
            wallet.jmman.on_network_start(network)

    def close_wallet(self, wallet):
        if wallet not in self._wallets:
            return
        wallet.jmman.stop()
        del wallet.jmman
        self._wallets.remove(wallet)
