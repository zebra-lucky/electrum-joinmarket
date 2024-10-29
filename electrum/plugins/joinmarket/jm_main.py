# -*- coding: utf-8 -*-

import asyncio
import pathlib
import logging
import threading

from electrum import constants, util
from electrum.i18n import _
from electrum.logging import Logger

from .jm_conf import JMConf
from .jm_wallet import JMWallet
from .jm_util import JMStates, JMGUILogHandler
from .jmclient import get_tumble_log


class JMManager(Logger):
    '''Class representing JoinMarket manager'''

    LOGGING_SHORTCUT = 'J'

    def __init__(self, wallet):
        self.debug = False
        self.wallet = wallet
        self.network = None
        self.loop = None
        self.config = config = wallet.config
        Logger.__init__(self)
        self.log_handler = JMGUILogHandler(self)
        self.logger = logging.LoggerAdapter(self.logger,
                                            {'jmman_id': id(self)})
        # tumble log will not always be used, but is made available anyway:
        self.tumble_logsdir = logsdir = pathlib.Path(config.path) / "logs"
        self.tumble_log = get_tumble_log(self, logsdir, config)

        self._state = JMStates.Unsupported
        self._stopped = False
        self.jmw = JMWallet(self)
        self.jmconf = JMConf(self)
        self.jmw.jmconf = self.jmconf

        self.states = JMStates
        self.state_lock = threading.Lock()

        self.postponed_notifications = {}

        self.wallet_types_supported = ['standard']
        self.keystore_types_supported = ['bip32']
        keystore = wallet.db.get('keystore')
        if keystore:
            self.w_ks_type = keystore.get('type', 'unknown')
        else:
            self.w_ks_type = 'unknown'
        self.w_type = wallet.wallet_type
        if (self.w_type in self.wallet_types_supported
                and self.w_ks_type in self.keystore_types_supported):
            if constants.net.TESTNET:
                jm_data = self.wallet.db.get('jm_data')
                if jm_data and jm_data.get('jm_enabled', False):
                    self._state = JMStates.Ready
                    self.jmw.init_jm_data()
                    self.jmconf.init_max_mixdepth()
                else:
                    self._state = JMStates.Disabled
        if self.unsupported:
            supported_w = ', '.join(self.wallet_types_supported)
            supported_ks = ', '.join(self.keystore_types_supported)
            this_type = self.w_type
            this_ks_type = self.w_ks_type
            if not constants.net.TESTNET:
                self.unsupported_msg = _(
                    'JoinMarket is currently not supported on mainnet')
            else:
                self.unsupported_msg = _(
                    f'JoinMarket plugin is currently supported on'
                    f' next wallet types: "{supported_w}"'
                    f' and keystore types: "{supported_ks}".'
                    f'\n\nThis wallet has type "{this_type}"'
                    f' and kestore type "{this_ks_type}".')
        else:
            self.unsupported_msg = ''
        self.client_factory = None

    def diagnostic_name(self):
        return str(self.wallet) if self.wallet else ''

    def set_client_factory(self, client_factory):
        self.client_factory = client_factory

    @property
    def state(self):
        '''Current state of JMManager (jm_util.JMStates enum)'''
        return self._state

    @state.setter
    def state(self, state):
        '''Set current state of JMManager'''
        if not self.enabled:
            self.logger.debug('Ignoring JMManager.state change '
                              'for disabled JMManager')
            return
        self._state = state

    @property
    def unsupported(self):
        '''Wallet and keystore types is not supported'''
        return self.state == JMStates.Unsupported

    @property
    def enabled(self):
        '''JM was enabled on this wallet'''
        return self.state not in [JMStates.Unsupported, JMStates.Disabled]

    @property
    def stopped(self):
        return self._stopped

    def enable_jm(self):
        '''Enables JM on this wallet, store changes in db.'''
        if not self.enabled:
            coro = self._enable_jm()
            fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
            return fut.result()
        else:
            return False

    async def _enable_jm(self):
        '''Start initialization, find untracked txs'''
        if self.enabled:
            return False
        self._state = JMStates.Ready
        self.jmw.init_jm_data()
        self.jmconf.init_max_mixdepth()
        self.jmw.set_jm_data('jm_enabled', True)
        await self.loop.run_in_executor(None, self.jmw.load_and_cleanup)
        self.wallet.save_db()
        self.logger.info('JMManager initialized')
        return True

    @property
    def is_mixing(self):
        return self.state == JMStates.Mixing

    def need_password(self):
        '''Check if password is needed to sign wallet transactions.'''
        return self.wallet.has_password()

    def on_network_start(self, network):
        '''Run when network is connected to the wallet'''
        self.network = network
        self.loop = network.asyncio_loop
        self.jmw.network = network
        self.jmw.loop = self.loop
        self.jmw.register_callbacks()
        self.jmw.on_network_start(network)
        asyncio.ensure_future(self.trigger_postponed_notifications())

    def stop(self):
        '''Run when the wallet is unloaded/stopped'''
        self._stopped = True
        self.jmw.unregister_callbacks()

    def postpone_notification(self, event, *args):
        '''Postpone notification to send many analogous notifications as one'''
        self.postponed_notifications[event] = args

    async def trigger_postponed_notifications(self):
        '''Trigger postponed notification'''
        while True:
            await asyncio.sleep(0.5)
            for event in list(self.postponed_notifications.keys()):
                args = self.postponed_notifications.pop(event, tuple())
                try:
                    util.trigger_callback(event, *args)
                except Exception as e:
                    self.logger.warning(f'trigger_callback: {repr(e)}')
