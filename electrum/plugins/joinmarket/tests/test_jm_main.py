# -*- coding: utf-8 -*-

import copy
from unittest import mock

from electrum import constants, util, storage, SimpleConfig
from electrum.wallet import restore_wallet_from_text

from tests import ElectrumTestCase

from electrum.plugins.joinmarket.jm_main import JMManager
from electrum.plugins.joinmarket.jm_util import JMStates
from electrum.plugins.joinmarket.tests import (
    SynchronizerMock, VerifyierMock, NetworkMock)


class JMManagerInitTestCase(ElectrumTestCase):
    '''Separate testcase to test JMManager'''

    TESTNET = True

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.patcher = mock.patch.object(storage.WalletStorage, 'write')
        self.patcher.start()

        self.asyncio_loop = util.get_asyncio_loop()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.config.FEE_EST_DYNAMIC = False
        self.config.FEE_EST_STATIC_FEERATE = 100000
        self.w = w = restore_wallet_from_text('logic observe arrest marriage '
                                              'crew bounce dismiss audit grunt'
                                              ' identify rate supply',
                                              path='if_this_exists_mocking'
                                              '_failed_648151893',
                                              gap_limit=10,
                                              config=self.config)['wallet']
        self.w.adb.synchronizer = SynchronizerMock()
        self.w.adb.verifier = VerifyierMock()
        self.w._up_to_date = True
        self.w.db.put('stored_height', int(1e7))
        self.network = NetworkMock(self.asyncio_loop, self.config, w)

    async def asyncTearDown(self):
        await self.w.stop()
        self.patcher.stop()

    async def test_init(self):
        w = self.w
        keystore = w.db.get('keystore')
        keystore_backup = copy.deepcopy(keystore)

        keystore['type'] = 'sometype'
        jmman = JMManager(w)
        assert jmman.unsupported
        assert not jmman.enabled
        assert jmman.state == JMStates.Unsupported

        keystore = w.db.put('keystore', None)
        jmman = JMManager(w)
        assert jmman.unsupported
        assert not jmman.enabled
        assert jmman.state == JMStates.Unsupported

        keystore = w.db.put('keystore', keystore_backup)
        jmman = JMManager(w)
        assert not jmman.enabled
        assert not jmman.unsupported
        assert jmman.state == JMStates.Disabled

        jmman = JMManager(w)
        jmman.on_network_start(self.network)
        assert not jmman.enabled
        assert not jmman.unsupported
        assert jmman.state == JMStates.Disabled
        await jmman._enable_jm()
        assert jmman.enabled
        assert jmman.state == JMStates.Ready
        jmman.stop()

    async def test_init_on_mainnet(self):
        w = self.w
        constants.BitcoinMainnet.set_as_network()
        jmman = JMManager(w)
        assert not jmman.enabled
        assert jmman.unsupported
        assert 'mainnet' in jmman.unsupported_msg

    async def test_init_jm_data(self):
        w = self.w
        db = w.db
        jmman = JMManager(w)
        jmman.on_network_start(self.network)
        jmw = jmman.jmw

        assert db.get('jm_data') is None
        assert db.get('jm_addresses') is None
        assert db.get('jm_commitments') is None
        assert db.get('jm_txs') is None

        jmw.init_jm_data()
        assert db.get('jm_data') is None
        assert db.get('jm_addresses') is None
        assert db.get('jm_commitments') is None
        assert db.get('jm_txs') is None

        await jmman._enable_jm()
        assert db.get('jm_data') == {'jm_enabled': True}
        assert db.get('jm_addresses') is not None
        assert db.get('jm_commitments') is not None
        assert db.get('jm_txs') is not None
        jmman.stop()

    async def test_enable_jm(self):
        w = self.w
        jmman = JMManager(w)
        jmman.on_network_start(self.network)
        assert not jmman.enabled

        enabled = await jmman.loop.run_in_executor(None, jmman.enable_jm)
        assert enabled
        assert jmman.enabled

        enabled = await jmman.loop.run_in_executor(None, jmman.enable_jm)
        assert jmman.enabled
        assert not enabled

        enabled = await jmman._enable_jm()
        assert jmman.enabled
        assert not enabled
        jmman.stop()
