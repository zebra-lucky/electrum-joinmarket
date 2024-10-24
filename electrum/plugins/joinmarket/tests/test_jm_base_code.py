# -*- coding: utf-8 -*-

import electrum_ecc as ecc

from electrum.transaction import Transaction
from electrum.util import bfh, TxMinedInfo
from electrum.plugins.joinmarket.jmbase import utxostr_to_utxo
from electrum.plugins.joinmarket.jmclient import (
    get_random_bytes, WalletMixdepthOutOfRange, EngineError,
    NotEnoughFundsException, select, select_gradual, select_greedy,
    select_greediest)

from electrum.plugins.joinmarket.tests import (
    JMTestCase, DummyJMWallet, tx1_txid)


reuse_txid = 'a86bca4072d4bd8f074b078cda1d8b84d2e7163bbd40f166d41260f510923c52'
raw_reuse_tx = (
    '02000000000101e6bb4c58d49e7d325a91c69a053ce7dc3dc3c2b8f9d4be08fb'
    'dec6e27a3e17010100000000fdffffff0210270000000000001600140cac01dc'
    '51b1a082c714c395d35da4895c02475c1c6da30000000000160014e1175a86df'
    '8011c59f0f51f00c9fe7b9eed4536602473044022054a365afcd9cd78c672531'
    '58582329b964c210e4efce533762d2ea6b7baa75f002206e5a6e2f0fef3772fe'
    'ea6b8a671671317d31f857fd6d361242a390af2e48fdcb0121024daffd007ec8'
    '3a1ab219961077d176f3b7b8577b9f1667989728bab7ff5f934992522d00'
)


class JMBaseCodeMixinTestCase(JMTestCase):

    async def test_mk_freeze_script(self):
        jmw = self.jmw
        privk = ecc.ECPrivkey.generate_random_key()
        pubk_bytes = privk.get_public_key_bytes()
        locktime = 500000000 + 1723833376  # 16 Aug 2024, 18:36:16 UTC
        script = jmw.mk_freeze_script(pubk_bytes, locktime)

        assert isinstance(script, bytes)
        assert len(script) == 43

        with self.assertRaises(TypeError):
            script = jmw.mk_freeze_script(pubk_bytes, pubk_bytes)

        with self.assertRaises(TypeError):
            script = jmw.mk_freeze_script(locktime, locktime)

        bad_pubk_bytes = b'\x02' + b'\x05'*32
        with self.assertRaises(ecc.InvalidECPointException):
            script = jmw.mk_freeze_script(bad_pubk_bytes, locktime)

    async def test_redeem_script_to_p2wsh_script(self):
        jmw = self.jmw
        redeem_script = get_random_bytes(32)
        p2wsh_script = jmw.redeem_script_to_p2wsh_script(redeem_script)

        assert isinstance(p2wsh_script, bytes)
        assert len(p2wsh_script) == 34

    async def test_get_median_time_past(self):
        jmw = self.jmw
        bch = self.network.blockchain()
        t = jmw.get_median_time_past(bch)
        assert t == 1723829360
        bch.no_headers = True
        t = jmw.get_median_time_past(bch)
        assert t is None
        bch.no_headers = False

    async def test_estimate_fee_basic(self):
        jmw = self.jmw
        assert jmw._estimate_fee_basic(5) is None
        jmw.config.fee_estimates = {25: 2337, 10: 2856, 5: 11900, 2: 18107}
        assert jmw._estimate_fee_basic(1) == (27160, 2)
        assert jmw._estimate_fee_basic(2) == (18107, 2)
        assert jmw._estimate_fee_basic(3) == (11900, 3)
        assert jmw._estimate_fee_basic(4) == (11900, 4)
        assert jmw._estimate_fee_basic(5) == (11900, 5)
        assert jmw._estimate_fee_basic(6) == (2856, 6)
        assert jmw._estimate_fee_basic(9) == (2856, 9)
        assert jmw._estimate_fee_basic(10) == (2856, 10)
        assert jmw._estimate_fee_basic(11) == (2337, 11)
        assert jmw._estimate_fee_basic(24) == (2337, 24)
        assert jmw._estimate_fee_basic(25) == (2337, 25)
        assert jmw._estimate_fee_basic(26) == (2337, 26)
        assert jmw._estimate_fee_basic(50) == (2337, 50)

    async def test_estimate_fee_per_kb(self):
        jmw = self.jmw
        jmw.config.fee_estimates = {25: 2337, 10: 2856, 5: 11900, 2: 18107}
        jmw.jmconf.tx_fees_factor = 0
        assert jmw.estimate_fee_per_kb(-1) == 18107
        assert jmw.estimate_fee_per_kb(0) == 18107
        assert jmw.estimate_fee_per_kb(1) == 27160
        assert jmw.estimate_fee_per_kb(2) == 18107
        assert jmw.estimate_fee_per_kb(5) == 11900
        assert jmw.estimate_fee_per_kb(10) == 2856
        assert jmw.estimate_fee_per_kb(25) == 2337
        assert jmw.estimate_fee_per_kb(1001) == 1001

        jmw.jmconf.tx_fees_factor = 0.2

        v = 0
        for i in range(10):
            v += jmw.estimate_fee_per_kb(1)
        assert 27160 < v/10 < 27160 * 1.2

        jmw.config.fee_estimates = {}
        jmw.jmconf.tx_fees_factor = 0
        assert jmw.estimate_fee_per_kb(-1) == 20000
        assert jmw.estimate_fee_per_kb(0) == 20000
        assert jmw.estimate_fee_per_kb(1) == 20000
        assert jmw.estimate_fee_per_kb(2) == 20000
        assert jmw.estimate_fee_per_kb(5) == 20000
        assert jmw.estimate_fee_per_kb(10) == 20000
        assert jmw.estimate_fee_per_kb(25) == 20000
        assert jmw.estimate_fee_per_kb(1001) == 1001

        jmw.jmconf.tx_fees_factor = 0.2

        v = 0
        for i in range(10):
            v += jmw.estimate_fee_per_kb(1)
        assert 20000 < v/10 < 20000 * 1.2

    async def test_query_utxo_set(self):
        jmw = self.jmw
        jm_utxos = [utxostr_to_utxo(u)[1] for u in jmw.get_jm_utxos()]
        jm_utxos.sort(key=lambda x: x[1])
        unknown_utxo = utxostr_to_utxo('00'*32 + ':0')[1]
        res = await jmw.query_utxo_set(unknown_utxo)
        assert not res
        assert isinstance(res, list)
        res = await jmw.query_utxo_set(jm_utxos[0], includeconfs=True)
        assert res == [{
            'value': 2500000,
            'address': 'tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk',
            'confirms': 9000001,
            'script': bfh('00140cac01dc51b1a082c714c395d35da4895c02475c'),
        }]

    async def test_get_bip32_pub_export(self):
        assert self.jmw.get_bip32_pub_export() == (
            'vpub5UF8rwHwPFB8erd6QGeJDo68qnfwfPsTV38wmeYtrTQXD7vCvcgBVhpK'
            'UfWj3QHBCjtSKr4aJH5nFdjqoqRJchK82QCYEufqKs7Lzcf8FP1')

    async def test_get_path(self):
        jmw = self.jmw
        assert jmw.get_path(mixdepth=4) == ()
        assert jmw.get_path(mixdepth=4, address_type='p2sh',
                            index=0) == ('p2sh', 0)

        with self.assertRaises(WalletMixdepthOutOfRange):
            jmw.get_path(mixdepth=5)

        with self.assertRaises(Exception):
            jmw.get_path(address_type='p2sh')

        with self.assertRaises(Exception):
            assert jmw.get_path(mixdepth=5, index=0) == ()

    async def test_get_path_repr(self):
        jmw = self.jmw
        assert jmw.get_path_repr([0, 0]) == 'm/0/0'
        assert jmw.get_path_repr([0, 1]) == 'm/0/1'
        assert jmw.get_path_repr([1, 1]) == 'm/1/1'

    async def test_calculate_timelocked_fidelity_bond_value(self):
        jmw = self.jmw
        utxo_value = 50000
        conf_time = 1723864595
        cur_time = conf_time + 50000
        locktime = conf_time + 500000
        interest_rate = 0.015
        val = jmw.calculate_timelocked_fidelity_bond_value(
            utxo_value, conf_time, locktime, cur_time, interest_rate)
        self.assertAlmostEqual(val, 24.9738, 4)

    async def test_get_validated_timelocked_fidelity_bond_utxo(self):
        jmman = self.jmman

        def clean_up():
            jmman.jmw = old_jmw

        old_jmw = jmman.jmw
        jmman.jmw = jmw = DummyJMWallet(jmman)
        jmw.jmconf = old_jmw.jmconf

        w = jmw.wallet
        idx = w.get_address_index('tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk')
        keypair = w.keystore.get_keypair(idx, None)
        jm_utxos = [utxostr_to_utxo(u)[1] for u in jmw.get_jm_utxos()]
        utxo_pub_key = keypair[0]
        conf_time = 1723864595
        locktime = conf_time + 500000
        cert_expiry = 15
        current_block_height = 2016 * cert_expiry

        fake_query_results = [{
            'value': 2500000,
            'address': 'tb1qs33rq0wmrq2awvuxrte0mqkksvzr6x9sdkrfdc',
            'script': bfh('00205d11e8d562de9e72e6cc44f98ea86e'
                          'c4fa28c70947a273aa2866f1917b54e26b'),
            'confirms': 9000001,
            'utxo': jm_utxos[0],
        }]
        jmw.insert_fake_query_results(fake_query_results)
        val = await jmw.get_validated_timelocked_fidelity_bond_utxo(
            jm_utxos[0], utxo_pub_key, locktime,
            cert_expiry, current_block_height)
        assert val
        assert isinstance(val, dict)

        jmw.insert_fake_query_results(None)
        clean_up()

    async def test_pubkey_has_script(self):
        jmw = self.jmw
        w = jmw.wallet
        addr = 'tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk'
        idx = w.get_address_index(addr)
        keypair = w.keystore.get_keypair(idx, None)
        pubkey = keypair[0]
        script = bfh('00140cac01dc51b1a082c714c395d35da4895c02475c')
        assert jmw.pubkey_has_script(pubkey, script)

        with self.assertRaises(EngineError):
            assert jmw.pubkey_has_script(pubkey, b'\x00' + script)

    async def test_get_key_from_addr(self):
        jmw = self.jmw
        w = jmw.wallet
        addr = 'tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk'
        idx = w.get_address_index(addr)
        keypair = w.keystore.get_keypair(idx, None)
        assert jmw.get_key_from_addr(addr) == keypair[1]

        assert await jmw.make_keypairs_cache(None, None)
        assert jmw.get_key_from_addr(addr) == keypair[1]

    async def test_get_script_from_path(self):
        jmw = self.jmw
        w = jmw.wallet
        addr = 'tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk'
        idx = w.get_address_index(addr)
        script = bfh('00140cac01dc51b1a082c714c395d35da4895c02475c')
        assert jmw.get_script_from_path(idx) == script

    async def test_script_to_addr(self):
        jmw = self.jmw
        addr = 'tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk'
        script = bfh('00140cac01dc51b1a082c714c395d35da4895c02475c')
        assert jmw.script_to_addr(script) == addr

    async def test_script_to_path(self):
        jmw = self.jmw
        w = jmw.wallet
        addr = 'tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk'
        idx = w.get_address_index(addr)
        script = bfh('00140cac01dc51b1a082c714c395d35da4895c02475c')
        assert jmw.script_to_path(script) == idx

    async def test_is_standard_wallet_script(self):
        jmw = self.jmw
        script = bfh('00140cac01dc51b1a082c714c395d35da4895c02475c')
        assert jmw.is_standard_wallet_script(script)
        script = bfh('00205d11e8d562de9e72e6cc44f98ea86e'
                     'c4fa28c70947a273aa2866f1917b54e26b'),
        assert not jmw.is_standard_wallet_script(script)

    async def test_get_address_from_path(self):
        jmw = self.jmw
        w = jmw.wallet
        addr = 'tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk'
        idx = w.get_address_index(addr)
        assert jmw.get_address_from_path(idx) == addr

    async def test_get_balance_by_mixdepth(self):
        jmw = self.jmw
        w = jmw.wallet
        utxos = [('b82763a40e3c701669cb57341a8116d7'
                  'f6d4cd2dbd0648d839c6b754aac37dd2:1')]

        w.set_frozen_state_of_coins(utxos, True)
        b = jmw.get_balance_by_mixdepth(include_disabled=True)
        assert b == {0: 2500000, 1: 7500000, 2: 0, 3: 0, 4: 0}

        b = jmw.get_balance_by_mixdepth()
        assert b == {0: 2500000, 1: 5000000, 2: 0, 3: 0, 4: 0}
        w.set_frozen_state_of_coins(utxos, False)

        b = jmw.get_balance_by_mixdepth(minconfs=1e7)
        assert b == {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}

    async def test_get_balance_at_mixdepth(self):
        jmw = self.jmw
        w = jmw.wallet
        utxos = [('b82763a40e3c701669cb57341a8116d7'
                  'f6d4cd2dbd0648d839c6b754aac37dd2:1')]

        w.set_frozen_state_of_coins(utxos, True)
        assert jmw.get_balance_at_mixdepth(0) == 2500000
        assert jmw.get_balance_at_mixdepth(1) == 5000000
        assert jmw.get_balance_at_mixdepth(1, include_disabled=True) == 7500000
        assert jmw.get_balance_at_mixdepth(2) == 0
        w.set_frozen_state_of_coins(utxos, False)

        assert jmw.get_balance_at_mixdepth(0, maxheight=1e5) == 0
        assert jmw.get_balance_at_mixdepth(1, maxheight=1e5) == 0

    async def test_get_utxos_at_mixdepth(self):
        jmw = self.jmw
        w = jmw.wallet
        utxos = [('b82763a40e3c701669cb57341a8116d7'
                  'f6d4cd2dbd0648d839c6b754aac37dd2:1')]

        w.set_frozen_state_of_coins(utxos, True)
        assert len(jmw.get_utxos_at_mixdepth(0, includeheight=True)) == 1
        assert len(jmw.get_utxos_at_mixdepth(1, includeheight=True)) == 2
        assert len(jmw.get_utxos_at_mixdepth(1, include_disabled=True)) == 3
        assert len(jmw.get_utxos_at_mixdepth(2)) == 0
        w.set_frozen_state_of_coins(utxos, False)

    async def test_get_utxos_by_mixdepth(self):
        jmw = self.jmw
        w = jmw.wallet
        utxos = [('b82763a40e3c701669cb57341a8116d7'
                  'f6d4cd2dbd0648d839c6b754aac37dd2:1')]

        w.set_frozen_state_of_coins(utxos, True)
        u = jmw.get_utxos_by_mixdepth(include_disabled=True, includeconfs=True)
        assert sorted(u.keys()) == [0, 1]
        assert len(u[0].keys()) == 1
        assert len(u[1].keys()) == 3
        assert len(list(u[1].values())[1]) == 6  # includeconfs

        u = jmw.get_utxos_by_mixdepth()
        assert sorted(u.keys()) == [0, 1, 2, 3, 4]  # FIXME for emtpy depths?
        assert len(u[0].keys()) == 1
        assert len(u[1].keys()) == 2
        assert len(u[2].keys()) == 0
        assert len(list(u[1].values())[1]) == 5  # no includeconfs
        w.set_frozen_state_of_coins(utxos, False)

    async def test_get_utxos_enabled_disabled(self):
        jmw = self.jmw
        w = jmw.wallet
        utxos = [('b82763a40e3c701669cb57341a8116d7'
                  'f6d4cd2dbd0648d839c6b754aac37dd2:1')]
        w.set_frozen_state_of_coins(utxos, True)
        e, d = jmw.get_utxos_enabled_disabled(md=0)
        assert len(e) == 1
        assert len(d) == 0
        e, d = jmw.get_utxos_enabled_disabled(md=1)
        assert len(e) == 2
        assert len(d) == 1
        e, d = jmw.get_utxos_enabled_disabled(md=2)
        assert len(e) == 0
        assert len(d) == 0
        w.set_frozen_state_of_coins(utxos, False)
        e, d = jmw.get_utxos_enabled_disabled(md=1)
        assert len(e) == 3
        assert len(d) == 0

    async def test_select_utxos(self):
        jmw = self.jmw
        w = jmw.wallet
        utxos = [('b82763a40e3c701669cb57341a8116d7'
                  'f6d4cd2dbd0648d839c6b754aac37dd2:1')]
        w.set_frozen_state_of_coins(utxos, True)

        with self.assertRaises(NotEnoughFundsException):
            u = jmw.select_utxos(mixdepth=0, amount=5000000)

        u = jmw.select_utxos(mixdepth=0, amount=2500000)
        assert len(u) == 1

        with self.assertRaises(NotEnoughFundsException):
            u = jmw.select_utxos(mixdepth=1, amount=7500000)

        u = jmw.select_utxos(mixdepth=1, amount=5000000)
        assert len(u) == 2

        w.set_frozen_state_of_coins(utxos, False)

    async def test_minconfs_to_maxheight(self):
        jmw = self.jmw
        assert jmw._minconfs_to_maxheight(None) is None
        assert jmw._minconfs_to_maxheight(5) == 9999995

    async def test_get_merge_algorithm(self):
        jmw = self.jmw
        assert jmw._get_merge_algorithm() == select
        assert jmw._get_merge_algorithm('default') == select
        assert jmw._get_merge_algorithm('gradual') == select_gradual
        assert jmw._get_merge_algorithm('greedy') == select_greedy
        assert jmw._get_merge_algorithm('greediest') == select_greediest
        with self.assertRaises(Exception):
            assert jmw._get_merge_algorithm('unknown')

    async def test_get_outtype(self):
        jmw = self.jmw
        addr = 'tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk'
        assert jmw.get_outtype(addr) == 'p2wpkh'
        assert jmw.get_outtype('notaddr') == 'invalid bitcoin address'

    async def test_get_internal_addr(self):
        jmw = self.jmw
        addr = jmw.get_internal_addr(0)
        assert addr == 'tb1qnaa3sy52lfljerrv824al34dp2k79d7wyu3mgf'
        addr = jmw.get_internal_addr(1)
        assert addr == 'tb1q96rpwjr8ymrd8wavsp9eswqwxv45gvlz38689z'
        addr = jmw.get_internal_addr(2)
        assert addr == 'tb1q6m6x07ks6dt2sl66knygp2g2x4pata7staasuh'

        with self.assertRaises(WalletMixdepthOutOfRange):
            jmw.get_internal_addr(-1)
        with self.assertRaises(WalletMixdepthOutOfRange):
            jmw.get_internal_addr(1e9)

    async def test_estimate_tx_fee(self):
        jmw = self.jmw
        assert jmw.estimate_tx_fee(6, 8) == 66700
        assert jmw.estimate_tx_fee(6, 8, txtype='p2pkh') == 117000
        assert jmw.estimate_tx_fee(6, 8, outtype=['p2wpkh']*8) == 66700

    async def test_wallet_service_register_callbacks(self):
        jmw = self.jmw

        def cb1(txd, txid):
            return True

        def cb2(txd, txid):
            return True

        def cb3(txd, txid, confs):
            return True

        callbacks = jmw.callbacks
        assert callbacks == {'all': [], 'confirmed': {}, 'unconfirmed': {}}
        jmw.wallet_service_register_callbacks([cb1], 'txid1')
        jmw.wallet_service_register_callbacks([cb2], 'txid2', 'unconfirmed')
        jmw.wallet_service_register_callbacks([cb3], 'txid3', 'confirmed')
        with self.assertRaises(AssertionError):
            jmw.wallet_service_register_callbacks([cb1], 'txid1', 'unknown')

        assert len(callbacks['all']) == 1
        assert callbacks['all'][0] == cb1
        assert len(callbacks['unconfirmed']['txid2']) == 1
        assert callbacks['unconfirmed']['txid2'][0] == cb2
        assert len(callbacks['confirmed']['txid3']) == 1
        assert callbacks['confirmed']['txid3'][0] == cb3

    async def _prepare_cb1_cb2_cb3(self):

        def cb1(txd, txid):
            return True

        def cb2(txd, txid):
            return True

        def cb3(txd, txid, confs):
            return True

        jmw = self.jmw
        jmw.wallet_service_register_callbacks([cb1], tx1_txid)
        jmw.wallet_service_register_callbacks([cb2], tx1_txid, 'unconfirmed')
        jmw.wallet_service_register_callbacks([cb3], tx1_txid, 'confirmed')
        txd = await jmw.get_tx(tx1_txid)
        return cb1, cb2, cb3, txd, tx1_txid

    async def test_check_for_reuse(self):
        jmw = self.jmw
        w = self.w
        reuse_tx = Transaction(raw_reuse_tx)
        w.adb.add_transaction(reuse_tx)
        w.adb.add_verified_tx(reuse_txid,
                              TxMinedInfo(int(1e6), 10, 10, 10, 10))

        first_coin = None
        reuse_coin = None
        self.cb_called = False

        coins = w.adb.get_utxos(['tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk'])
        for c in coins:
            if c.value_sats() == 2500000:  # First transaction
                first_coin = c
            elif c.value_sats() == 10000:  # Reuse transaction
                reuse_coin = c

        assert first_coin
        assert reuse_coin
        assert not w.is_frozen_coin(first_coin)
        assert not w.is_frozen_coin(reuse_coin)

        def autofreeze_warning_cb(outpoint, utxo):
            assert reuse_coin.prevout.to_str() == outpoint
            self.cb_called = True

        jmw.set_autofreeze_warning_cb(autofreeze_warning_cb)
        await jmw.transaction_monitor(reuse_tx, reuse_txid)

        assert not w.is_frozen_coin(first_coin)
        assert w.is_frozen_coin(reuse_coin)
        assert self.cb_called

    async def test_transaction_monitor(self):
        jmw = self.jmw
        cb1, cb2, cb3, txd, txid = await self._prepare_cb1_cb2_cb3()
        jmw.active_txs[txid] = txd
        await jmw.transaction_monitor(txd, txid)
        assert jmw.active_txs == {}

    async def test_check_callback_called(self):
        jmw = self.jmw
        _, cb2, cb3, txd, txid = await self._prepare_cb1_cb2_cb3()
        jmw.active_txs[txid] = txd
        await jmw.transaction_monitor(txd, txid)
        assert jmw.active_txs == {}
        assert jmw.check_callback_called(txid, cb3, 'confirmed', 'msg')
        assert not jmw.check_callback_called(txid, cb2, 'unconfirmed', 'msg')
