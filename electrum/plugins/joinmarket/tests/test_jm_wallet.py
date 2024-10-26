# -*- coding: utf-8 -*-

import asyncio
from unittest import mock

from electrum.wallet import Abstract_Wallet
from electrum.synchronizer import Synchronizer

from electrum.plugins.joinmarket.tests import JMTestCase
from electrum.plugins.joinmarket.jm_util import JMAddress, JMUtxo, KPStates
from electrum.plugins.joinmarket.jm_wallet import JMWallet, KeypairNotFound


class KeyPairsMixinTestCase(JMTestCase):

    async def test_keypairs_state(self):
        jmw = self.jmman.jmw
        assert jmw.keypairs_state == KPStates.Empty
        jmw.keypairs_state = KPStates.Ready
        assert jmw.keypairs_state == KPStates.Ready

    @mock.patch.object(Abstract_Wallet, 'has_password', return_value=True)
    async def test_check_need_new_keypairs_true(self, mock_has_password):
        assert self.jmman.jmw.check_need_new_keypairs()

    @mock.patch.object(Abstract_Wallet, 'has_password', return_value=False)
    async def test_check_need_new_keypairs_false(self, mock_has_password):
        assert not self.jmman.jmw.check_need_new_keypairs()

    async def test_cleanup_keypairs(self):
        jmw = self.jmman.jmw
        assert await jmw.make_keypairs_cache(None, None)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 60
        await jmw.cleanup_keypairs()
        assert jmw.keypairs_state == KPStates.Empty
        assert len(jmw._keypairs_cache) == 0

    async def test_make_keypairs_cache(self):
        jmw = self.jmman.jmw
        assert jmw.keypairs_state == KPStates.Empty
        assert len(jmw._keypairs_cache) == 0

        def cached_cb():
            raise Exception('fail')

        assert await jmw.make_keypairs_cache(None, cached_cb)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 60
        assert not await jmw.make_keypairs_cache(None, None)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 60

    @mock.patch.object(JMWallet, '_cache_keypairs', side_effect=Exception('e'))
    async def test_make_keypairs_cache_fails(self, mock__cache_keypairs):
        jmw = self.jmman.jmw
        assert jmw.keypairs_state == KPStates.Empty
        assert len(jmw._keypairs_cache) == 0

        assert not await jmw.make_keypairs_cache(None, None)
        assert jmw.keypairs_state == KPStates.Empty
        assert len(jmw._keypairs_cache) == 0

    async def test_cache_keypairs(self):
        jmw = self.jmman.jmw
        assert jmw.keypairs_state == KPStates.Empty
        assert len(jmw._keypairs_cache) == 0
        assert jmw._cache_keypairs(None)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 60
        assert not jmw._cache_keypairs(None)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 60

        # test other algo with tx_cnt
        await jmw.cleanup_keypairs()
        assert jmw._cache_keypairs(None, tx_cnt=0)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 4

        await jmw.cleanup_keypairs()
        assert jmw._cache_keypairs(None, tx_cnt=1)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 64

        await jmw.cleanup_keypairs()
        assert jmw._cache_keypairs(None, tx_cnt=2)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 124

        await jmw.cleanup_keypairs()
        assert jmw._cache_keypairs(None, tx_cnt=3)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 184

        await jmw.cleanup_keypairs()
        assert jmw._cache_keypairs(None, tx_cnt=4)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 244

        await jmw.cleanup_keypairs()
        assert jmw._cache_keypairs(None, tx_cnt=20)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 1204

    async def test_get_cached_key(self):
        jmw = self.jmman.jmw
        await jmw.make_keypairs_cache(None, None)
        addr = 'tb1q29r4lv7qnu3j3q8cm9wfwht0yvkf74umquf7vr'
        key_hex = ('4ff86e1e68243594bbfe06985f60f8ce'
                   '7805ba49c861126c5e34ebda68a6727d')
        assert jmw.get_cached_key(addr).hex() == key_hex
        unknown_addr = 'unk' + addr
        with self.assertRaises(KeypairNotFound):
            jmw.get_cached_key(unknown_addr)

    async def test_get_keypairs(self):
        jmw = self.jmman.jmw
        assert await jmw.make_keypairs_cache(None, None)
        assert jmw.keypairs_state == KPStates.Ready
        assert len(jmw._keypairs_cache) == 60
        keypairs = jmw.get_keypairs()
        assert len(keypairs) == 60


class WalletDBMixinTestCase(JMTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        jmw = self.jmw
        jmw.pop_jm_data('minimum_makers')
        jmw.pop_jm_data('taker_utxo_age')
        jmw.pop_jm_data('tx_fees')
        jmw.pop_jm_data('tx_fees_factor')
        assert self.w.db.get_dict('jm_data') == {'jm_enabled': True}

    async def test_get_jm_data(self):
        jmw = self.jmw
        assert jmw.get_jm_data('key1') is None
        jmw.set_jm_data('key1', 'value1')
        assert jmw.get_jm_data('key1') == 'value1'

    async def test_set_jm_data(self):
        jmw = self.jmw
        jmw.set_jm_data('key1', 'value1')
        assert jmw.get_jm_data('key1') == 'value1'
        assert self.w.db.get_dict('jm_data') == {
            'jm_enabled': True,
            'key1': 'value1'}

    async def test_pop_jm_data(self):
        jmw = self.jmman.jmw
        jmw.set_jm_data('key1', {'subkey1': 'value1'})
        assert self.w.db.get_dict('jm_data') == {
            'jm_enabled': True,
            'key1': {'subkey1': 'value1'}}
        assert jmw.pop_jm_data('key1') == {'subkey1': 'value1'}

    async def test_get_jm_commitments(self):
        jmw = self.jmw
        jmw.jm_commitments['used'] = {'c1': 'v1'}
        jmw.jm_commitments['external'] = {'ec1': {'ev1': 'abc'}}
        assert jmw.get_jm_commitments() == {
            'used': {'c1': 'v1'},
            'external': {
                'ec1': {'ev1': 'abc'},
            },
        }

    async def test_set_jm_commitments(self):
        jmw = self.jmman.jmw
        assert jmw.get_jm_data('jm_commitments') is None
        jmw.set_jm_commitments(used={'c1': 'v1'},
                               external={'ec1': {'ev1': 'abc'}})
        assert jmw.jm_commitments == {
            'used': {'c1': 'v1'},
            'external': {
                'ec1': {'ev1': 'abc'},
            },
        }

    async def test_add_jm_address(self):
        jmw = self.jmman.jmw
        addr1 = 'addr1'
        assert addr1 not in jmw.jm_addresses
        jm_addr = JMAddress(mixdepth=0, branch=1, index=2)
        jmw.add_jm_address(addr1, jm_addr)
        assert addr1 in jmw.jm_addresses
        assert jmw.jm_addresses[addr1] == (0, 1, 2)

    async def test_get_jm_address(self):
        jmw = self.jmman.jmw
        addr1 = 'addr1'
        jmw.jm_addresses[addr1] = (0, 1, 2)
        jm_addr = jmw.get_jm_address(addr1)
        assert jm_addr == JMAddress(mixdepth=0, branch=1, index=2)

    async def test_is_jm_address(self):
        jmw = self.jmman.jmw
        addr1 = 'addr1'
        addr2 = 'addr2'
        jmw.jm_addresses[addr1] = (0, 1, 2)
        assert jmw.is_jm_address(addr1)
        assert not jmw.is_jm_address(addr2)

    async def test_get_jm_addresses(self):
        jmw = self.jmman.jmw
        jmw.jm_addresses.clear()
        addr1 = 'addr1'
        addr2 = 'addr2'
        jmw.jm_addresses[addr1] = (0, 1, 2)
        jmw.jm_addresses[addr2] = (1, 0, 3)

        assert addr1 in jmw.get_jm_addresses()
        assert addr2 in jmw.get_jm_addresses()

        assert addr1 in jmw.get_jm_addresses(mixdepth=0)
        assert addr2 not in jmw.get_jm_addresses(mixdepth=0)

        assert addr1 not in jmw.get_jm_addresses(mixdepth=1)
        assert addr2 in jmw.get_jm_addresses(mixdepth=1)

        assert addr1 in jmw.get_jm_addresses(mixdepth=0, internal=1)
        assert addr2 not in jmw.get_jm_addresses(mixdepth=0, internal=1)

        assert addr1 not in jmw.get_jm_addresses(mixdepth=1, internal=1)
        assert addr2 not in jmw.get_jm_addresses(mixdepth=1, internal=1)

        assert addr1 not in jmw.get_jm_addresses(mixdepth=0, internal=0)
        assert addr2 not in jmw.get_jm_addresses(mixdepth=0, internal=0)

        assert addr1 not in jmw.get_jm_addresses(mixdepth=1, internal=0)
        assert addr2 in jmw.get_jm_addresses(mixdepth=1, internal=0)

        assert addr1 not in jmw.get_jm_addresses(mixdepth=1, internal=1)
        assert addr2 not in jmw.get_jm_addresses(mixdepth=1, internal=1)

    async def test_get_jm_utxos(self):
        jmw = self.jmw
        coins = jmw.get_jm_utxos()
        assert len(coins) == 4

        coins = jmw.get_jm_utxos(internal=1)
        assert len(coins) == 0

        coins = jmw.get_jm_utxos(mixdepth=0, internal=1)
        assert len(coins) == 0

        coins = jmw.get_jm_utxos(mixdepth=0)
        assert len(coins) == 1
        outpoint = ('b82763a40e3c701669cb57341a8116d7'
                    'f6d4cd2dbd0648d839c6b754aac37dd2:4')
        assert coins[outpoint] == JMUtxo(
            addr='tb1qs33rq0wmrq2awvuxrte0mqkksvzr6x9sdkrfdc',
            value=2500000, mixdepth=0)

        coins = jmw.get_jm_utxos(mixdepth=1)
        assert len(coins) == 3
        outpoint = ('b82763a40e3c701669cb57341a8116d7'
                    'f6d4cd2dbd0648d839c6b754aac37dd2:1')
        assert coins[outpoint] == JMUtxo(
            addr='tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk',
            value=2500000, mixdepth=1)
        outpoint = ('b82763a40e3c701669cb57341a8116d7'
                    'f6d4cd2dbd0648d839c6b754aac37dd2:2')
        assert coins[outpoint] == JMUtxo(
            addr='tb1q8qymfhts46zngpnve4rf6mjaqg398ggskvw3ez',
            value=2500000, mixdepth=1)
        outpoint = ('b82763a40e3c701669cb57341a8116d7'
                    'f6d4cd2dbd0648d839c6b754aac37dd2:3')
        assert coins[outpoint] == JMUtxo(
            addr='tb1q8c2k82wyzcxgk3x2257r2j6ngzedvjppdh4904',
            value=2500000, mixdepth=1)

    async def test_add_jm_tx(self):
        jmw = self.jmw
        txid = 'txid'
        addr = 'addr'
        amount = 123456  # sats
        date = 1721290860  # epoch time
        assert txid not in jmw.jm_txs
        jmw.add_jm_tx(txid, addr, amount, date)
        assert txid in jmw.jm_txs
        assert jmw.jm_txs[txid] == (addr, amount, date)

    async def test_get_jm_tx(self):
        jmw = self.jmw
        assert jmw.get_jm_tx('unnown_txid') is None
        txid = 'txid'
        addr = 'addr'
        amount = 123456  # sats
        date = 1721290860  # epoch time
        assert txid not in jmw.jm_txs
        jmw.jm_txs[txid] = (addr, amount, date)
        assert jmw.get_jm_tx(txid) == (addr, amount, date)

    async def test_get_jm_txs(self):
        jmw = self.jmw
        assert jmw.get_jm_txs() == dict()
        txid = 'txid'
        txid2 = 'txid2'
        addr = 'addr'
        addr2 = 'addr2'
        amount = 123456  # sats
        amount2 = 789012  # sats
        date = 1721290860  # epoch time
        date2 = 1721290862  # epoch time
        jmw.add_jm_tx(txid, addr, amount, date)
        jmw.add_jm_tx(txid2, addr2, amount2, date2)
        assert jmw.get_jm_txs() == {
            txid: (addr, amount, date),
            txid2: (addr2, amount2, date2),
        }


class JMWalletTestCase(JMTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.addr3 = 'tb1qpjkqrhz3kxsg93c5cw2axhdy39wqy36u9ygzdk'  # spent
        self.addr4 = 'tb1q8qymfhts46zngpnve4rf6mjaqg398ggskvw3ez'  # spent
        self.spent_addrs = set([self.addr3, self.addr4])
        self.unspent_addrs = set()
        self.txid1 = '55'*32
        self.txid2 = 'aa'*32
        self.w.adb._history_local[self.addr3].add(self.txid1)
        self.w.adb._history_local[self.addr4].add(self.txid2)

    async def test_load_and_cleanup(self):
        self.jmw.load_and_cleanup()

    async def test_get_spent_jm_addresses(self):
        jmw = self.jmw
        assert jmw.get_spent_jm_addresses() == self.spent_addrs

    async def test_get_unspent_jm_addresses(self):
        jmw = self.jmw
        jm_addrs = set(jmw.get_jm_addresses().keys())
        assert jmw.get_unspent_jm_addresses() == jm_addrs - self.spent_addrs

    async def test_add_spent_addrs(self):
        jmw = self.jmw
        jmw.add_spent_addrs(self.unspent_addrs)
        assert jmw.spent_addrs == set()
        jmw.add_spent_addrs(self.spent_addrs)
        assert jmw.spent_addrs == self.spent_addrs
        assert jmw.unsubscribed_addrs == self.spent_addrs

    async def test_restore_spent_addrs(self):
        jmw = self.jmw
        jmw.spent_addrs.update()
        assert jmw.spent_addrs == set()
        assert jmw.unsubscribed_addrs == set()
        jmw.spent_addrs.update(self.spent_addrs)
        jmw.unsubscribed_addrs.update(self.spent_addrs)
        jmw.restore_spent_addrs(self.spent_addrs)
        assert jmw.spent_addrs == set()
        assert jmw.unsubscribed_addrs == set()

    async def test_subscribe_spent_addr(self):
        w = self.w
        s = w.adb.synchronizer
        jmw = self.jmw
        assert jmw.spent_addrs == set()
        assert jmw.unsubscribed_addrs == set()

        for addr in self.spent_addrs:
            jmw.subscribe_spent_addr(addr)

        assert jmw.spent_addrs == self.unspent_addrs
        assert jmw.unsubscribed_addrs == set()
        for addr in self.spent_addrs:
            assert addr in s.addrs

    async def test_unsubscribe_spent_addr(self):
        w = self.w
        s = w.adb.synchronizer
        jmw = self.jmw
        assert jmw.spent_addrs == set()
        assert jmw.unsubscribed_addrs == set()
        jmw.add_spent_addrs(self.spent_addrs)
        assert jmw.spent_addrs == self.spent_addrs
        assert jmw.unsubscribed_addrs == self.spent_addrs

        jmw.unsubscribed_addrs == self.spent_addrs
        for addr in list(self.spent_addrs):
            jmw.unsubscribe_spent_addr(addr)

        assert jmw.spent_addrs == self.spent_addrs
        assert jmw.unsubscribed_addrs == self.spent_addrs
        await asyncio.sleep(0.01)
        assert s._requests_sent == 2

    async def test_synchronizer_remove_addr(self):  # FIXME add more testing
        w = self.w
        jmw = self.jmw
        w.adb.synchronizer = s = Synchronizer(self)
        addr1 = 'tb1q9nlrq3u90flpclsg27p94wjtvjpx3yxzey7zhz'
        addr2 = 'tb1q3vq6tl758sq36fgpa67r0vhtel32alk0zdfcal'
        s.add(addr1)
        s.add(addr2)
        assert s._adding_addrs == {addr1, addr2}
        jmw.synchronizer_remove_addr(addr1)
        await asyncio.sleep(0.01)
        assert s._requests_sent == 1
