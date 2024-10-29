# -*- coding: utf-8 -*-

import asyncio
import attr
import threading
from aiorpcx import run_in_thread

from electrum import util
from electrum.bitcoin import (pubkey_to_address, address_to_scripthash,
                              is_address)
from electrum.interface import NetworkException
from electrum.transaction import Transaction
from electrum.util import EventListener, event_listener, ignore_exceptions

from .jm_base_code import JMBaseCodeMixin
from .jm_util import JMAddress, JMUtxo, KPStates


class KeypairNotFound(Exception):
    ...


class KeyPairsMixin:
    '''Cached keypairs for automatic tx signing'''

    def __init__(self):
        self.keypairs_state_lock = threading.Lock()
        self._keypairs_state = KPStates.Empty
        self._keypairs_cache = {}

    @property
    def keypairs_state(self):
        '''Get keypairs cache state'''
        return self._keypairs_state

    @keypairs_state.setter
    def keypairs_state(self, keypairs_state):
        '''Set keypairs cache state'''
        assert isinstance(keypairs_state, KPStates)
        self._keypairs_state = keypairs_state

    def check_need_new_keypairs(self):
        '''Check if there is a need to cache new keypairs in addition
        to possibly already cached ones'''
        if not self.jmman.need_password():
            return False

        with self.keypairs_state_lock:
            return self.keypairs_state == KPStates.Empty

    async def cleanup_keypairs(self):
        '''Async task which cleans keypairs after mixing is stopped'''

        def cleanup_keypairs_cache():
            '''Cleanup keypairs cache'''
            with self.keypairs_state_lock:
                self.logger.info('Cleaning Keypairs Cache')
                if self._keypairs_cache:
                    for addr in list(self._keypairs_cache.keys()):
                        self._keypairs_cache.pop(addr)
                self.keypairs_state = KPStates.Empty
                self.logger.info('Cleaned Keypairs Cache')

        await self.loop.run_in_executor(None, cleanup_keypairs_cache)

    async def make_keypairs_cache(self, password, keypairs_cached_callback,
                                  *, tx_cnt=None):
        '''Make keypairs cache after mixing is started'''
        if self.keypairs_state == KPStates.Ready:
            return False
        try:
            def _cache_keypairs():
                return self._cache_keypairs(password, tx_cnt=tx_cnt)

            self.logger.info('Making Keypairs Cache')
            cached = await self.loop.run_in_executor(None, _cache_keypairs)
            self.logger.info(f'Keypairs Cache Done, cached {cached} keys')
            if keypairs_cached_callback:
                try:
                    keypairs_cached_callback()
                except BaseException as e:
                    self.logger.info(f'make_keypairs_cache: '
                                     f'keypairs_cached_callback: {str(e)}')
            return True
        except Exception as e:
            self.logger.warning(f'make_keypairs_cache: {str(e)}')
            await self.cleanup_keypairs()
            return False

    def _cache_keypairs(self, password, *, tx_cnt=None):
        '''Cache keypairs on mixing start'''
        w = self.wallet
        jmconf = self.jmconf
        cached = 0
        out_cnt = 2

        with self.keypairs_state_lock:
            if self.keypairs_state == KPStates.Ready:
                return cached
            if isinstance(tx_cnt, int) and tx_cnt >= 0:
                # cache keys for existing JM utxos
                for jm_utxo in self.get_jm_utxos().values():
                    addr = jm_utxo.addr
                    sequence = w.get_address_index(addr)
                    pubkey = w.keystore.derive_pubkey(*sequence)
                    sec, _ = w.keystore.get_private_key(sequence, password)
                    self._keypairs_cache[addr] = (pubkey, sec)
                    cached += 1
                if tx_cnt > 0:

                    def filter_unused(addr):
                        return w.adb.get_address_history_len(addr) == 0

                    mixdepth = jmconf.mixdepth + 1
                    gaplimit = jmconf.gaplimit
                    key_cnt = out_cnt * tx_cnt * mixdepth * gaplimit + cached
                    unused_idxs = []

                    # cache keys for unused adresses by mixdepth
                    for d in range(mixdepth):
                        addrs = [a for a, jm_address in sorted(
                            self.get_jm_addresses(mixdepth=d,
                                                  internal=True).items(),
                            key=lambda x: x[1].index[1])]
                        addrs = list(filter(filter_unused, addrs))
                        if addrs:
                            sequence = w.get_address_index(addrs[0])
                            if sequence:
                                unused_idxs.append(sequence[1])
                        depth_cached = 0
                        for addr in addrs:
                            if depth_cached + 1 > out_cnt * tx_cnt:
                                break
                            sequence = w.get_address_index(addr)
                            if addr in self._keypairs_cache:
                                continue  # skip cached
                            pubkey = w.keystore.derive_pubkey(*sequence)
                            sec, _ = w.keystore.get_private_key(sequence,
                                                                password)
                            self._keypairs_cache[addr] = (pubkey, sec)
                            depth_cached += 1
                            cached += 1
                    # cache keys for unused adresses not in cache
                    # starting from mininum unused index
                    idx = min(unused_idxs) if unused_idxs else 0
                    while cached < key_cnt:
                        sequence = (1, idx)
                        idx += 1
                        pubkey = w.keystore.derive_pubkey(*sequence)
                        addr = pubkey_to_address(w.txin_type, pubkey.hex())
                        if addr in self._keypairs_cache:
                            continue  # skip cached
                        if w.adb.get_address_history_len(addr) > 0:
                            continue  # skip used
                        sec, _ = w.keystore.get_private_key(sequence, password)
                        self._keypairs_cache[addr] = (pubkey, sec)
                        cached += 1
            else:
                for addr in self.get_unspent_jm_addresses():
                    sequence = w.get_address_index(addr)
                    pubkey = w.keystore.derive_pubkey(*sequence)
                    sec, _ = w.keystore.get_private_key(sequence, password)
                    self._keypairs_cache[addr] = (pubkey, sec)
                    cached += 1
            self.keypairs_state = KPStates.Ready
        return cached

    def get_cached_key(self, addr):
        if addr in self._keypairs_cache:
            return self._keypairs_cache[addr][1]
        else:
            self.logger.error(f'get_key_from_addr: keypair'
                              f' for {addr} not found')
            raise KeypairNotFound(f'Address {addr} not found '
                                  f'in the keypairs cache')

    def get_keypairs(self):
        '''Transform keypairs cache to dict suitable for Transaction.sign'''
        keypairs = {}
        for pubkey, sec in self._keypairs_cache.values():
            keypairs[pubkey] = sec
        return keypairs

    def get_keypairs_for_coinjoin_tx(self, tx, password):
        '''Derive keypairs for coinjoin tx to fix add_info_from_wallet
        problem on transactions with unknown addresses (post 4.1.х fix)'''
        w = self.wallet
        keypairs = {}
        for txin in tx.inputs():
            addr = txin.address
            if addr is None or not w.is_mine(addr):
                continue
            sequence = w.get_address_index(addr)
            pubkey = w.keystore.derive_pubkey(*sequence)
            sec, _ = w.keystore.get_private_key(sequence, password)
            keypairs[pubkey] = sec
        return keypairs

    def sign_coinjoin_transaction(self, tx, password=None):
        '''Sign coinjoin transactions (with keypairs if cached)'''
        if self._keypairs_cache:
            keypairs = self.get_keypairs()
        else:
            keypairs = self.get_keypairs_for_coinjoin_tx(tx, password)
        tx.sign(keypairs)
        tx.finalize_psbt()
        keypairs.clear()
        if tx.is_complete():
            return tx


class WalletDBMixin:

    def wallet_db_modifier(func):
        def wrapper(self, *args, **kwargs):
            with self.db.lock:
                self.db._modified = True
                return func(self, *args, **kwargs)
        return wrapper

    def wallet_db_locked(func):
        def wrapper(self, *args, **kwargs):
            with self.db.lock:
                return func(self, *args, **kwargs)
        return wrapper

    @wallet_db_locked
    def get_jm_data(self, key, default_val=None):
        return self.jm_data.get(key, default_val)

    @wallet_db_modifier
    def set_jm_data(self, key, val):
        self.jm_data[key] = val

    @wallet_db_modifier
    def pop_jm_data(self, key):
        return self.jm_data.pop(key, None)

    @wallet_db_modifier
    def set_jm_commitments(self, *, used, external):
        self.jm_commitments['used'] = used
        self.jm_commitments['external'] = external

    @wallet_db_locked
    def get_jm_commitments(self):
        return self.jm_commitments

    @wallet_db_modifier
    def add_jm_address(self, address, jm_address):
        '''
        add add jm_address (mixdepth, branch, index, address) tuple
        at address BIP32 path
        '''
        assert isinstance(jm_address, JMAddress)
        self.jm_addresses[address] = attr.astuple(jm_address)

    @wallet_db_locked
    def get_jm_address(self, address):
        jm_address_tuple = self.jm_addresses.get(address)
        if jm_address_tuple:
            return JMAddress(*jm_address_tuple)

    @wallet_db_locked
    def is_jm_address(self, address):
        return address in self.jm_addresses

    @wallet_db_locked
    def get_jm_addresses(self, *, mixdepth=None, internal=None):
        addresses = {k: JMAddress(*v) for k, v in self.jm_addresses.items()}
        if mixdepth is not None:
            addresses = {k: v for k, v in addresses.items()
                         if v.mixdepth == mixdepth}
        if internal is not None:
            addresses = {k: v for k, v in addresses.items()
                         if v.branch == int(internal)}
        return addresses

    def get_jm_utxos(self, *, mixdepth=None, internal=None):
        addrs = self.get_jm_addresses(mixdepth=mixdepth, internal=internal)
        coins = self.wallet.get_utxos(list(addrs.keys()))
        res = {}
        for c in coins:
            outpoint = c.prevout.to_str()
            addr = c.address
            jm_addr = addrs[addr]
            res[outpoint] = JMUtxo(addr, c.value_sats(), jm_addr.mixdepth)
        return res

    @wallet_db_modifier
    def add_jm_tx(self, txid, address, amount, date):
        self.jm_txs[txid] = (address, amount, date)

    @wallet_db_locked
    def get_jm_tx(self, txid):
        return self.jm_txs.get(txid, None)

    @wallet_db_locked
    def get_jm_txs(self):
        return self.jm_txs


class JMWallet(KeyPairsMixin, WalletDBMixin, JMBaseCodeMixin, EventListener):

    def __init__(self, jmman):
        KeyPairsMixin.__init__(self)
        JMBaseCodeMixin.__init__(self)
        self._jm_conf = None
        self.jmman = jmman
        self.logger = jmman.logger
        self.wallet = jmman.wallet
        self.config = jmman.config
        self.debug = False
        self.db = self.wallet.db
        self.jm_data = None
        self.jm_addresses = None
        self.jm_commitments = None
        self.jm_txs = None

        # sycnhronizer unsubsribed addresses
        self.spent_addrs = set()
        self.unsubscribed_addrs = set()

        # ignored makers list persisted across entire app run
        self.ignored_makers = []
        # from jmclient wallet service
        self.callbacks = {
            "all": [],  # note: list, not dict
            "unconfirmed": {},
            "confirmed": {},
        }

        # transactions we are actively monitoring,
        # i.e. they are not new but we want to track:
        self.active_txs = {}
        # to ensure transactions are only processed once:
        self.processed_txids = set()

        self.taskgroup = util.OldTaskGroup()

    def init_jm_data(self):
        if not self.jmman.enabled:
            return
        db = self.db
        self.jm_data = db.get_dict('jm_data')
        self.jm_addresses = db.get_dict('jm_addresses')
        self.jm_commitments = db.get_dict('jm_commitments')
        self.jm_txs = db.get_dict('jm_txs')

    @property
    def jmconf(self):
        return self._jm_conf

    @jmconf.setter
    def jmconf(self, jmconf):
        self._jm_conf = jmconf

    def load_and_cleanup(self):
        '''Start on wallet load_and_cleanup if JM enabled
        or when JM enabled first time'''
        if not self.jmman.enabled:
            return
        self.synchronize()
        # load and unsubscribe spent JM addresses
        self.add_spent_addrs(self.get_jm_addresses().keys())

    def get_address_label(self, addr):
        return self.wallet.get_label_for_address(addr)

    def set_address_label(self, addr, label):
        self.wallet.set_label(addr, label)

    def add_spent_addrs(self, addrs):
        '''Save addresses as spent, to minimize electrum server
        usage for spent denoms'''
        unspent = self.get_unspent_jm_addresses()
        for addr in addrs:
            if addr in unspent:
                continue
            self.spent_addrs.add(addr)
            if self.jmconf.subscribe_spent:
                continue
            self.unsubscribe_spent_addr(addr)

    def restore_spent_addrs(self, addrs):
        '''Remove addresses from spent and subscribe on server again'''
        for addr in addrs:
            self.subscribe_spent_addr(addr)
            self.spent_addrs.remove(addr)

    def subscribe_spent_addr(self, addr):
        '''Return previously unsubscribed address to synchronizer'''
        if addr not in self.spent_addrs or addr not in self.unsubscribed_addrs:
            return
        w = self.wallet
        self.unsubscribed_addrs.remove(addr)
        if w.adb.synchronizer:
            self.logger.debug(f'Add {addr} to synchronizer')
            w.adb.synchronizer.add(addr)

    def unsubscribe_spent_addr(self, addr):
        '''Unsubscribe spent address from synchronizer/electrum server'''
        if (self.jmconf.subscribe_spent
                or addr not in self.spent_addrs
                or addr in self.unsubscribed_addrs):
            return
        self.unsubscribed_addrs.add(addr)
        self.synchronizer_remove_addr(addr)

    def synchronizer_remove_addr(self, addr):
        w = self.wallet
        synchronizer = w.adb.synchronizer
        if synchronizer:
            if self.debug:
                self.logger.debug(f'Remove {addr} from synchronizer')

            async def _remove_address(addr: str):
                if not is_address(addr):
                    raise ValueError(f"invalid bitcoin address {addr}")
                h = address_to_scripthash(addr)
                synchronizer._requests_sent += 1
                async with synchronizer._network_request_semaphore:
                    await synchronizer.session.send_request(
                        'blockchain.scripthash.unsubscribe', [h])
                synchronizer._requests_answered += 1

            asyncio.run_coroutine_threadsafe(_remove_address(addr), self.loop)

    def reserve_jm_addrs(self, addrs_count, *, internal=False):
        '''Reserve addresses for JM use'''
        result = []
        w = self.wallet
        with w.lock:
            while len(result) < addrs_count and not self.jmman.stopped:
                if internal:
                    unused = w.calc_unused_change_addresses()
                else:
                    unused = w.get_unused_addresses()
                    unused = [addr for addr in unused
                              if not w.is_address_reserved(addr)]
                if unused:
                    addr = unused[0]
                else:
                    addr = w.create_new_address(internal)
                self.wallet.set_reserved_state_of_address(addr, reserved=True)
                result.append(addr)
        return result

    def last_few_addresses(self, jm_addrs, limit=0):
        sorted_addrs = sorted(jm_addrs.items(), key=lambda x: x[1].index[1])
        return [a for a, data in sorted_addrs][-limit:]

    def generate_jm_address(self, *, mixdepth, internal):
        addrs = self.reserve_jm_addrs(1, internal=internal)
        if not addrs:
            self.logger.error(f'Error generating new address for'
                              f' mixdepth={mixdepth}, internal={internal}')
            return False
        addr = addrs[0]
        index = self.wallet.get_address_index(addr)
        jm_addr = JMAddress(mixdepth=mixdepth, branch=int(internal),
                            index=index)
        self.add_jm_address(addr, jm_addr)
        return True

    def synchronize_sequence(self, mixdepth: int, internal: bool) -> int:
        w = self.wallet
        gen_cnt = 0  # num new addresses we generated
        limit = self.jmconf.gaplimit

        while True and not self.jmman.stopped:
            jm_addrs = self.get_jm_addresses(mixdepth=mixdepth,
                                             internal=internal)
            addr_cnt = len(jm_addrs)

            if addr_cnt < limit:
                if not self.generate_jm_address(mixdepth=mixdepth,
                                                internal=internal):
                    return gen_cnt
                gen_cnt += 1
                continue

            last_few_addrs = self.last_few_addresses(jm_addrs, limit)
            if any(map(w.adb.address_is_old, last_few_addrs)):
                if not self.generate_jm_address(mixdepth=mixdepth,
                                                internal=internal):
                    return gen_cnt
                gen_cnt += 1
            else:
                break
        return gen_cnt

    def synchronize(self):
        if not self.jmman.enabled:
            return
        count = 0
        with self.wallet.lock:
            for d in range(self.jmconf.max_mixdepth + 1):
                for i in range(2):
                    count += self.synchronize_sequence(mixdepth=d,
                                                       internal=bool(i))
        return count

    def on_network_start(self, network):
        '''Run when network is connected to the wallet'''
        asyncio.run_coroutine_threadsafe(self.main_loop(), self.loop)

    @ignore_exceptions  # don't kill outer taskgroup
    async def main_loop(self):
        try:
            async with self.taskgroup as group:
                await group.spawn(self.do_synchronize_loop())
        except BaseException:
            self.logger.exception("taskgroup died.")
        finally:
            self.logger.info("taskgroup stopped.")

    async def do_synchronize_loop(self):
        while True and not self.jmman.stopped:
            if self.jmman.enabled:
                # note: we only generate new HD addresses if the existing ones
                #       have history that are mined and SPV-verified.
                await run_in_thread(self.synchronize)
            await asyncio.sleep(1)

    async def get_tx(self, txid, *, ignore_network_issues=True, timeout=None):
        tx = self.wallet.db.get_transaction(txid)
        if tx:
            return tx
        if self.network and self.network.has_internet_connection():
            try:
                raw_tx = await self.network.get_transaction(txid,
                                                            timeout=timeout)
            except NetworkException as e:
                self.logger.info(f'got network error getting input txn. err:'
                                 f' {repr(e)}. txid: {txid}.')
                if not ignore_network_issues:
                    raise e
            else:
                tx = Transaction(raw_tx)
        if not tx and not ignore_network_issues:
            raise NetworkException('failed to get prev tx from network')
        return tx

    def get_spent_jm_addresses(self, *, mixdepth=None, internal=None):
        jm_addr_list = set()
        for addr in self.get_jm_addresses(mixdepth=mixdepth,
                                          internal=internal).keys():
            if self.wallet.adb.get_address_history_len(addr) >= 2:
                jm_addr_list.add(addr)
        return jm_addr_list

    def get_unspent_jm_addresses(self, *, mixdepth=None, internal=None):
        jm_addr_list = set()
        for addr in self.get_jm_addresses(mixdepth=mixdepth,
                                          internal=internal).keys():
            if self.wallet.adb.get_address_history_len(addr) < 2:
                jm_addr_list.add(addr)
        return set(jm_addr_list)

    @event_listener
    async def on_event_adb_added_tx(self, adb, txid: str, tx: Transaction):
        if not self.jmman.enabled:
            return
        if self.wallet.adb != adb:
            return
        try:
            await self.transaction_monitor(tx, txid)
        except Exception as e:
            self.logger.warning(f'on_event_adb_added_tx: {str(e)}')

    @event_listener
    async def on_event_adb_added_verified_tx(self, adb, txid):
        if not self.jmman.enabled:
            return
        if self.wallet.adb != adb:
            return
        try:
            tx = self.wallet.adb.get_transaction(txid)
            if tx:
                await self.transaction_monitor(tx, txid)
            else:
                self.logger.debug(f'on_event_adb_added_verified_tx: tx not'
                                  f' found for txid={txid}')
        except Exception as e:
            self.logger.warning(f'on_event_adb_added_verified_tx: {str(e)}')

    @event_listener
    async def on_event_adb_tx_height_changed(self, adb, txid,
                                             old_height, tx_height):
        if not self.jmman.enabled:
            return
        if self.wallet.adb != adb:
            return
        try:
            tx = self.wallet.adb.get_transaction(txid)
            await self.transaction_monitor(tx, txid)
        except Exception as e:
            self.logger.warning(f'on_event_adb_tx_height_changed: {str(e)}')
