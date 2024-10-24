# -*- coding: utf-8 -*-

import copy
import collections
import random
from decimal import Decimal
from math import ceil, exp
from numbers import Integral
from typing import Union, List, Tuple, Optional, Dict, Any

import electrum_ecc as ecc

from electrum.bip32 import convert_bip32_intpath_to_strpath
from electrum.bitcoin import (script_to_scripthash, address_to_script,
                              construct_script, opcodes)
from electrum.crypto import sha256
from electrum.descriptor import get_singlesig_descriptor_from_legacy_leaf
from electrum.transaction import (get_address_from_output_script,
                                  get_script_type_from_output_script)
from electrum.util import bfh

from .import jmbitcoin as btc
from .jmclient import (select, select_gradual, select_greedy, select_greediest,
                       NotEnoughFundsException, EngineError,
                       WalletMixdepthOutOfRange)
from .jm_util import (JMAddress, guess_address_script_type,
                      decompress_secp256k1_pubkey, KPStates)


class JMBaseCodeMixin:

    BIP32_MAX_PATH_LEVEL = 2**31

    MERGE_ALGORITHMS = {
        'default': select,
        'gradual': select_gradual,
        'greedy': select_greedy,
        'greediest': select_greediest
    }

    def __init__(self):
        self.autofreeze_warning_cb = self.default_autofreeze_warning_cb

    # jmbitcoin/secp256k1_transaction.py mk_freeze_script
    def mk_freeze_script(self, pub: bytes, locktime: int) -> bytes:
        """
        Given a pubkey and locktime, create a script which can only be spent
        after the locktime has passed using OP_CHECKLOCKTIMEVERIFY
        """
        if not isinstance(locktime, int):
            raise TypeError("locktime must be int")
        if not isinstance(pub, bytes):
            raise TypeError("pubkey must be in bytes")

        # check pubkey bytes is valid
        _pub = decompress_secp256k1_pubkey(pub)
        ecc._x_and_y_from_pubkey_bytes(_pub)

        return construct_script(
            [locktime, opcodes.OP_CHECKLOCKTIMEVERIFY,
             opcodes.OP_DROP, pub, opcodes.OP_CHECKSIG]
        )

    # jmbitcoin/secp256k1_transaction.py redeem_script_to_p2wsh_script
    def redeem_script_to_p2wsh_script(self, redeem_script: bytes) -> bytes:
        """ Given redeem script of type CScript (or bytes)
        returns the corresponding segwit v0 scriptPubKey as
        for the case pay-to-witness-scripthash.
        """
        wsh = sha256(redeem_script)
        return construct_script([opcodes.OP_0, wsh])

    # jmclient/blockchaininterface.py reimplement get_best_block_median_time
    def get_median_time_past(self, blockchain) -> int:
        tip_header = blockchain.header_at_tip()
        block_height = tip_header['block_height'] if tip_header else 0
        MEDIAN_TIME_SPAN = 11
        timestamps = [tip_header['timestamp']] if tip_header else []
        for height in range(block_height - 1,
                            block_height - MEDIAN_TIME_SPAN,
                            -1):
            header = blockchain.read_header(height)
            if header:
                timestamps.append(header['timestamp'])
        if not timestamps:
            self.logger.error('get_median_time_past: no timestamps found')
            return None
        timestamps.sort()
        return timestamps[len(timestamps)//2]

    # jmclient/blockchaininterface.py from BlockchainInterface with same name
    def fee_per_kb_has_been_manually_set(self, tx_fees: int) -> bool:
        """If the block target (tx_fees) is higher than 1000, interpret it
        as manually set fee sats/kvB.
        """
        return tx_fees > 1000

    # jmclient/blockchaininterface.py from BitcoinCoreInterface with same name
    def _estimate_fee_basic(self,
                            conf_target: int) -> Optional[Tuple[int, int]]:
        estimates = self.config.fee_estimates
        if not estimates:
            self.logger.warning("Could not source a fee estimate")
            return None
        targets = sorted(estimates.keys())
        target = min(targets, key=lambda x: abs(x-conf_target))
        if target < conf_target:
            target_idx = targets.index(target)
            if len(targets) > target_idx + 1:
                target = targets[target_idx+1]
        fee_rate_sats = estimates[target]
        blocks = conf_target
        if conf_target == 1:  # see electrum SimpleConfig.eta_target_to_fee
            fee_rate_sats += fee_rate_sats / 2
            fee_rate_sats = int(fee_rate_sats)
            blocks = target
        return fee_rate_sats, blocks

    # jmclient/blockchaininterface.py from BlockchainInterface with same name
    def estimate_fee_per_kb(self, tx_fees: int) -> int:
        """ The argument tx_fees may be either a number of blocks target,
        for estimation of feerate by Core, or a number of satoshis
        per kilo-vbyte (see `fee_per_kb_has_been_manually_set` for
        how this is distinguished).
        In both cases it is prevented from falling below the current
        minimum feerate for tx to be accepted into node's mempool.
        In case of failure to connect, source a specific minimum fee relay
        rate (which is used to sanity check user's chosen fee rate), or
        failure to source a feerate estimate for targeted number of blocks,
        a default of 20000 is returned.
        """

        # default to use if fees cannot be estimated
        fallback_fee = 20000

        tx_fees_factor = abs(self.jmconf.tx_fees_factor)

        # NOTE: can not get data from estimatesmartfee with electrum protocol,
        # but value with default config seems 1000 sat/kb
        mempoolminfee_in_sat = 1000
        # mempoolminfee_in_sat = self._get_mempool_min_fee()
        # in case of error
        if mempoolminfee_in_sat is None:
            mempoolminfee_in_sat = fallback_fee
        mempoolminfee_in_sat_randomized = random.uniform(
            mempoolminfee_in_sat,
            mempoolminfee_in_sat * float(1 + tx_fees_factor))

        if self.fee_per_kb_has_been_manually_set(tx_fees):
            N_res = random.uniform(tx_fees,
                                   tx_fees * float(1 + tx_fees_factor))
            if N_res < mempoolminfee_in_sat:
                msg = "Using this mempool min fee as tx feerate"
                if tx_fees_factor != 0:
                    msg = msg + " (randomized for privacy)"
                self.logger.info(
                    msg + ": " +
                    btc.fee_per_kb_to_str(mempoolminfee_in_sat_randomized) +
                    ".")
                return int(mempoolminfee_in_sat_randomized)
            else:
                msg = "Using this manually set tx feerate"
                if tx_fees_factor != 0:
                    msg = msg + " (randomized for privacy)"
                self.logger.info(
                    msg + ": " + btc.fee_per_kb_to_str(N_res) + ".")
                return int(N_res)

        retval = self._estimate_fee_basic(tx_fees)
        if retval is None:
            msg = ("Fee estimation for " + str(tx_fees) +
                   " block confirmation target failed. " +
                   "Falling back to default")
            if tx_fees_factor != 0:
                msg = msg + " (randomized for privacy)"
            fallback_fee_randomized = random.uniform(
                fallback_fee, fallback_fee * float(1 + tx_fees_factor))
            self.logger.warning(
                msg + ": " +
                btc.fee_per_kb_to_str(fallback_fee_randomized) + ".")
            return int(fallback_fee_randomized)

        feerate, blocks = retval
        # 1 block difference is tolerated with intent, Core will often return
        # 2 block target for `estimatesmartfee 1`.
        if tx_fees - blocks > 1:
            self.logger.warning(
                f"Fee estimation for {tx_fees} block confirmation target "
                f"was requested, but {blocks} block target was provided by "
                f"blockchain source. Tx fee may be higher then expected.")

        feerate = random.uniform(feerate, feerate * float(1 + tx_fees_factor))

        if feerate < mempoolminfee_in_sat:
            msg = "Using this mempool min fee as tx feerate"
            if tx_fees_factor != 0:
                msg = msg + " (randomized for privacy)"
            self.logger.info(msg + ": " + btc.fee_per_kb_to_str(
                mempoolminfee_in_sat_randomized) + ".")
            return int(mempoolminfee_in_sat_randomized)
        else:
            msg = "Using bitcoin network feerate for " + str(tx_fees) + \
                " block confirmation target"
            if tx_fees_factor != 0:
                msg = msg + " (randomized for privacy)"
            self.logger.info(msg + ": " + btc.fee_per_kb_to_str(feerate))
            return int(feerate)

    # jmclient/blockchaininterface.py BitcoinCoreInterface.query_utxo_set
    async def query_utxo_set(
            self,
            txouts: Union[Tuple[bytes, int], List[Tuple[bytes, int]]],
            includeconfs: bool = False,
            include_mempool: bool = True) -> List[Optional[dict]]:
        # FIXME include_mempool param does not work for include_mepool=True
        #
        # listunspent_for_scripthash filters out potential spends for
        # scripthash from mempool
        #
        # possible fix: use blockchain.scripthash.get_mempool protocol method,
        # but it's currently not included in electrum code
        #
        # if included, then info on txout can be get from transaction
        if not isinstance(txouts, list):
            txouts = [txouts]
        result = []
        for txo in txouts:
            tx = await self.get_tx(txo[0].hex())
            if not tx:
                return result
            o = tx.outputs()[txo[1]]
            address = o.address
            script = o.scriptpubkey
            shash = script_to_scripthash(script)
            utxo_info = await self.network.listunspent_for_scripthash(shash)
            utxo = None
            for u in utxo_info:
                if u['tx_hash'] == txo[0].hex() and u['tx_pos'] == txo[1]:
                    utxo = u
            if utxo is None:
                result.append(None)
                continue
            r = {
                'value': u['value'],
                'address': address,
                'script': script
            }
            if includeconfs:
                current_height = self.wallet.adb.get_local_height()
                if int(u['height']) <= 0:
                    # unconfirmed inputs
                    r['confirms'] = 0
                else:
                    # +1 because if current height = tx height, that's 1 conf
                    r['confirms'] = int(current_height) - int(u['height']) + 1
            result.append(r)
        return result

    ###########################################################################
    # jmclient/wallet.py BIP32Wallet/FidelityBondMixin same name
    def get_bip32_pub_export(self, mixdepth=None, address_type=None):
        return self.wallet.get_master_public_key()

    # jmclient/wallet.py BIP32Wallet/FidelityBondMixin same name
    def get_path(self, mixdepth=None, address_type=None, index=None):
        if mixdepth is not None:
            assert isinstance(mixdepth, Integral)
            if not 0 <= mixdepth <= self.jmconf.max_mixdepth:
                raise WalletMixdepthOutOfRange()

        if address_type is not None:
            if mixdepth is None:
                raise Exception("mixdepth must be set if address_type is set")

        if index is not None:
            assert isinstance(index, Integral)
            if address_type is None:
                raise Exception("address_type must be set if index is set")
            assert index < self.BIP32_MAX_PATH_LEVEL
            return (address_type, index)
        return tuple()

    # jmclient/wallet.py BIP32Wallet/FidelityBondMixin same name
    def get_path_repr(self, path):
        return convert_bip32_intpath_to_strpath(path)

    # jmclient/wallet.py FidelityBondMixin same name
    def calculate_timelocked_fidelity_bond_value(self, utxo_value,
                                                 confirmation_time, locktime,
                                                 current_time, interest_rate):
        """
        utxo_value is in satoshi
        interest rate is per year
        all times are seconds
        """
        YEAR = 60 * 60 * 24 * 365.2425  # gregorian calender year length

        r = interest_rate
        T = (locktime - confirmation_time) / YEAR
        L = locktime / YEAR
        t = current_time / YEAR

        a = max(0, min(1, exp(r*T) - 1) - min(1, exp(r*max(0, t-L)) - 1))
        exponent = self.jmconf.bond_value_exponent
        return pow(utxo_value*a, exponent)

    # jmclient/wallet.py FidelityBondMixin same name
    async def get_validated_timelocked_fidelity_bond_utxo(
            self, utxo, utxo_pubkey, locktime,
            cert_expiry, current_block_height):

        utxo_data = await self.query_utxo_set(utxo, includeconfs=True)
        if utxo_data[0] is None:
            return None
        if utxo_data[0]["confirms"] <= 0:
            return None
        RETARGET_INTERVAL = 2016
        if current_block_height > cert_expiry*RETARGET_INTERVAL:
            return None
        implied_spk = self.redeem_script_to_p2wsh_script(
            self.mk_freeze_script(utxo_pubkey, locktime))
        if utxo_data[0]["script"] != implied_spk:
            return None
        return utxo_data[0]

    # jmclient/wallet.py BaseWallet.pubkey_has_script
    def pubkey_has_script(self, pubkey: bytes, script: bytes) -> bool:
        txin_type = get_script_type_from_output_script(script)
        if txin_type is None:
            raise EngineError

        desc = get_singlesig_descriptor_from_legacy_leaf(pubkey=pubkey.hex(),
                                                         script_type=txin_type)
        desc_exp = desc.expand()
        return script == desc_exp.output_script

    # jmclient/wallet.py BaseWallet.get_key_from_addr
    def get_key_from_addr(self, addr) -> bytes:
        w = self.wallet
        if self.keypairs_state == KPStates.Ready:
            return self.get_cached_key(addr)
        else:
            path = w.get_address_index(addr)
            privk, _ = w.keystore.get_private_key(path, None)
            return privk

    # jmclient/wallet.py BaseWallet/BIP32Wallet get_script_from_path
    def get_script_from_path(self, path) -> bytes:
        addr = self.get_address_from_path(path)
        return address_to_script(addr)

    # jmclient/wallet.py BaseWallet.script_to_addr
    def script_to_addr(self, script: bytes):
        return get_address_from_output_script(script)

    # jmclient/wallet.py BaseWallet.script_to_path
    def script_to_path(self, script: bytes):
        w = self.wallet
        addr = get_address_from_output_script(script)
        if not w.is_mine(addr):
            raise Exception(f'Address {addr} is not from current wallet')
        return w.get_address_index(addr)

    # jmclient/wallet.py BaseWallet/BIP32Wallet/FidelityBondMixin same name
    def is_standard_wallet_script(self, script: bytes):
        w = self.wallet
        try:
            addr = get_address_from_output_script(script)
            return w.is_mine(addr)
        except BaseException:
            return False

    # jmclient/wallet.py BaseWallet/BIP32Wallet get_address_from_path
    def get_address_from_path(self, path):
        # for standard electrum wallet path is (0/1, n) tuple
        w = self.wallet
        if len(path) != 2:
            raise Exception(f'Path {path} hash wrong lenght')
        path0 = path[0]
        idx = path[1]
        if path0 == 0:
            addrs = w.get_receiving_addresses(slice_start=idx,
                                              slice_stop=idx+1)
            return addrs[0]
        elif path0 == 1:
            addrs = w.get_change_addresses(slice_start=idx,
                                           slice_stop=idx+1)
            return addrs[0]
        else:
            raise Exception(f'Path {path} has wrong first element')

    # jmclient/wallet_service.py WalletService.get_balance_by_mixdepth
    def get_balance_by_mixdepth(self, verbose=True,
                                include_disabled=False,
                                minconfs=None):
        w = self.wallet
        if minconfs is None:
            maxheight = None
        else:
            local_height = w.adb.get_local_height()
            maxheight = local_height - minconfs + 1
        return self._get_balance_by_mixdepth(verbose=verbose,
                                             include_disabled=include_disabled,
                                             maxheight=maxheight)

    # jmclient/wallet.py BaseWallet.get_balance_by_mixdepth
    def _get_balance_by_mixdepth(self, verbose=True,
                                 include_disabled=False,
                                 maxheight=None):
        """
        Get available funds in each active mixdepth.
        By default ignores disabled utxos in calculation.
        By default returns unconfirmed transactions, to filter
        confirmations, set maxheight to max acceptable blockheight.
        returns: {mixdepth: value}
        """
        balances = collections.defaultdict(int)
        for md in range(self.jmconf.mixdepth + 1):
            balances[md] = self.get_balance_at_mixdepth(
                md, verbose=verbose, include_disabled=include_disabled,
                maxheight=maxheight)
        return balances

    # jmclient/wallet.py BaseWallet.get_balance_at_mixdepth
    def get_balance_at_mixdepth(self, mixdepth,
                                verbose: bool = True,
                                include_disabled: bool = False,
                                maxheight: Optional[int] = None) -> int:
        # TODO: verbose
        return self.utxo_manager_get_balance_at_mixdepth(
            mixdepth, include_disabled=include_disabled, maxheight=maxheight)

    # jmclient/wallet.py UTXOManager.get_balance_at_mixdepth
    def utxo_manager_get_balance_at_mixdepth(
            self, mixdepth: int,
            include_disabled: bool = True,
            maxheight: Optional[int] = None) -> int:
        """ By default this returns aggregated bitcoin balance at mixdepth.
        To get only enabled balance, set include_disabled=False.
        To get balances only with a certain number of confs, use maxheight.
        """
        utxomap = self.utxo_manager_get_utxos_at_mixdepth(mixdepth,
                                                          include_disabled)
        if not utxomap:
            return 0
        if maxheight is not None:
            utxomap = {k: c for k, c in utxomap.items() if c[2] <= maxheight}
        return sum(c[1] for c in utxomap.values())

    # jmclient/wallet.py UTXOManager.get_utxos_at_mixdepth
    def utxo_manager_get_utxos_at_mixdepth(
        self, mixdepth: int,
        include_disabled: bool
    ) -> Dict[Tuple[bytes, int], Tuple[Tuple, int, int]]:
        w = self.wallet
        jm_utxos = self.get_jm_utxos(mixdepth=mixdepth)
        utxomap = {}
        for outpoint, jm_utxo in jm_utxos.items():  # FIXMiE
            coins = [c for c in w.get_utxos([jm_utxo.addr])
                     if c.prevout.to_str() == outpoint]
            coin = coins[0] if coins else None
            if coin:
                if not include_disabled and w.is_frozen_coin(coin):
                    continue
                addr = jm_utxo.addr
                jm_addr = self.get_jm_address(addr)
                # utxo: (path, value, height)
                utxo = (jm_addr.index, coin.value_sats(), coin.block_height)
                txid = coin.prevout.txid
                out_idx = coin.prevout.out_idx
                utxomap[(txid, out_idx)] = utxo
        return copy.deepcopy(utxomap) if utxomap else {}

    # jmclient/wallet.py BaseWallet.get_utxos_at_mixdepth
    def get_utxos_at_mixdepth(
            self, mixdepth: int,
            include_disabled: bool = False,
            includeheight: bool = False) -> Dict[Tuple[bytes, int],
                                                 Dict[str, Any]]:
        script_utxos = {}
        if 0 <= mixdepth <= self.jmconf.mixdepth:
            data = self.utxo_manager_get_utxos_at_mixdepth(mixdepth,
                                                           include_disabled)
            for utxo, (path, value, height) in data.items():
                script = self.get_script_from_path(path)
                addr = self.get_address_from_path(path)
                script_utxo = {
                    'script': script,
                    'path': path,
                    'value': value,
                    'address': addr,
                    'label': self.wallet.get_label_for_address(addr),
                }
                if includeheight:
                    script_utxo['height'] = height
                script_utxos[utxo] = script_utxo
        return script_utxos

    # jmclient/wallet.py BaseWallet.get_utxos_by_mixdepth
    def _get_utxos_by_mixdepth(
            self, include_disabled: bool = False, includeheight: bool = False,
            limit_mixdepth: Optional[int] = None) -> collections.defaultdict:
        """
        Get all UTXOs for active mixdepths or specified mixdepth.

        returns:
            {mixdepth: {(txid, index):
                {'script': bytes, 'path': tuple, 'value': int}}}
        (if `includeheight` is True, adds key 'height': int)
        """
        script_utxos = collections.defaultdict(dict)
        if limit_mixdepth:
            script_utxos[limit_mixdepth] = self.get_utxos_at_mixdepth(
                mixdepth=limit_mixdepth, include_disabled=include_disabled,
                includeheight=includeheight)
        else:
            for md in range(self.jmconf.mixdepth + 1):
                script_utxos[md] = self.get_utxos_at_mixdepth(
                    md, include_disabled=include_disabled,
                    includeheight=includeheight)
        return script_utxos

    # jmclient/wallet_service.py WalletService.get_utxos_by_mixdepth
    def get_utxos_by_mixdepth(
            self, include_disabled: bool = False,
            verbose: bool = False, includeconfs: bool = False,
            limit_mixdepth: Optional[int] = None) -> collections.defaultdict:
        """ Returns utxos by mixdepth in a dict, optionally including
        information about how many confirmations each utxo has.
        """
        def height_to_confs(x: int) -> int:
            # convert height entries to confirmations:
            ubym_conv = collections.defaultdict(dict)
            for m, i in x.items():
                for u, d in i.items():
                    ubym_conv[m][u] = d
                    h = ubym_conv[m][u].pop("height")
                    if h >= 1e8:
                        confs = 0
                    else:
                        local_height = self.wallet.adb.get_local_height()
                        confs = local_height - h + 1
                    ubym_conv[m][u]["confs"] = confs
            return ubym_conv

        ubym = self._get_utxos_by_mixdepth(
            include_disabled=include_disabled, includeheight=includeconfs,
            limit_mixdepth=limit_mixdepth)
        if not includeconfs:
            return ubym
        else:
            return height_to_confs(ubym)

    # jmclient/wallet_utils.py get_utxos_enabled_disabled
    def get_utxos_enabled_disabled(self, md: int) -> Tuple[dict, dict]:
        w = self.wallet
        enabled = {}
        disabled = {}
        jm_utxos = self.get_jm_utxos(mixdepth=md)
        for outpoint, jm_utxo in jm_utxos.items():  # FIXME enhance code
            coins = [c for c in w.get_utxos([jm_utxo.addr])
                     if c.prevout.to_str() == outpoint]
            coin = coins[0] if coins else None
            if coin:
                addr = jm_utxo.addr
                jm_addr = self.get_jm_address(addr)
                utxo = {
                    'address': addr,
                    'label': self.wallet.get_label_for_address(addr),
                    'path': jm_addr.index,
                    'script': self.get_script_from_path(jm_addr.index),
                    'value': jm_utxo.value,
                }
                if w.is_frozen_coin(coin):
                    disabled[outpoint] = utxo
                else:
                    enabled[outpoint] = utxo
        return enabled, disabled

    def _outpoint_to_tuple(self, outpoint):
        res = outpoint.split(':')
        res[0] = bfh(res[0])
        res[1] = int(res[1])
        return tuple(res)

    # jmclient/wallet.py UTXOManager.select_utxos
    def utxo_manager_select_utxos(self, mixdepth, amount, utxo_filter=(),
                                  select_fn=None, maxheight=None):
        assert isinstance(mixdepth, Integral)
        enabled, _ = self.get_utxos_enabled_disabled(mixdepth)
        # do not select anything in the filter
        utxos = {self._outpoint_to_tuple(utxo): jm_utxo
                 for utxo, jm_utxo in enabled.items()}
        available = [{'utxo': utxo, 'value': jm_utxo['value']}
                     for utxo, jm_utxo in utxos.items()
                     if utxo not in utxo_filter]
        # do not select anything with insufficient confirmations:
        if maxheight is not None:
            available = [{'utxo': utxo, 'value': jm_utxo['value']}
                         for utxo, jm_utxo in utxos.items()
                         if self.wallet.adb.get_tx_height(
                            utxo[0].hex()).height <= maxheight]
        # do not select anything disabled is already done
        # by get_utxos_enabled_disabled
        selector = select_fn or self._get_merge_algorithm()
        selected = selector(available, amount)
        # note that we do not return height; for selection, we expect
        # the caller will not want this (after applying the height filter)
        return {s['utxo']: {'path': utxos[s['utxo']]['path'],
                            'value': utxos[s['utxo']]['value']}
                for s in selected}

    # jmclient/wallet.py BaseWallet._get_merge_algorithm
    def _get_merge_algorithm(self, algorithm_name=None):
        if not algorithm_name:
            algorithm_name = self.jmconf.merge_algorithm

        alg = self.MERGE_ALGORITHMS.get(algorithm_name)
        if alg is None:
            raise Exception("Unknown merge algorithm: '{}'."
                            "".format(algorithm_name))
        return alg

    # jmclient/wallet.py BaseWallet.select_utxos
    def wallet_select_utxos(self, mixdepth, amount, utxo_filter=None,
                            select_fn=None, maxheight=None, includeaddr=False,
                            require_auth_address=False):
        """
        Select a subset of available UTXOS for a given mixdepth whose value is
        greater or equal to amount. If `includeaddr` is True, adds an `address`
        key to the returned dict.

        args:
            mixdepth: int, mixdepth to select utxos from, must be smaller or
                equal to wallet.max_mixdepth
            amount: int, total minimum amount of all selected utxos
            utxo_filter: list of (txid, index), utxos not to select
            maxheight: only select utxos with blockheight <= this.
            require_auth_address: if True, output utxos must include a
                standard wallet address. The first item of the output dict is
                guaranteed to be a suitable utxo. Result will be empty if no
                such utxo set could be found.

        returns:
            {(txid, index): {'script': bytes, 'path': tuple, 'value': int}}

        raises:
            NotEnoughFundsException: if mixdepth does not have utxos with
                enough value to satisfy amount
        """
        assert isinstance(mixdepth, Integral)
        assert isinstance(amount, Integral)

        if not utxo_filter:
            utxo_filter = ()
        for i in utxo_filter:
            assert len(i) == 2
            assert isinstance(i[0], bytes)
            assert isinstance(i[1], Integral)
        utxos = self.utxo_manager_select_utxos(
            mixdepth, amount, utxo_filter, select_fn, maxheight=maxheight)

        total_value = 0
        standard_utxo = None
        for key, data in utxos.items():
            total_value += data['value']
            data['script'] = self.get_script_from_path(data['path'])
            if self.is_standard_wallet_script(data['script']):
                standard_utxo = key
            if includeaddr:
                data["address"] = self.get_address_from_path(data["path"])

        if require_auth_address and not standard_utxo:
            # try to select more utxos, hoping for a standard one
            try:
                return self.wallet_select_utxos(
                    mixdepth, total_value + 1, utxo_filter, select_fn,
                    maxheight, includeaddr, require_auth_address)
            except NotEnoughFundsException:
                # recursive utxo selection was unsuccessful, give up
                return {}
        elif require_auth_address:
            utxos = collections.OrderedDict(utxos)
            utxos.move_to_end(standard_utxo, last=False)

        return utxos

    def _minconfs_to_maxheight(self, minconfs):
        local_height = self.wallet.adb.get_local_height()
        return local_height - minconfs if minconfs is not None else None

    # jmclient/wallet_service.py WalletService.select_utxos
    def select_utxos(self, mixdepth, amount, utxo_filter=None,
                     select_fn=None, minconfs=None, includeaddr=False,
                     require_auth_address=False):
        """ Request utxos from the wallet in a particular mixdepth to satisfy
        a certain total amount, optionally set the selector function (or use
        the currently configured function set by the wallet, and optionally
        require a minimum of minconfs confirmations (default none means
        unconfirmed are allowed).
        """
        return self.wallet_select_utxos(
            mixdepth, amount, utxo_filter=utxo_filter, select_fn=select_fn,
            maxheight=self._minconfs_to_maxheight(minconfs),
            includeaddr=includeaddr, require_auth_address=require_auth_address)

    # jmclient/wallet.py BaseWallet.get_outtype
    def get_outtype(self, addr):
        return guess_address_script_type(addr)

    # jmclient/wallet.py BaseWallet.get_internal_addr
    def get_internal_addr(self, mixdepth):
        if not 0 <= mixdepth <= self.jmconf.max_mixdepth:
            raise WalletMixdepthOutOfRange()

        addrs = self.get_jm_addresses(mixdepth=mixdepth, internal=True)
        jm_addrs = {addr: jm_address for addr, jm_address in addrs.items()
                    if not self.wallet.adb.is_used(addr)}
        if jm_addrs:
            addrs = self.last_few_addresses(jm_addrs)
        else:
            addrs = self.reserve_jm_addrs(1, internal=True)
            addr = addrs[0]
            index = self.wallet.get_address_index(addr)
            jm_addr = JMAddress(mixdepth=mixdepth, branch=1, index=index)
            self.logger.debug(f'generated JM address {addr}: {jm_addr}')
            self.add_jm_address(addr, jm_addr)
        return addrs[0]

    # jmclient/wallet.py estimate_tx_fee
    def estimate_tx_fee(self, ins, outs, txtype='p2wpkh', outtype=None,
                        extra_bytes=0):
        '''Returns an estimate of the number of satoshis required
        for a transaction with the given number of inputs and outputs,
        based on information from the blockchain interface.

        Arguments:
        ins: int, number of inputs
        outs: int, number of outputs
        txtype: either a single string, or a list of strings
        outtype: either None or a list of strings
        extra_bytes: an int
        These arguments are intended to allow a kind of 'default', where
        all the inputs and outputs match a predefined type (that of the
        wallet), but also allow customization for heterogeneous input and
        output types. For supported input and output types, see the keys of
        the dicts `inmults` and `outmults` in
        jmbitcoin.secp256k1_transaction.estimate_tx_size`.

        Returns:
        a single integer number of satoshis as estimate.
        '''
        fee_per_kb = self.estimate_fee_per_kb(self.jmconf.tx_fees)
        if fee_per_kb is None:
            raise RuntimeError("Cannot estimate fee per kB, possibly" +
                               " a failure of connection to the blockchain.")
        absurd_fee = self.jmconf.absurd_fee_per_kb
        if fee_per_kb > absurd_fee:
            # This error is considered critical; for safety reasons, shut down.
            raise ValueError("Estimated fee " +
                             btc.fee_per_kb_to_str(fee_per_kb) +
                             " greater than absurd value " +
                             btc.fee_per_kb_to_str(absurd_fee) + ", quitting.")

        # See docstring for explanation:
        if isinstance(txtype, str):
            ins = [txtype] * ins
        else:
            assert isinstance(txtype, list)
            ins = txtype
        if outtype is None:
            outs = [txtype] * outs
        elif isinstance(outtype, str):
            outs = [outtype] * outs
        else:
            assert isinstance(outtype, list)
            outs = outtype

        # Note: the calls to `estimate_tx_size` in this code
        # block can raise `NotImplementedError` if any of the
        # strings in (ins, outs) are not known script types.
        if not btc.there_is_one_segwit_input(ins):
            tx_estimated_bytes = btc.estimate_tx_size(ins, outs) + extra_bytes
            return int((tx_estimated_bytes * fee_per_kb)/Decimal(1000.0))
        else:
            witness_estimate, non_witness_estimate = btc.estimate_tx_size(
                ins, outs)
            non_witness_estimate += extra_bytes
            return int(int(ceil(non_witness_estimate + 0.25*witness_estimate) *
                           fee_per_kb)/Decimal(1000.0))

    # jmclient/wallet_service.py WalletService.register_callbacks
    def wallet_service_register_callbacks(self, callbacks, txinfo,
                                          cb_type="all"):
        """ Register callbacks that will be called by the
        transaction monitor loop, on transactions stored under
        our wallet label (see WalletService.get_wallet_name()).
        Callback arguments are currently (txd, txid) and return
        is boolean, except "confirmed" callbacks which have
        arguments (tx, txid, confirmations).
        Note that callbacks MUST correctly return True if they
        recognized the transaction and processed it, and False
        if not. The True return value will be used to remove
        the callback from the list.
        Arguments:
        `callbacks` - a list of functions with signature as above
        and return type boolean.
        `txinfo` - either a txid expected for the transaction, if
        known, or a tuple of the ordered output set, of the form
        ((CScript, int), ..). This is be constructed from the
        CMutableTransaction vout list.
        See WalletService.transaction_monitor().
        `cb_type` - must be one of "all", "unconfirmed", "confirmed";
        the first type will be called back once for every new
        transaction, the second only once when the number of
        confirmations is 0, and the third only once when the number
        of confirmations is > 0.
        """
        if cb_type == "all":
            # note that in this case, txid is ignored.
            self.callbacks["all"].extend(callbacks)
        elif cb_type in ["unconfirmed", "confirmed"]:
            if callbacks:
                reg = self.callbacks[cb_type].setdefault(txinfo, [])
                if isinstance(reg, str):
                    # found a txid breadcrumb for this txinfo
                    reg = self.callbacks[cb_type].setdefault(reg, [])
                reg.extend(callbacks)
        else:
            assert False, "Invalid argument: " + cb_type

    # jmclient/wallet_service.py WalletService.default_autofreeze_warning_cb
    def default_autofreeze_warning_cb(self, outpoint, utxo):
        utxostr = f'{outpoint}: address={utxo.address}, value={utxo.value}'
        self.logger.warning(
            "WARNING: new utxo has been automatically "
            "frozen to prevent forced address reuse: ")
        self.logger.warning(utxostr)
        self.logger.warning(
            "You can unfreeze this utxo with the method "
            "on the Coins tab.")

    # jmclient/wallet_service.py WalletService.set_autofreeze_warning_cb
    def set_autofreeze_warning_cb(self, cb=None):
        """ This callback takes a single argument, the
        string representation of a utxo in form txid:index,
        and informs the user that the utxo has been frozen.
        It returns nothing (the user is not deciding in this case,
        as the decision was already taken by the configuration).
        """
        if cb is None:
            self.autofreeze_warning_cb = self.default_autofreeze_warning_cb
        else:
            self.autofreeze_warning_cb = cb

    # jmclient/wallet_service.py WalletService.check_for_reuse
    def check_for_reuse(self, added_utxos):
        """ (a) Check if addresses in new utxos are already in
        used address list, (b) disable the new utxo if it returned as true
        for (a), and it passes the filter set in the configuration.
        """
        to_be_frozen = set()
        w = self.wallet
        for outpoint, au in added_utxos.items():
            received = w.adb.get_addr_io(au.address)[0]
            if len(received) > 1:
                to_be_frozen.add(outpoint)

        # disable those that passed the first check, before the addition,
        # if they satisfy configured logic
        for outpoint in to_be_frozen:
            freeze_threshold = self.jmconf.max_sats_freeze_reuse
            utxo = added_utxos[outpoint]
            if freeze_threshold == -1 or utxo.value <= freeze_threshold:
                # freezing of coins must be communicated to user:
                w.set_frozen_state_of_coins([outpoint], True)
                self.autofreeze_warning_cb(outpoint, utxo)

    # jmclient/wallet_service.py WalletService.transaction_monitor
    async def transaction_monitor(self, tx, txid):
        w = self.wallet
        tx_mined_info = w.adb.get_tx_height(txid)
        confs = tx_mined_info.conf
        if confs < 0:
            self.logger.info(
                "Transaction: " + txid + " has a conflict, abandoning.")
            self.active_txs.pop(txid, None)
            return

        if confs == 0:
            if txid in self.active_txs:
                return

        added_utxos = {}
        for n, o in enumerate(tx.outputs()):
            if w.is_mine(o.address):
                added_utxos[f'{txid}:{n}'] = o

        if txid not in self.processed_txids:
            self.check_for_reuse(added_utxos)
            self.processed_txids.add(txid)

        # first fire 'all' type callbacks, irrespective of if the
        # transaction pertains to anything known (but must
        # have correct label per above); filter on this Joinmarket
        # wallet label, or the external monitoring label:
        for f in self.callbacks["all"]:
            # note we need no return value as we will never
            # remove these from the list
            f(tx, txid)

        # txid is not always available at the time of callback registration.
        # Migrate any callbacks registered under the provisional key, and
        # leave a txid breadcrumb so check_callback_called can find it.
        # NOTE: in base code used in src/jmclient/payjoin.py for PSBT
        txos = tuple((o.scriptpubkey, o.value) for o in tx.outputs())
        for cb_type in ["unconfirmed", "confirmed"]:
            callbacks = self.callbacks[cb_type]
            reg = callbacks.get(txos)
            if isinstance(reg, list):
                callbacks.setdefault(txid, [])[:0] = reg
                callbacks[txos] = txid

        if confs == 0 and txid not in self.active_txs:
            callbacks = [f for f in
                         self.callbacks["unconfirmed"].pop(txid, [])
                         if not f(tx, txid)]
            if callbacks:
                self.callbacks["unconfirmed"][txid] = callbacks
            else:
                self.callbacks["unconfirmed"].pop(txos, None)
            # we always add into active_txs, even if the caller
            # didn't create any confirmed callbacks, because we
            # need to trigger process_new_tx logic to update
            # the height of the utxo in UtxoManager
            self.active_txs[txid] = tx

        if confs > 0 and txid in self.active_txs:
            callbacks = [f for f in
                         self.callbacks["confirmed"].pop(txid, [])
                         if not f(tx, txid, confs)]
            if callbacks:
                self.callbacks["confirmed"][txid] = callbacks
            else:
                self.callbacks["confirmed"].pop(txos, None)
                # no more callbacks registered; stop monitoring tx
                self.active_txs.pop(txid, None)

    # jmclient/wallet_service.py WalletService.check_callback_called
    def check_callback_called(self, txinfo, callback, cbtype, msg):
        """ Intended to be a deferred Task to be scheduled some
        set time after the callback was registered. "all" type
        callbacks do not expire and are not included.
        If the callback was previously called, return True, otherwise False.
        """
        assert cbtype in ["unconfirmed", "confirmed"]
        callbacks = self.callbacks[cbtype]
        if isinstance(txinfo, str):
            txid = txinfo
            reg = callbacks.get(txid)
        else:
            txid = None
            reg = callbacks.get(txinfo)
            if isinstance(reg, str):
                # found a txid breadcrumb for this txinfo
                txid = reg
                reg = callbacks.get(txid)
        if reg:
            if callback in reg:
                # the callback was not called, drop it and warn
                reg.remove(callback)
                if not reg:
                    del callbacks[txinfo]
                    if txid:
                        callbacks.pop(txid, None)
                        # no more callbacks registered; stop monitoring tx
                        self.active_txs.pop(txid, None)
                self.logger.info("Timed out: " + msg)
                return False
            # if callback is not in the list, it was already
            # processed and so do nothing.
        return True
