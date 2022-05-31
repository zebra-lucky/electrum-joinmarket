# -*- coding: utf-8 -*-

'''Some helper functions for testing'''

from typing import List, Optional, Tuple, Union

from electrum.bitcoin import pubkey_to_address, address_to_script
from electrum.logging import get_logger, ShortcutInjectingFilter

from electrum.plugins.joinmarket.jmbase import hextobin, dictchanger
from electrum.plugins.joinmarket.jm_wallet import JMWallet


LOGGING_SHORTCUT = 'J'
log = get_logger(__name__)
log.addFilter(ShortcutInjectingFilter(shortcut=LOGGING_SHORTCUT))


default_max_cj_fee = (1, float('inf'))


# callbacks for making transfers in-script with direct_send:
def dummy_accept_callback(tx, destaddr, actual_amount, fee_est,
                          custom_change_addr):
    return True


def dummy_info_callback(msg):
    pass


class DummyJMWallet(JMWallet):

    def __init__(self, jmman):
        super().__init__(jmman)
        self.fake_query_results = None
        self.qusfail = False
        self.default_confs = 20
        self.confs_for_qus = {}
        self.inject_addr_get_failure = False

    def insert_fake_query_results(self, fqr: List[dict]) -> None:
        self.fake_query_results = fqr

    def setQUSFail(self, state: bool) -> None:
        self.qusfail = state

    def get_internal_addr(self, mixing_depth):
        if self.inject_addr_get_failure:
            raise Exception("address get failure")
        return super().get_internal_addr(mixing_depth)

    def set_confs(self, confs_utxos) -> None:
        # we hook specific confirmation results
        # for specific utxos so that query_utxo_set
        # can return a non-constant fake value.
        self.confs_for_qus.update(confs_utxos)

    def reset_confs(self) -> None:
        self.confs_for_qus = {}

    def add_extra_utxo(self, txid, index, value, md,
                       script=None,
                       i=0):
        pass

    async def query_utxo_set(
            self,
            txouts: Union[Tuple[bytes, int], List[Tuple[bytes, int]]],
            includeconfs: bool = False,
            include_mempool: bool = True) -> List[Optional[dict]]:
        if not isinstance(txouts, list):
            txouts = [txouts]
        if self.qusfail:
            # simulate failure to find the utxo
            return [None] * len(txouts)
        if self.fake_query_results:
            result = []
            for x in self.fake_query_results:
                for y in txouts:
                    if y == x['utxo']:
                        result.append(x)
            return result
        result = []
        # external maker utxos
        known_outs = {
            "03243f4a659e278a1333f8308f6aaf32"
            "db4692ee7df0340202750fd6c09150f6:1":
                "03a2d1cbe977b1feaf8d0d5cc28c6868"
                "59563d1520b28018be0c2661cf1ebe4857",
            "498faa8b22534f3b443c6b0ce202f31e"
            "12f21668b4f0c7a005146808f250d4c3:0":
                "02b4b749d54e96b04066b0803e372a43"
                "d6ffa16e75a001ae0ed4b235674ab286be",
            "3f3ea820d706e08ad8dc1d2c392c98fa"
            "cb1b067ae4c671043ae9461057bd2a3c:1":
                "023bcbafb4f68455e0d1d117c178b0e8"
                "2a84e66414f0987453d78da034b299c3a9"}
        known_outs = dictchanger(known_outs)
        # our wallet utxos, faked, for podle tests: utxos are doctored
        # (leading 'f'), and the lists are (amt, age)
        wallet_outs = {
            'b82763a40e3c701669cb57341a8116d7'
            'f6d4cd2dbd0648d839c6b754aac37dd2:4': [2500000, 2],
            'b82763a40e3c701669cb57341a8116d7'
            'f6d4cd2dbd0648d839c6b754aac37dd2:3': [2500000, 6],
            'b82763a40e3c701669cb57341a8116d7'
            'f6d4cd2dbd0648d839c6b754aac37dd2:1': [2500000, 3],
            'b82763a40e3c701669cb57341a8116d7'
            'f6d4cd2dbd0648d839c6b754aac37dd2:2': [2500000, 6]}
        wallet_outs = dictchanger(wallet_outs)

        if includeconfs and set(txouts).issubset(set(wallet_outs)):
            # includeconfs used as a trigger for a podle check;
            # here we simulate a variety of amount/age returns
            results = []
            for to in txouts:
                results.append({'value': wallet_outs[to][0],
                                'confirms': wallet_outs[to][1]})
            return results
        if txouts[0] in known_outs:
            pubkey = known_outs[txouts[0]].hex()
            addr = pubkey_to_address('p2wpkh', pubkey)
            scr = address_to_script(addr)
            return [{'value': 2500000,
                     'address': addr,
                     'script': scr,
                     'confirms': self.default_confs}]
        for t in txouts:
            result_dict = {
                'value': 2000000,
                'address': "mrcNu71ztWjAQA6ww9kHiW3zBWSQidHXTQ",
                'script': hextobin('76a91479b000887626b294'
                                   'a914501a4cd226b58b23598388ac')
            }
            if includeconfs:
                if t in self.confs_for_qus:
                    confs = self.confs_for_qus[t]
                else:
                    confs = self.default_confs
                result_dict['confirms'] = confs
            result.append(result_dict)
        return result
