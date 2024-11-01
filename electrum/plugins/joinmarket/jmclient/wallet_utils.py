from numbers import Integral
from collections import Counter
from itertools import islice
from typing import Optional, Tuple

from electrum.transaction import Transaction


"""The classes in this module manage representations
of wallet states; but they know nothing about Bitcoin,
so do not attempt to validate addresses, keys, BIP32 or relationships.
A console based output is provided as default, but underlying serializations
can be used by calling classes for UIs.
"""


"""
WalletView* classes manage wallet representations.
"""


class WalletError(Exception):
    pass


class WalletMixdepthOutOfRange(WalletError):

    def __init__(self):
        super().__init__("Mixdepth outside of wallet's range.")


class WalletViewBase(object):

    def __init__(self, wallet_path_repr, children=None, serclass=str,
                 custom_separator=None):
        self.wallet_path_repr = wallet_path_repr
        self.children = children
        self.serclass = serclass
        self.separator = custom_separator if custom_separator else "\t"

    def get_balance(self, include_unconf=True):
        if not include_unconf:
            raise NotImplementedError("Separate conf/unconf balances"
                                      " not impl.")
        return sum([x.get_balance() for x in self.children])

    def get_available_balance(self):
        return sum([x.get_available_balance() for x in self.children])

    def get_balances(self, include_unconf=True):
        return (self.get_balance(include_unconf=include_unconf),
                self.get_available_balance())

    def get_fmt_balance(self, include_unconf=True):
        total_balance, available_balance = self.get_balances(
            include_unconf=include_unconf)
        if available_balance != total_balance:
            return "{0:.08f} ({1:.08f})".format(available_balance,
                                                total_balance)
        else:
            return "{0:.08f}".format(total_balance)

    def get_fmt_balance_json(self, include_unconf=True):
        total_balance, available_balance = self.get_balances(
            include_unconf=include_unconf)
        return {self.balance_key_name: "{0:.08f}".format(total_balance),
                "available_balance": "{0:.08f}".format(available_balance)}


class WalletViewEntry(WalletViewBase):

    balance_key_name = "amount"

    def __init__(self, wallet_path_repr, account, address_type, aindex, addr,
                 amounts, status='new', serclass=str, priv=None,
                 custom_separator=None, label=None):
        super().__init__(wallet_path_repr, serclass=serclass,
                         custom_separator=custom_separator)
        self.account = account
        assert address_type in [0, 1]
        self.address_type = address_type
        assert isinstance(aindex, Integral)
        assert aindex >= 0
        self.aindex = aindex
        self.address = addr
        self.unconfirmed_amount, self.confirmed_amount = amounts
        # note no validation here
        self.private_key = priv
        self.status = status
        self.label = label

    def is_frozen(self):
        return "[FROZEN]" in self.status

    def get_balance(self, include_unconf=True):
        """Overwrites base class since no children
        """
        if not include_unconf:
            raise NotImplementedError("Separate conf/unconf balances"
                                      " not impl.")
        return self.unconfirmed_amount/1e8

    def get_available_balance(self, include_unconf=True):
        return 0 if self.is_frozen() else self.get_balance()

    def serialize(self):
        left = self.serialize_wallet_position()
        addr = self.serialize_address()
        amounts = self.serialize_amounts()
        status = self.serialize_status()
        label = self.serialize_label()
        extradata = self.serialize_extra_data()
        return self.serclass(self.separator.join([
            left, addr, amounts, status, label, extradata]))

    def serialize_json(self):
        json_serialized = {
            "hd_path": self.wallet_path_repr,
            "address": self.serialize_address(),
            "status": self.serialize_status(),
            "label": self.serialize_label(),
            "extradata": self.serialize_extra_data()
        }
        json_serialized.update(self.get_fmt_balance_json())
        return json_serialized

    def serialize_wallet_position(self):
        return self.wallet_path_repr.ljust(20)

    def serialize_address(self):
        return self.serclass(self.address)

    def serialize_amounts(self, unconf_separate=False, denom="BTC"):
        if denom != "BTC":
            raise NotImplementedError("Altern. denominations not yet"
                                      " implemented.")
        if unconf_separate:
            raise NotImplementedError("Separate handling of unconfirmed funds "
                                      "not yet implemented.")
        return self.serclass("{0:.08f}".format(self.unconfirmed_amount/1e8))

    def serialize_status(self):
        return self.serclass(self.status)

    def serialize_label(self):
        if self.label:
            return self.serclass(self.label)
        else:
            return self.serclass("")

    def serialize_extra_data(self):
        if self.private_key:
            return self.serclass(self.private_key)
        else:
            return self.serclass("")


class WalletViewBranch(WalletViewBase):

    balance_key_name = "balance"

    def __init__(self, wallet_path_repr, account, address_type,
                 branchentries=None, xpub=None, serclass=str,
                 custom_separator=None):
        super().__init__(wallet_path_repr, children=branchentries,
                         serclass=serclass, custom_separator=custom_separator)
        self.account = account
        assert address_type in [0, 1]
        self.address_type = address_type
        if xpub:
            assert xpub[0:4].lower() in ['xpub', 'ypub', 'zpub',
                                         'tpub', 'upub', 'vpub']
        self.xpub = xpub if xpub else ""
        self.branchentries = branchentries

    def serialize(self, entryseparator="\n", summarize=False):
        if summarize:
            return ""
        lines = [self.serialize_branch_header()]
        for we in self.branchentries:
            lines.append(we.serialize())
        footer = "Balance:" + self.separator + self.get_fmt_balance()
        lines.append(footer)
        return self.serclass(entryseparator.join(lines))

    def serialize_json(self, summarize=False):
        if summarize:
            return {}
        json_serialized = {
            "branch": self.serialize_branch_header(),
            "entries": [x.serialize_json() for x in self.branchentries]
        }
        json_serialized.update(self.get_fmt_balance_json())
        return json_serialized

    def serialize_branch_header(self):
        start = ("external addresses" if self.address_type == 0
                 else "internal addresses")
        if self.address_type == -1:
            start = "Imported keys"
        return self.serclass(self.separator.join([start, self.wallet_path_repr,
                                                  self.xpub]))


class WalletViewAccount(WalletViewBase):

    balance_key_name = "account_balance"

    def __init__(self, wallet_path_repr, account, branches=None,
                 account_name="mixdepth", serclass=str, custom_separator=None,
                 xpub=None):
        super().__init__(wallet_path_repr, children=branches,
                         serclass=serclass, custom_separator=custom_separator)
        self.account = account
        self.account_name = account_name
        self.xpub = xpub
        if branches:
            assert len(branches) in [2]
            assert all([isinstance(x, WalletViewBranch) for x in branches])
        self.branches = branches

    def serialize(self, entryseparator="\n", summarize=False):
        header = self.account_name + self.separator + str(self.account)
        if self.xpub:
            header = header + self.separator + self.xpub
        footer = ("Balance for mixdepth " +
                  str(self.account) + ":" +
                  self.separator + self.get_fmt_balance())
        if summarize:
            return self.serclass(
                entryseparator.join([
                    x.serialize("", summarize=True)
                    for x in self.branches] + [footer]
                ))
        else:
            return self.serclass(
                entryseparator.join(
                    [header] +
                    [x.serialize(entryseparator)
                     for x in self.branches] + [footer]))

    def serialize_json(self, summarize=False):
        json_serialized = {"account": str(self.account)}
        json_serialized.update(self.get_fmt_balance_json())
        if summarize:
            return json_serialized
        json_serialized["branches"] = [x.serialize_json()
                                       for x in self.branches]
        return json_serialized


class WalletView(WalletViewBase):

    balance_key_name = "total_balance"

    def __init__(self, wallet_path_repr, accounts, wallet_name="JM wallet",
                 serclass=str, custom_separator=None):
        super().__init__(wallet_path_repr, children=accounts,
                         serclass=serclass, custom_separator=custom_separator)
        self.wallet_name = wallet_name
        assert all([isinstance(x, WalletViewAccount) for x in accounts])
        self.accounts = accounts

    def serialize(self, entryseparator="\n", summarize=False):
        header = self.wallet_name
        if len(self.accounts) > 1:
            footer = "Total balance:" + self.separator + \
                self.get_fmt_balance()
        else:
            footer = ""
        if summarize:
            return self.serclass(
                entryseparator.join(
                    [header] +
                    [x.serialize("", summarize=True)
                     for x in self.accounts] +
                    [footer]))
        else:
            return self.serclass(
                entryseparator.join(
                    [header] +
                    [x.serialize(entryseparator, summarize=False)
                     for x in self.accounts] +
                    [footer]))

    def serialize_json(self, summarize=False):
        json_serialized = {
            "wallet_name": self.wallet_name,
            "accounts": [x.serialize_json(summarize=summarize)
                         for x in self.accounts]}
        json_serialized.update(self.get_fmt_balance_json())
        return json_serialized


def get_tx_info(
    jmman,
    txid: bytes,
    tx_cache: Optional[dict] = None
) -> Tuple[bool, int, int, dict, int, Transaction]:
    """
    Retrieve some basic information about the given transaction.

    :param txid: txid as binary
    :param tx_cache: optional cache (dictionary) for get_transaction results
    :return: tuple
        is_coinjoin: bool
        cj_amount: int, only useful if is_coinjoin==True
        cj_n: int, number of cj participants, only useful if is_coinjoin==True
        output_script_values: {script: value} dict including all outputs
        blocktime: int, blocktime this tx was mined
        txd: deserialized transaction object (hex-encoded data)
    """
    if tx_cache is not None and txid in tx_cache:
        tx, blocktime = tx_cache[txid]
    else:
        tx = jmman.wallet.adb.get_transaction(txid.hex())
        blocktime = 0  # used in base code for wallet-tool.py history cmd
        if tx_cache is not None:
            tx_cache[txid.hex()] = (tx, blocktime)
    output_script_values = {x.scriptpubkey: x.value for x in tx.outputs()}
    value_freq_list = sorted(
        Counter(output_script_values.values()).most_common(),
        key=lambda x: -x[1])
    non_cj_freq = (0 if len(value_freq_list) == 1 else
                   sum(next(islice(zip(*value_freq_list[1:]), 1, None))))
    is_coinjoin = (value_freq_list[0][1] > 1 and
                   value_freq_list[0][1] in
                   [non_cj_freq, non_cj_freq + 1])
    cj_amount = value_freq_list[0][0]
    cj_n = value_freq_list[0][1]
    return (is_coinjoin, cj_amount, cj_n, output_script_values, blocktime, tx)


def get_utxo_status_string(utxos, utxos_enabled, path):
    has_frozen_utxo = False
    has_pending_utxo = False
    for utxo, utxodata in utxos.items():
        if tuple(path) == tuple(utxodata["path"]):
            if utxo not in utxos_enabled:
                has_frozen_utxo = True
            if utxodata['confs'] <= 0:
                has_pending_utxo = True

    utxo_status_string = ""
    if has_frozen_utxo:
        utxo_status_string += ' [FROZEN]'
    if has_pending_utxo:
        utxo_status_string += ' [PENDING]'
    return utxo_status_string


def wallet_display(jmman, showprivkey, displayall=False,
                   serialized=True, summarized=False, mixdepth=None,
                   jsonified=False, password=None):
    """build the walletview object,
    then return its serialization directly if serialized,
    else return the WalletView object.
    """
    def get_addr_status(addr_path, utxos, utxos_enabled, is_new, is_internal):
        addr_balance = 0
        status = []

        for utxo, utxodata in utxos.items():
            if tuple(addr_path) != tuple(utxodata['path']):
                continue
            addr_balance += utxodata['value']

            is_coinjoin, cj_amount, cj_n = get_tx_info(jmman, utxo[0])[:3]
            if is_coinjoin and utxodata['value'] == cj_amount:
                status.append('cj-out')
            elif is_coinjoin:
                status.append('change-out')
            elif is_internal:
                status.append('non-cj-change')
            else:
                status.append('deposit')

        out_status = 'new' if is_new else 'used'
        if len(status) > 1:
            out_status = 'reused'
        elif len(status) == 1:
            out_status = status[0]

        out_status += get_utxo_status_string(utxos, utxos_enabled, addr_path)

        return addr_balance, out_status

    acctlist = []

    utxos = jmman.jmw.get_utxos_by_mixdepth(
        include_disabled=True, includeconfs=True)
    utxos_enabled = jmman.jmw.get_utxos_by_mixdepth()

    if mixdepth:
        md_range = range(mixdepth, mixdepth + 1)
    else:
        md_range = range(jmman.jmconf.mixdepth + 1)
    for m in md_range:
        branchlist = []
        for address_type in [0, 1]:  # EXTERNAL, INTERNAL
            entrylist = []
            if address_type == 0:
                # users would only want to hand out the xpub for externals
                xpub_key = jmman.jmw.get_bip32_pub_export(m, address_type)
            else:
                xpub_key = ""
            jm_addrs = jmman.jmw.get_jm_addresses(mixdepth=m,
                                                  internal=bool(address_type))
            for addr in jmman.jmw.last_few_addresses(jm_addrs):
                jm_addr = jm_addrs[addr]
                path = jm_addr.index
                k = path[1]
                label = jmman.jmw.get_address_label(addr)
                is_new = not jmman.wallet.adb.is_used(addr)
                balance, status = get_addr_status(
                    path, utxos[m], utxos_enabled[m], is_new, address_type)
                if showprivkey:
                    privkey = jmman.jmw.get_wif_path(path, password)
                else:
                    privkey = ''
                if (displayall or balance > 0 or
                        (status == 'new' and address_type == 0)):
                    entrylist.append(WalletViewEntry(
                        jmman.jmw.get_path_repr(path), m, address_type,
                        k, addr, [balance, balance], priv=privkey,
                        status=status, label=label))
            path = jmman.jmw.get_path_repr(jmman.jmw.get_path(m, address_type))
            branchlist.append(WalletViewBranch(path, m, address_type,
                                               entrylist, xpub=xpub_key))

        # get the xpub key of the whole account
        xpub_account = jmman.jmw.get_bip32_pub_export(mixdepth=m)
        path = jmman.jmw.get_path_repr(jmman.jmw.get_path(m))
        acctlist.append(WalletViewAccount(path, m, branchlist,
                                          xpub=xpub_account))
    path = jmman.jmw.get_path_repr(jmman.jmw.get_path())
    walletview = WalletView(path, acctlist)
    if serialized:
        if jsonified:
            return walletview.serialize_json(summarize=summarized)
        else:
            return walletview.serialize(summarize=summarized)
    else:
        return walletview
