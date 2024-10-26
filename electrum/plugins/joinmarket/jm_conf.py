# -*- coding: utf-8 -*-

import copy

from electrum import constants
from electrum.i18n import _
from electrum.json_db import register_dict
from electrum.simple_config import FEE_ETA_TARGETS

from .jmclient.cli_options import MAX_DEFAULT_REL_FEE, MIN_MAX_DEFAULT_ABS_FEE


register_dict('msg_channels', dict, None)


class JMConf:

    DEFAULT_MIXDEPTH = 4
    DEFAULT_MAX_MIXDEPTH = 4
    DEFAULT_MINCJAMOUNT = 100000
    # TIMEOUT section
    DEFAULT_MAKER_TIMEOUT = 60
    DEFAULT_MAKER_TIMEOUT_REGTEST = 15
    DEFAULT_UNCONFIRM_TIMEOUT_SEC = 180
    DEFAULT_CONFIRM_TIMEOUT_HOURS = 6
    # POLICY section
    DEFAULT_MERGE_ALGORITHM = 'default'
    DEFAULT_GAPLIMIT = 6
    DEFAULT_TX_FEES = 5
    DEFAULT_TX_FEES_FACTOR = 0.2
    DEFAULT_ABSURD_FEE_PER_KB = 350000
    DEFAULT_MAX_SWEEP_FEE_CHANGE = 0.8
    DEFAULT_TX_BROADCAST = 'random-peer'
    DEFAULT_MINIMUM_MAKERS = 4
    DEFAULT_MAX_SATS_FREEZE_REUSE = -1
    DEFAULT_INTEREST_RATE = 0.015
    DEFAULT_BONDLESS_MAKERS_ALLOWANCE = 0.125
    DEFAULT_BOND_VALUE_EXPONENT = 1.3
    DEFAULT_TAKER_UTXO_RETRIES = 3
    DEFAULT_TAKER_UTXO_AGE = 5
    DEFAULT_TAKER_UTXO_AMTPERCENT = 20
    DEFAULT_ACCEPT_COMMITMENT_BROADCASTS = 1
    MIN_TAKER_UTXO_AGE = 1

    # OTHER section
    DEFAULT_MAX_CJ_FEE_ABS = MIN_MAX_DEFAULT_ABS_FEE
    DEFAULT_MAX_CJ_FEE_REL = MAX_DEFAULT_REL_FEE
    DEFAULT_MAX_CJ_FEE_CONFIRMED = False

    # GUI section
    DEFAULT_CHECK_HIGH_FEE = 2
    DEFAULT_ORDER_WAIT_TIME = 30

    DEFAULT_NOTIFY_JM_TXS = False       # GUI notify on JM txs arrival
    DEFAULT_SUBSCRIBE_SPENT = False     # on server subscribe to spent jm addrs

    CLEAR_JM_DATA_MSG = _('Are you sure to clear all wallet JoinMarket data?'
                          ' This is not recommended if there is'
                          ' no particular need.')

    BLOCKCHAIN_SOURCE = 'electrum'

    MESSAGING_ONION_MAINET = {
        'type': 'onion',
        'enabled': True,
        'socks5_host': 'localhost',
        'socks5_port': '9050',
        'directory_nodes':
            'g3hv4uynnmynqqq2mchf3fcm3yd46kfzmcdogejuckgwknwyq5ya6iad'
                '.onion:5222,'
            '3kxw6lf5vf6y26emzwgibzhrzhmhqiw6ekrek3nqfjjmhwznb2moonad'
                '.onion:5222,'
            'bqlpq6ak24mwvuixixitift4yu42nxchlilrcqwk2ugn45tdclg42qid'
                '.onion:5222',
    }

    MESSAGING_ONION_TESTNET = {
        'type': 'onion',
        'enabled': True,
        'socks5_host': 'localhost',
        'socks5_port': 9050,
        'directory_nodes':
            'rr6f6qtleiiwic45bby4zwmiwjrj3jsbmcvutwpqxjziaydjydkk5iad'
                '.onion:5222,'
            'k74oyetjqgcamsyhlym2vgbjtvhcrbxr4iowd4nv4zk5sehw4v665jad'
                '.onion:5222,'
            'y2ruswmdbsfl4hhwwiqz4m3sx6si5fr6l3pf62d4pms2b53wmagq3eqd'
                '.onion:5222',
    }

    MESSAGING_ONION_REGTEST = {
        'type': 'onion',
        'enabled': True,
        'socks5_host': 'localhost',
        'socks5_port': 9050,
        'directory_nodes':
            'wvidnzpzkl562gme2zkntxyigukjgzdgjmtbag6rcwt6mxeu74mwr5id'
                '.onion:5222',
    }

    MESSAGING_DARKSCIENCE = {
        'type': 'irc',
        'enabled': True,
        'channel': 'joinmarket-pit',
        'host':
            'darkirc6tqgpnwd3blln3yfv5ckl47eg7llfxkmtovrv7c7iwohhb6ad.onion',
        'port': 6697,
        'usessl': True,
        'socks5': True,
        'socks5_host': 'localhost',
        'socks5_port': 9050,
    }

    MESSAGING_HACKINT = {
        'type': 'irc',
        'enabled': True,
        'channel': 'joinmarket-pit',
        'host':
            'ncwkrwxpq2ikcngxq3dy2xctuheniggtqeibvgofixpzvrwpa77tozqd.onion',
        'port': 6667,
        'usessl': False,
        'socks5': True,
        'socks5_host': 'localhost',
        'socks5_port': 9050,
    }

    MESSAGING_IRC_CHANNEL = {
        'type': 'irc',
        'enabled': True,
        'channel': 'joinmarket-pit',
        'host': 'localhost',
        'port': 6667,
        'usessl': True,
        'socks5': False,
        'socks5_host': 'localhost',
        'socks5_port': 9050,
    }

    DEFAULT_MSG_CHANNELS = {
        'irc1': copy.deepcopy(MESSAGING_DARKSCIENCE),
        'irc2': copy.deepcopy(MESSAGING_HACKINT),
        'onion': copy.deepcopy(MESSAGING_ONION_MAINET),
    }

    DEFAULT_MSG_CHANNELS_TESTNET = {
        'irc1': copy.deepcopy(MESSAGING_IRC_CHANNEL),
        'irc2': copy.deepcopy(MESSAGING_IRC_CHANNEL),
        'onion': copy.deepcopy(MESSAGING_ONION_TESTNET),
    }
    DEFAULT_MSG_CHANNELS_TESTNET['irc2']['enabled'] = False

    DEFAULT_MSG_CHANNELS_REGTEST = {
        'irc1': copy.deepcopy(MESSAGING_IRC_CHANNEL),
        'irc2': copy.deepcopy(MESSAGING_IRC_CHANNEL),
        'onion': copy.deepcopy(MESSAGING_ONION_REGTEST),
    }
    DEFAULT_MSG_CHANNELS_REGTEST['irc1']['enabled'] = False
    DEFAULT_MSG_CHANNELS_REGTEST['irc2']['enabled'] = False

    def __init__(self, jmman):
        self.jmman = jmman
        self.logger = jmman.logger
        self.wallet = jmman.wallet
        self.jmw = jmman.jmw

        self.BITCOIN_DUST_THRESHOLD = 2730
        self.DUST_THRESHOLD = 10 * self.BITCOIN_DUST_THRESHOLD
        self._mincjamount = self.DEFAULT_MINCJAMOUNT

    def init_max_mixdepth(self):
        if self.max_mixdepth != self.mixdepth:
            self.max_mixdepth = max(self.max_mixdepth, self.mixdepth)

    @property
    def blockchain_network(self):
        if not constants.net.TESTNET:
            return constants.net.NET_NAME
        elif constants.net.NET_NAME == 'regtest':
            return 'testnet'
        else:
            return constants.net.NET_NAME

    # unsorted cli/wallet options
    @property
    def mixdepth(self):
        '''effective maximum mixdepth to be used by joinmarket'''
        if not self.jmman.enabled:
            return self.DEFAULT_MIXDEPTH
        return self.jmw.get_jm_data('mixdepth', self.DEFAULT_MIXDEPTH)

    @mixdepth.setter
    def mixdepth(self, mixdepth):
        '''effective maximum mixdepth to be used by joinmarket'''
        assert isinstance(mixdepth, int)
        self.jmw.set_jm_data('mixdepth', mixdepth)
        if self.max_mixdepth < mixdepth:
            self.max_mixdepth = mixdepth

    @property
    def max_mixdepth(self):
        '''highest mixdepth ever used in wallet, important for synching'''
        return self.jmw.get_jm_data('max_mixdepth', self.DEFAULT_MAX_MIXDEPTH)

    @max_mixdepth.setter
    def max_mixdepth(self, max_mixdepth):
        '''highest mixdepth ever used in wallet, important for synching'''
        assert isinstance(max_mixdepth, int)
        if self.max_mixdepth > max_mixdepth:
            self.logger.warning(f'Trying to set max_mixdepth to {max_mixdepth}'
                                f' when current value is {self.max_mixdepth}')
            return
        self.jmw.set_jm_data('max_mixdepth', max_mixdepth)

    @property
    def mincjamount(self):
        '''minimum coinjoin amount in transaction in satoshi, default 100k'''
        return self._mincjamount

    @mincjamount.setter
    def mincjamount(self, mincjamount):
        assert isinstance(mincjamount, int)
        self._mincjamount = mincjamount

    def reset_mincjamount(self):
        self._mincjamount = self.DEFAULT_MINCJAMOUNT

    # TIMEOUT section
    @property
    def maker_timeout_sec(self):
        if constants.net.NET_NAME == 'regtest':
            return self.jmw.get_jm_data('maker_timeout_sec',
                                        self.DEFAULT_MAKER_TIMEOUT_REGTEST)
        else:
            return self.jmw.get_jm_data('maker_timeout_sec',
                                        self.DEFAULT_MAKER_TIMEOUT)

    @maker_timeout_sec.setter
    def maker_timeout_sec(self, maker_timeout_sec):
        assert isinstance(maker_timeout_sec, int)
        self.jmw.set_jm_data('maker_timeout_sec', maker_timeout_sec)

    @property
    def unconfirm_timeout_sec(self):
        return self.jmw.get_jm_data('unconfirm_timeout_sec',
                                    self.DEFAULT_UNCONFIRM_TIMEOUT_SEC)

    @unconfirm_timeout_sec.setter
    def unconfirm_timeout_sec(self, unconfirm_timeout_sec):
        assert isinstance(unconfirm_timeout_sec, int)
        self.jmw.set_jm_data('unconfirm_timeout_sec', unconfirm_timeout_sec)

    @property
    def confirm_timeout_hours(self):
        return self.jmw.get_jm_data('confirm_timeout_hours',
                                    self.DEFAULT_CONFIRM_TIMEOUT_HOURS)

    @confirm_timeout_hours.setter
    def confirm_timeout_hours(self, confirm_timeout_hours):
        assert isinstance(confirm_timeout_hours, int)
        self.jmw.set_jm_data('confirm_timeout_hours', confirm_timeout_hours)

    # POLICY section
    @property
    def merge_algorithm(self):
        return self.jmw.get_jm_data('merge_algorithm',
                                    self.DEFAULT_MERGE_ALGORITHM)

    @merge_algorithm.setter
    def merge_algorithm(self, merge_algorithm):
        assert isinstance(merge_algorithm, str)
        self.jmw.set_jm_data('merge_algorithm', merge_algorithm)

    @property
    def gaplimit(self):
        return self.jmw.get_jm_data('gaplimit', self.DEFAULT_GAPLIMIT)

    @gaplimit.setter
    def gaplimit(self, gaplimit):
        assert isinstance(gaplimit, int)
        self.jmw.set_jm_data('gaplimit', gaplimit)

    @property
    def tx_fees(self):
        return self.jmw.get_jm_data('tx_fees', self.DEFAULT_TX_FEES)

    @tx_fees.setter
    def tx_fees(self, tx_fees):
        assert isinstance(tx_fees, int)
        assert tx_fees > 0
        if 1 < tx_fees <= 1000:
            targets = sorted(FEE_ETA_TARGETS)
            target = min(targets, key=lambda x: abs(x-tx_fees))
            if target < tx_fees:
                target_idx = targets.index(target)
                if len(targets) > target_idx + 1:
                    target = targets[target_idx+1]
            if target != tx_fees:
                self.logger.warning(f'tx_fees is set to closest high value'
                                    f' {target} from electrum'
                                    f' FEE_ETA_TARGETS {targets}')
            self.jmw.set_jm_data('tx_fees', target)
        else:
            self.jmw.set_jm_data('tx_fees', tx_fees)

    @property
    def tx_fees_factor(self):
        return self.jmw.get_jm_data('tx_fees_factor',
                                    self.DEFAULT_TX_FEES_FACTOR)

    @tx_fees_factor.setter
    def tx_fees_factor(self, tx_fees_factor):
        assert isinstance(tx_fees_factor, (float, int))
        self.jmw.set_jm_data('tx_fees_factor', float(tx_fees_factor))

    @property
    def absurd_fee_per_kb(self):
        return self.jmw.get_jm_data('absurd_fee_per_kb',
                                    self.DEFAULT_ABSURD_FEE_PER_KB)

    @absurd_fee_per_kb.setter
    def absurd_fee_per_kb(self, absurd_fee_per_kb):
        assert isinstance(absurd_fee_per_kb, int)
        self.jmw.set_jm_data('absurd_fee_per_kb', absurd_fee_per_kb)

    @property
    def max_sweep_fee_change(self):
        return self.jmw.get_jm_data('max_sweep_fee_change',
                                    self.DEFAULT_MAX_SWEEP_FEE_CHANGE)

    @max_sweep_fee_change.setter
    def max_sweep_fee_change(self, max_sweep_fee_change):
        assert isinstance(max_sweep_fee_change, (float, int))
        self.jmw.set_jm_data('max_sweep_fee_change',
                             float(max_sweep_fee_change))

    @property
    def tx_broadcast(self):
        return self.jmw.get_jm_data('tx_broadcast', self.DEFAULT_TX_BROADCAST)

    @tx_broadcast.setter
    def tx_broadcast(self, tx_broadcast):
        assert isinstance(tx_broadcast, str)
        self.jmw.set_jm_data('tx_broadcast', tx_broadcast)

    @property
    def minimum_makers(self):
        return self.jmw.get_jm_data('minimum_makers',
                                    self.DEFAULT_MINIMUM_MAKERS)

    @minimum_makers.setter
    def minimum_makers(self, minimum_makers):
        '''Set need mix counterparties count'''
        assert isinstance(minimum_makers, int)
        self.jmw.set_jm_data('minimum_makers', minimum_makers)

    @property
    def max_sats_freeze_reuse(self):
        '''Threshold number of satoshis below which an incoming utxo
        to a reused address in the wallet will be AUTOMATICALLY frozen.
        This avoids forced address reuse attacks; see:
        https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse

        The default is to ALWAYS freeze a utxo to an already used address,
        whatever the value of it, and this is set with the value -1.
        '''
        return self.jmw.get_jm_data('max_sats_freeze_reuse',
                                    self.DEFAULT_MAX_SATS_FREEZE_REUSE)

    @max_sats_freeze_reuse.setter
    def max_sats_freeze_reuse(self, max_sats_freeze_reuse):
        assert isinstance(max_sats_freeze_reuse, int)
        self.jmw.set_jm_data('max_sats_freeze_reuse', max_sats_freeze_reuse)

    @property
    def interest_rate(self):
        return self.jmw.get_jm_data('interest_rate',
                                    self.DEFAULT_INTEREST_RATE)

    @interest_rate.setter
    def interest_rate(self, interest_rate):
        assert isinstance(interest_rate, (float, int))
        self.jmw.set_jm_data('interest_rate', float(interest_rate))

    @property
    def bondless_makers_allowance(self):
        return self.jmw.get_jm_data('bondless_makers_allowance',
                                    self.DEFAULT_BONDLESS_MAKERS_ALLOWANCE)

    @bondless_makers_allowance.setter
    def bondless_makers_allowance(self, bondless_makers_allowance):
        assert isinstance(bondless_makers_allowance, (float, int))
        self.jmw.set_jm_data('bondless_makers_allowance',
                             float(bondless_makers_allowance))

    @property
    def bond_value_exponent(self):
        return self.jmw.get_jm_data('bond_value_exponent',
                                    self.DEFAULT_BOND_VALUE_EXPONENT)

    @bond_value_exponent.setter
    def bond_value_exponent(self, bond_value_exponent):
        assert isinstance(bond_value_exponent, (float, int))
        self.jmw.set_jm_data('bond_value_exponent', float(bond_value_exponent))

    @property
    def taker_utxo_retries(self):
        return self.jmw.get_jm_data('taker_utxo_retries',
                                    self.DEFAULT_TAKER_UTXO_RETRIES)

    @taker_utxo_retries.setter
    def taker_utxo_retries(self, taker_utxo_retries):
        assert isinstance(taker_utxo_retries, int)
        self.jmw.set_jm_data('taker_utxo_retries', taker_utxo_retries)

    @property
    def taker_utxo_age(self):
        return self.jmw.get_jm_data('taker_utxo_age',
                                    self.DEFAULT_TAKER_UTXO_AGE)

    @taker_utxo_age.setter
    def taker_utxo_age(self, taker_utxo_age):
        '''Set minimal taker utxo confirmations to use in mix'''
        assert isinstance(taker_utxo_age, int)
        self.jmw.set_jm_data('taker_utxo_age', taker_utxo_age)

    @property
    def taker_utxo_amtpercent(self):
        return self.jmw.get_jm_data('taker_utxo_amtpercent',
                                    self.DEFAULT_TAKER_UTXO_AMTPERCENT)

    @taker_utxo_amtpercent.setter
    def taker_utxo_amtpercent(self, taker_utxo_amtpercent):
        assert isinstance(taker_utxo_amtpercent, int)
        self.jmw.set_jm_data('taker_utxo_amtpercent', taker_utxo_amtpercent)

    @property
    def max_cj_fee_abs(self):
        return self.jmw.get_jm_data('max_cj_fee_abs',
                                    self.DEFAULT_MAX_CJ_FEE_ABS)

    @max_cj_fee_abs.setter
    def max_cj_fee_abs(self, max_cj_fee_abs):
        assert isinstance(max_cj_fee_abs, int)
        self.jmw.set_jm_data('max_cj_fee_abs', max_cj_fee_abs)

    @property
    def max_cj_fee_rel(self):
        return self.jmw.get_jm_data('max_cj_fee_rel',
                                    self.DEFAULT_MAX_CJ_FEE_REL)

    @max_cj_fee_rel.setter
    def max_cj_fee_rel(self, max_cj_fee_rel):
        assert isinstance(max_cj_fee_rel, (float, int))
        self.jmw.set_jm_data('max_cj_fee_rel', float(max_cj_fee_rel))

    @property
    def max_cj_fee_confirmed(self):
        return self.jmw.get_jm_data('max_cj_fee_confirmed',
                                    self.DEFAULT_MAX_CJ_FEE_CONFIRMED)

    @max_cj_fee_confirmed.setter
    def max_cj_fee_confirmed(self, max_cj_fee_confirmed):
        assert isinstance(max_cj_fee_confirmed, bool)
        self.jmw.set_jm_data('max_cj_fee_confirmed', max_cj_fee_confirmed)

    # Other
    def set_msg_channels(self, msg_channels):
        self.jmw.set_jm_data('msg_channels', msg_channels)

    def get_msg_channels(self):
        msg_channels = self.jmw.get_jm_data('msg_channels')
        if msg_channels:
            return msg_channels

        if not constants.net.TESTNET:
            return copy.deepcopy(self.DEFAULT_MSG_CHANNELS)
        elif constants.net.NET_NAME == 'regtest':
            return copy.deepcopy(self.DEFAULT_MSG_CHANNELS_REGTEST)
        else:
            return copy.deepcopy(self.DEFAULT_MSG_CHANNELS_TESTNET)

    def set_schedule(self, schedule: str):
        self.jmw.set_jm_data('schedule', schedule)

    def get_schedule(self) -> str:
        return self.jmw.get_jm_data('schedule', '')

    @property
    def show_warn_electrumx(self):
        '''Check if warning about JM specific on electrum should be shown'''
        if not self.jmman.enabled:
            return True
        return self.jmw.get_jm_data('show_warn_electrumx', True)

    @show_warn_electrumx.setter
    def show_warn_electrumx(self, show):
        assert isinstance(show, bool)
        '''Set if warning about JM specific on electrum should be shown'''
        self.jmw.set_jm_data('show_warn_electrumx', show)

    def warn_electrumx_data(self, full_txt=False, help_txt=False):
        '''Str data for UI warning/preferences about JM specific on electrum'''
        if full_txt:
            return _('Privacy Warning: ElectrumX is a weak spot'
                     ' in JoinMarket privacy and knows all your'
                     ' wallet UTXO including JoinMarket mixed UTXOs.'
                     ' You should use trusted ElectrumX server'
                     ' for JoinMarket operation.')
        elif help_txt:
            return _('Show privacy warning about ElectrumX servers usage')
        else:
            return _('Privacy Warning ...')

    @property
    def subscribe_spent(self):
        '''Check if on server subscriptions for spent JM addresses done'''
        if not self.jmman.enabled:
            return self.DEFAULT_SUBSCRIBE_SPENT
        return self.jmw.get_jm_data('subscribe_spent',
                                    self.DEFAULT_SUBSCRIBE_SPENT)

    @subscribe_spent.setter
    def subscribe_spent(self, subscribe_spent):
        '''Set if on server subscriptions for spent JM addresses done'''
        if self.subscribe_spent == subscribe_spent:
            return
        self.jmw.set_jm_data('subscribe_spent', bool(subscribe_spent))
        jmw = self.jmw
        for addr in jmw.spent_addrs:
            if subscribe_spent:
                jmw.subscribe_spent_addr(addr)
            else:
                jmw.unsubscribe_spent_addr(addr)

    def subscribe_spent_data(self, full_txt=True):
        '''Str data for UI subscribe_spent preference'''
        if full_txt:
            return _('Subscribe to spent JM addresses'
                     ' on electrum servers')
        else:
            return _('Subscribe to spent JM addresses')

    def reset_to_defaults(self, conf_keys: list):
        for key in conf_keys:
            if key in self.jmw.jm_data.keys():
                self.jmw.jm_data.pop(key)
