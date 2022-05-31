# -*- coding: utf-8 -*-

from electrum import constants

from electrum.plugins.joinmarket.tests import JMTestCase


class JMConfTestCase(JMTestCase):

    async def test_blockchain_network(self):
        jmconf = self.jmconf
        constants.BitcoinMainnet.set_as_network()
        assert jmconf.blockchain_network == 'mainnet'
        constants.BitcoinTestnet.set_as_network()
        assert jmconf.blockchain_network == 'testnet'

    async def test_mixdepth(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.mixdepth == 4
        assert jmw.get_jm_data('mixdepth') is None
        jmconf.mixdepth = 6
        assert jmconf.mixdepth == 6
        assert jmw.get_jm_data('mixdepth') == 6
        jmconf.mixdepth = 3
        assert jmconf.mixdepth == 3
        assert jmw.get_jm_data('mixdepth') == 3

    async def test_max_mixdepth(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.max_mixdepth == 4
        assert jmw.get_jm_data('max_mixdepth') is None
        jmconf.max_mixdepth = 6
        assert jmconf.max_mixdepth == 6
        assert jmw.get_jm_data('max_mixdepth') == 6
        jmconf.max_mixdepth = 3
        assert jmconf.max_mixdepth == 6  # uses highest possible prev value
        assert jmw.get_jm_data('max_mixdepth') == 6

    async def test_mincjamount(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.mincjamount == 100000
        assert jmw.get_jm_data('mincjamount') is None
        jmconf.mincjamount = 40000
        assert jmconf.mincjamount == 40000
        assert jmw.get_jm_data('mincjamount') is None  # not saved to jm_data
        jmconf.reset_mincjamount()
        jmconf.mincjamount = 100000

    async def test_maker_timeout_sec(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.maker_timeout_sec == 60
        assert jmw.get_jm_data('maker_timeout_sec') is None
        jmconf.maker_timeout_sec = 90
        assert jmconf.maker_timeout_sec == 90
        assert jmw.get_jm_data('maker_timeout_sec') == 90

    async def test_unconfirm_timeout_sec(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.unconfirm_timeout_sec == 180
        assert jmw.get_jm_data('unconfirm_timeout_sec') is None
        jmconf.unconfirm_timeout_sec = 360
        assert jmconf.unconfirm_timeout_sec == 360
        assert jmw.get_jm_data('unconfirm_timeout_sec') == 360

    async def test_confirm_timeout_hours(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.confirm_timeout_hours == 6
        assert jmw.get_jm_data('confirm_timeout_hours') is None
        jmconf.confirm_timeout_hours = 8
        assert jmconf.confirm_timeout_hours == 8
        assert jmw.get_jm_data('confirm_timeout_hours') == 8

    async def test_merge_algorithm(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.merge_algorithm == 'default'
        assert jmw.get_jm_data('merge_algorithm') is None
        jmconf.merge_algorithm = 'unknown'  # FIXME possible limit string set
        assert jmconf.merge_algorithm == 'unknown'
        assert jmw.get_jm_data('merge_algorithm') == 'unknown'

    async def test_gaplimit(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.gaplimit == 6
        assert jmw.get_jm_data('gaplimit') is None
        jmconf.gaplimit = 50
        assert jmconf.gaplimit == 50
        assert jmw.get_jm_data('gaplimit') == 50

    async def test_tx_fees(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.tx_fees == 100000
        assert jmw.get_jm_data('tx_fees') == 100000

        jmconf.tx_fees = 1
        assert jmconf.tx_fees == 1
        assert jmw.get_jm_data('tx_fees') == 1

        jmconf.tx_fees = 2
        assert jmconf.tx_fees == 2

        jmconf.tx_fees = 3
        assert jmconf.tx_fees == 5

        jmconf.tx_fees = 5
        assert jmconf.tx_fees == 5

        jmconf.tx_fees = 6
        assert jmconf.tx_fees == 10

        jmconf.tx_fees = 10
        assert jmconf.tx_fees == 10

        jmconf.tx_fees = 11
        assert jmconf.tx_fees == 25

        jmconf.tx_fees = 25
        assert jmconf.tx_fees == 25

        jmconf.tx_fees = 50
        assert jmconf.tx_fees == 25

        jmconf.tx_fees = 1000
        assert jmconf.tx_fees == 25

        jmconf.tx_fees = 1001
        assert jmconf.tx_fees == 1001

    async def test_tx_fees_factor(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.tx_fees_factor == 0
        assert jmw.get_jm_data('tx_fees_factor') == 0
        jmconf.tx_fees_factor = 0.3
        assert jmconf.tx_fees_factor == 0.3
        assert jmw.get_jm_data('tx_fees_factor') == 0.3
        jmconf.tx_fees_factor = 0
        assert isinstance(jmconf.tx_fees_factor, float)
        assert jmconf.tx_fees_factor == 0

    async def test_absurd_fee_per_kb(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.absurd_fee_per_kb == 350000
        assert jmw.get_jm_data('absurd_fee_per_kb') is None
        jmconf.absurd_fee_per_kb = 100000
        assert jmconf.absurd_fee_per_kb == 100000
        assert jmw.get_jm_data('absurd_fee_per_kb') == 100000

    async def test_max_sweep_fee_change(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.max_sweep_fee_change == 0.8
        assert jmw.get_jm_data('max_sweep_fee_change') is None
        jmconf.max_sweep_fee_change = 0.7
        assert jmconf.max_sweep_fee_change == 0.7
        assert jmw.get_jm_data('max_sweep_fee_change') == 0.7
        jmconf.max_sweep_fee_change = 0
        assert isinstance(jmconf.max_sweep_fee_change, float)
        assert jmconf.max_sweep_fee_change == 0

    async def test_tx_broadcast(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.tx_broadcast == 'random-peer'
        assert jmw.get_jm_data('tx_broadcast') is None
        jmconf.tx_broadcast = 'unknown'  # FIXME possible limit string set
        assert jmconf.tx_broadcast == 'unknown'
        assert jmw.get_jm_data('tx_broadcast') == 'unknown'

    async def test_minimum_makers(self):
        jmw = self.jmw
        jmconf = self.jmconf
        jmw.pop_jm_data('minimum_makers')
        assert jmconf.minimum_makers == 4
        assert jmw.get_jm_data('minimum_makers') is None
        jmconf.minimum_makers = 1
        assert jmconf.minimum_makers == 1
        assert jmw.get_jm_data('minimum_makers') == 1

    async def test_max_sats_freeze_reuse(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.max_sats_freeze_reuse == -1
        assert jmw.get_jm_data('max_sats_freeze_reuse') is None
        jmconf.max_sats_freeze_reuse = 500000
        assert jmconf.max_sats_freeze_reuse == 500000
        assert jmw.get_jm_data('max_sats_freeze_reuse') == 500000

    async def test_interest_rate(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.interest_rate == 0.015
        assert jmw.get_jm_data('interest_rate') is None
        jmconf.interest_rate = 0.02
        assert jmconf.interest_rate == 0.02
        assert jmw.get_jm_data('interest_rate') == 0.02
        jmconf.interest_rate = 0
        assert isinstance(jmconf.interest_rate, float)
        assert jmconf.interest_rate == 0

    async def test_bondless_makers_allowance(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.bondless_makers_allowance == 0.125
        assert jmw.get_jm_data('bondless_makers_allowance') is None
        jmconf.bondless_makers_allowance = 0.2
        assert jmconf.bondless_makers_allowance == 0.2
        assert jmw.get_jm_data('bondless_makers_allowance') == 0.2
        jmconf.bondless_makers_allowance = 0
        assert isinstance(jmconf.bondless_makers_allowance, float)
        assert jmconf.bondless_makers_allowance == 0

    async def test_bond_value_exponent(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.bond_value_exponent == 1.3
        assert jmw.get_jm_data('bond_value_exponent') is None
        jmconf.bond_value_exponent = 1.33
        assert jmconf.bond_value_exponent == 1.33
        assert jmw.get_jm_data('bond_value_exponent') == 1.33
        jmconf.bond_value_exponent = 1
        assert isinstance(jmconf.bond_value_exponent, float)
        assert jmconf.bond_value_exponent == 1

    async def test_taker_utxo_retries(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.taker_utxo_retries == 3
        assert jmw.get_jm_data('taker_utxo_retries') is None
        jmconf.taker_utxo_retries = 5
        assert jmconf.taker_utxo_retries == 5
        assert jmw.get_jm_data('taker_utxo_retries') == 5

    async def test_taker_utxo_age(self):
        jmw = self.jmw
        jmconf = self.jmconf
        jmw.pop_jm_data('taker_utxo_age')
        assert jmconf.taker_utxo_age == 5
        assert jmw.get_jm_data('taker_utxo_age') is None
        jmconf.taker_utxo_age = 1
        assert jmconf.taker_utxo_age == 1
        assert jmw.get_jm_data('taker_utxo_age') == 1

    async def test_taker_utxo_amtpercent(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.taker_utxo_amtpercent == 20
        assert jmw.get_jm_data('taker_utxo_amtpercent') is None
        jmconf.taker_utxo_amtpercent = 25
        assert jmconf.taker_utxo_amtpercent == 25
        assert jmw.get_jm_data('taker_utxo_amtpercent') == 25

    async def test_max_cj_fee_abs(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.max_cj_fee_abs == 4000
        assert jmw.get_jm_data('max_cj_fee_abs') is None
        jmconf.max_cj_fee_abs = 10000
        assert jmconf.max_cj_fee_abs == 10000
        assert jmw.get_jm_data('max_cj_fee_abs') == 10000

    async def test_max_cj_fee_rel(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.max_cj_fee_rel == 0.004
        assert jmw.get_jm_data('max_cj_fee_rel') is None
        jmconf.max_cj_fee_rel = 0.002
        assert jmconf.max_cj_fee_rel == 0.002
        assert jmw.get_jm_data('max_cj_fee_rel') == 0.002
        jmconf.max_cj_fee_rel = 0
        assert isinstance(jmconf.max_cj_fee_rel, float)
        assert jmconf.max_cj_fee_rel == 0

    async def test_max_cj_fee_confirmed(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.max_cj_fee_confirmed is False
        assert isinstance(jmconf.max_cj_fee_confirmed, bool)
        assert jmw.get_jm_data('max_cj_fee_confirmed') is None
        jmconf.max_cj_fee_confirmed = True
        assert jmconf.max_cj_fee_confirmed is True
        assert isinstance(jmconf.max_cj_fee_confirmed, bool)
        assert jmw.get_jm_data('max_cj_fee_confirmed') is True

    async def test_get_msg_channels(self):
        jmw = self.jmw
        jmconf = self.jmconf
        def_msg_channels = jmconf.DEFAULT_MSG_CHANNELS_TESTNET
        assert jmw.get_jm_data('msg_channels') is None
        msg_channels = jmconf.get_msg_channels()
        assert msg_channels == def_msg_channels
        assert id(msg_channels) != id(def_msg_channels)
        msg_channels['irc1']['port'] = 12345
        jmw.set_jm_data('msg_channels', msg_channels)
        changed_msg_channels = jmconf.get_msg_channels()
        assert changed_msg_channels != def_msg_channels
        assert changed_msg_channels == msg_channels
        assert id(changed_msg_channels) != id(msg_channels)

    async def test_set_msg_channels(self):
        jmw = self.jmw
        jmconf = self.jmconf
        def_msg_channels = jmconf.DEFAULT_MSG_CHANNELS_TESTNET
        assert jmw.get_jm_data('msg_channels') is None
        msg_channels = jmconf.get_msg_channels()
        assert msg_channels == def_msg_channels
        assert id(msg_channels) != id(def_msg_channels)
        msg_channels['irc1']['port'] = 12345
        assert msg_channels != def_msg_channels
        jmconf.set_msg_channels(msg_channels)
        changed_msg_channels = jmconf.get_msg_channels()
        assert changed_msg_channels != def_msg_channels
        assert changed_msg_channels == msg_channels
        assert id(changed_msg_channels) != id(msg_channels)
        assert jmw.get_jm_data('msg_channels') == msg_channels
        assert id(jmw.get_jm_data('msg_channels')) != id(msg_channels)

    async def test_get_schedule(self):
        jmw = self.jmw
        jmconf = self.jmconf
        sch_str = 'some schedule;'
        assert jmw.get_jm_data('schedule') is None
        assert jmconf.get_schedule() == ''
        jmw.set_jm_data('schedule', sch_str)
        assert jmconf.get_schedule() == sch_str

    async def test_set_schedule(self):
        jmw = self.jmw
        jmconf = self.jmconf
        sch_str = 'some schedule;'
        assert jmw.get_jm_data('schedule') is None
        assert jmconf.get_schedule() == ''
        jmconf.set_schedule(sch_str)
        assert jmconf.get_schedule() == sch_str
        assert jmw.get_jm_data('schedule') == sch_str

    async def test_show_warn_electrumx(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.show_warn_electrumx is True
        assert jmw.get_jm_data('show_warn_electrumx') is None
        jmconf.show_warn_electrumx = False
        assert jmconf.show_warn_electrumx is False
        assert jmw.get_jm_data('show_warn_electrumx') is False

    async def test_warn_electrumx_data(self):
        jmconf = self.jmconf
        assert jmconf.warn_electrumx_data() == 'Privacy Warning ...'
        assert jmconf.warn_electrumx_data(help_txt=True).startswith(
            'Show privacy warning about ElectrumX'
        )
        assert jmconf.warn_electrumx_data(full_txt=True).startswith(
            'Privacy Warning: ElectrumX is a weak spot'
        )

    async def test_subscribe_spent(self):
        jmw = self.jmw
        jmconf = self.jmconf
        assert jmconf.subscribe_spent is False
        assert jmw.get_jm_data('subscribe_spent') is None
        jmconf.subscribe_spent = True
        assert jmconf.subscribe_spent is True
        assert jmw.get_jm_data('subscribe_spent') is True
        jmconf.subscribe_spent = False
        assert jmconf.subscribe_spent is False
        assert jmw.get_jm_data('subscribe_spent') is False

    async def test_subscribe_spent_data(self):
        jmconf = self.jmconf
        assert jmconf.subscribe_spent_data(full_txt=False) == (
            'Subscribe to spent JM addresses'
        )
        assert jmconf.subscribe_spent_data().startswith(
            'Subscribe to spent JM addresses on'
        )
