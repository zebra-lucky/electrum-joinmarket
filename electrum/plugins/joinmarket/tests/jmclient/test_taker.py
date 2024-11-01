# -*- coding: utf-8 -*-

import os
import copy
import random
import pytest
import struct
from base64 import b64encode
from unittest_parametrize import parametrize, ParametrizedTestCase

from electrum.bitcoin import pubkey_to_address, address_to_script
from electrum.descriptor import PubkeyProvider, WPKHDescriptor
from electrum.transaction import (PartialTransaction, PartialTxInput,
                                  Transaction, PartialTxOutput, TxOutpoint)
from electrum.util import bfh

from electrum.plugins.joinmarket.jmbitcoin import privkey_to_pubkey
from electrum.plugins.joinmarket.jmbase import utxostr_to_utxo
from electrum.plugins.joinmarket import jmbitcoin as btc
from electrum.plugins.joinmarket.jmclient import Taker, NO_ROUNDING
from electrum.plugins.joinmarket.jmclient.taker_utils import (
    get_total_tumble_amount, restart_wait, unconf_update,
    tumbler_taker_finished_update, tumbler_filter_orders_callback)
from electrum.plugins.joinmarket.jm_util import add_txin_descriptor

from electrum.plugins.joinmarket.tests import JMTestCase, tx1_txid

from .commontest import default_max_cj_fee, DummyJMWallet
from .taker_test_data import (
    t_utxos_by_mixdepth, t_orderbook, t_maker_response, t_chosen_orders)


def convert_utxos(utxodict):
    return_dict = {}
    for uk, val in utxodict.items():
        return_dict[utxostr_to_utxo(uk)[1]] = val
    return return_dict


def dummy_order_chooser():
    return t_chosen_orders


def taker_finished(res, fromtx=False, waittime=0, txdetails=None):
    print("called taker finished callback")


def dummy_filter_orderbook(orders_fees, cjamount):
    print("calling dummy filter orderbook")
    return True


def get_taker(jmman, schedule=None, schedule_len=0, on_finished=None,
              filter_orders=None, custom_change=None):
    if not schedule:
        # note, for taker.initalize() this will result in junk
        schedule = [['a', 'b', 'c', 'd', 'e', 'f']]*schedule_len
    print("Using schedule: " + str(schedule))
    on_finished_callback = on_finished if on_finished else taker_finished
    filter_orders_callback = (filter_orders if filter_orders
                              else dummy_filter_orderbook)
    taker = Taker(jmman, schedule, default_max_cj_fee,
                  callbacks=[filter_orders_callback, None,
                             on_finished_callback],
                  custom_change_address=custom_change)
    return taker


on_sig_makers_txid = ('292107292b6e1aa530678b26668c1c9c'
                      'aaad50274bbd5c52af33531469a27cb1')
on_sig_makers_tx = (
    '020000000001011f892d01a66d02e96a6cf0a9bcddb7eb908365f8a6b17493b5319c8510'
    '285a800100000000fdffffff04204e0000000000001600140f25eef1e0cc272a81a5bf61'
    'd3a5850720df9a50204e00000000000016001443bc8c9250689d3b3f6f52646762e0aedf'
    '74bc7d204e000000000000160014bdc9958748e9abffe0e800779aa80aeff2dca29348bc'
    '000000000000160014ff22340e4f7d72be679db7a1f338e4df5b6e113002473044022064'
    '858c3642129c254c3301a22d7a1fec4e45e50bdb17a21610fb712410a72d53022020cc48'
    '1035fb3af66d8ae3cac510bc3663ea179e2ebd68141b8ab5ad9dc2dcc20121035243ad44'
    '884314c865f1cd192a70e8730b3c515ed7b4015624bf619796c6c8d3410f2b00'
)


on_sig_makers_data = {
    2: (
        '292107292b6e1aa530678b26668c1c9caaad50274bbd5c52af33531469a27cb1:1',
        'tb1qgw7geyjsdzwnk0m02fjxwchq4m0hf0raeen4zs',
        '90300392d8a1e4434ce041fcb427f527e2723acfa70a6196c0578e09412b2f08',
        '0207c70b1ac8e90137eb57d9a6cb97d22a14036f5dd83b1e630dd0cf0317427253',
    ),
    3: (
        '292107292b6e1aa530678b26668c1c9caaad50274bbd5c52af33531469a27cb1:2',
        'tb1qhhyetp6gax4llc8gqpme42q2aledeg5nfe6urf',
        '40d5694b2ec7e73d5ffd6489541f92172b63d66412c3f8380d33b56d440d730c',
        '0266e50c0b2ac2a53e2c2afff53eff400b3f4d38e8e2fd2d3aaa91e14574f9e496',
    ),
    4: (
        '292107292b6e1aa530678b26668c1c9caaad50274bbd5c52af33531469a27cb1:0',
        'tb1qpuj7au0qesnj4qd9hasa8fv9qusdlxjs4dzswx',
        '9fbfb107b9163809b380821b27af1f7c53a20b08d48583254a466757ac044070',
        '03c47fb63ce103be2cb8c10c2af5df30b64a3386922f8e65673e170227efa36058',
    ),
}


class DummyTx(object):

    def __init__(self, txid):
        self._txid = txid

    def txid(self):
        return self._txid


class TakerTestCase(JMTestCase, ParametrizedTestCase):

    async def test_filter_rejection(self):
        def filter_orders_reject(orders_feesl, cjamount):
            print("calling filter orders rejection")
            return False

        jmman = self.jmman
        taker = get_taker(jmman, filter_orders=filter_orders_reject)
        taker.schedule = [[0, 20000000, 3,
                           "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
                           0, NO_ROUNDING]]
        res = await taker.initialize(t_orderbook, [])
        assert not res[0]
        taker = get_taker(jmman, filter_orders=filter_orders_reject)
        taker.schedule = [[0, 0, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
                           0, NO_ROUNDING]]
        res = await taker.initialize(t_orderbook, [])
        assert not res[0]

    @parametrize(
        "mixdepth, cjamt, failquery, external, expected_success, amtpercent,"
        " age, mixdepth_extras",
        [
            (0, 1100000, False, False, True, 0, 0, {}),
            (0, 1100000, True, False, True, 0, 0, {}),
            (0, 1100000, False, True, True, 0, 0, {}),
            # this will fail to source from mixdepth 1 just because 2 < 50%
            # of 5.5:
            (1, 60000000, False, False, False, 50, 5, {}),
            # this must fail to source even though the size in mixdepth 0
            # is enough:
            (1, 5500000, False, False, False, 50, 5, {0: [6000000]}),
            # this should succeed in sourcing because even though there are
            # 9 utxos in mixdepth 0, one of them is more than 20%
            # (the original 0.02BTC):
            (0, 9000000, False, False, True, 20, 5, {0: [1000000]*8}),
            # this case must fail since the utxos are all at 20 confs and
            # too new:
            (0, 1100000, False, False, False, 20, 25, {}),
            # make the confs in the spending mixdepth insufficient, while those
            # in another mixdepth are OK; must fail:
            (0, 1100000, False, False, False, 20, 5, {"confchange": {0: 1}}),
            # add one timelock script in mixdepth 0, must succeed without
            # trying to use it as PoDLE:
            (0, 1100000, False, False, True, 20, 5,
             {"custom-script": {0: [440000]}}),
            # add one timelock script in mixdepth 0, must fail because only
            # the timelocked UTXO is big enough:
            (0, 11100000, False, False, False, 20, 5,
             {"custom-script": {0: [10000000]}}),
        ])
    async def test_make_commitment(self, mixdepth, cjamt, failquery, external,
                                   expected_success, amtpercent, age,
                                   mixdepth_extras):
        jmman = self.jmman
        jmconf = jmman.jmconf

        def clean_up():
            jmman.jmw = old_jmw
            jmconf.taker_utxo_age = old_taker_utxo_age
            jmconf.taker_utxo_amtpercent = old_taker_utxo_amtpercent

        # define the appropriate podle acceptance parameters in the
        # global config:
        old_jmw = jmman.jmw
        jmman.jmw = jmw = DummyJMWallet(jmman)
        jmw.jmconf = old_jmw.jmconf
        old_taker_utxo_age = jmconf.taker_utxo_age
        old_taker_utxo_amtpercent = jmconf.taker_utxo_amtpercent
        if expected_success:
            # set to defaults for mainnet
            newtua = 5
            newtuap = 20
        else:
            newtua = age
            newtuap = amtpercent
            jmconf.taker_utxo_age = newtua
            jmconf.taker_utxo_amtpercent = newtuap

        taker = get_taker(jmman, [(mixdepth, cjamt, 3,
                                   "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
                                   NO_ROUNDING)])

        # modify or add any extra utxos for this run:
        for k, v in mixdepth_extras.items():
            if k == "confchange":
                for k2, v2 in v.items():
                    # set the utxos in mixdepth k2 to have confs v2:
                    cdict = jmw.get_utxos_by_mixdepth()[k2]
                    jmw.set_confs({utxo: v2 for utxo in cdict.keys()})
            elif k == "custom-script":
                # note: this is inspired by fidelity bonds, and currently
                # uses scripts of that specific timelock type, but is really
                # only testing the general concept: that commitments must
                # not be made on any non-standard script type.
                for k2, v2 in v.items():
                    priv = os.urandom(32) + b"\x01"
                    tl = random.randrange(1430454400, 1430494400)
                    script_inner = jmw.mk_freeze_script(
                        btc.privkey_to_pubkey(priv).get_public_key_bytes(),
                        tl)
                    script_outer = jmw.redeem_script_to_p2wsh_script(
                        script_inner)
                    # FIXME taker.wallet_service.wallet._script_map[
                    #    script_outer] = ("nonstandard_path",)
                    jmw.add_extra_utxo(
                        os.urandom(32), 0, v2, k2, script=script_outer)
            else:
                for value in v:
                    jmw.add_extra_utxo(os.urandom(32), 0, value, k)

        taker.cjamount = cjamt
        taker.input_utxos = jmw.get_utxos_by_mixdepth()[mixdepth]
        taker.mixdepth = mixdepth
        if failquery:
            jmw.setQUSFail(True)
        comm, revelation, msg = await taker.make_commitment()
        if expected_success and failquery:
            # for manual tests, show the error message:
            print("Failure case due to QUS fail: ")
            print("Erromsg: ", msg)
            assert not comm
        elif expected_success:
            assert comm, "podle was not generated but should have been."
        else:
            # in these cases we have set the podle acceptance
            # parameters such that our in-mixdepth utxos are not good
            # enough.
            # for manual tests, show the errormsg:
            print("Failure case, errormsg: ", msg)
            assert not comm, "podle was generated but should not have been."
        clean_up()

    async def test_not_found_maker_utxos(self):
        jmman = self.jmman
        taker = get_taker(jmman, [(0, 20000000, 3,
                                   "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw", 0,
                                   NO_ROUNDING)])
        orderbook = copy.deepcopy(t_orderbook)
        res = await taker.initialize(orderbook, [])
        # total_cjfee unaffected, all same
        taker.orderbook = copy.deepcopy(t_chosen_orders)
        maker_response = copy.deepcopy(t_maker_response)
        res = await taker.receive_utxos(maker_response)
        assert not res[0]
        assert res[1] == ("Not enough counterparties responded to fill,"
                          " giving up")

    async def test_auth_pub_not_found(self):
        jmman = self.jmman

        def clean_up():
            jmman.jmw = old_jmw

        old_jmw = jmman.jmw
        jmman.jmw = jmw = DummyJMWallet(jmman)
        jmw.jmconf = old_jmw.jmconf

        taker = get_taker(jmman, [(0, 20000000, 3,
                                   "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw", 0,
                                   NO_ROUNDING)])
        orderbook = copy.deepcopy(t_orderbook)
        res = await taker.initialize(orderbook, [])
        # total_cjfee unaffected, all same
        taker.orderbook = copy.deepcopy(t_chosen_orders)
        maker_response = copy.deepcopy(t_maker_response)
        utxos = [utxostr_to_utxo(x)[1] for x in [
            "03243f4a659e278a1333f8308f6aaf32"
            "db4692ee7df0340202750fd6c09150f6:1",
            "498faa8b22534f3b443c6b0ce202f31e"
            "12f21668b4f0c7a005146808f250d4c3:0",
            "3f3ea820d706e08ad8dc1d2c392c98fa"
            "cb1b067ae4c671043ae9461057bd2a3c:1"]]
        fake_query_results = [{
            'value': 200000000,
            'address': "mrKTGvFfYUEqk52qPKUroumZJcpjHLQ6pn",
            'script': bfh('76a914767c956efe6092a775'
                          'fea39a06d1cac9aae956d788ac'),
            'utxo': utxos[i],
            'confirms': 20} for i in range(3)]
        jmw.insert_fake_query_results(fake_query_results)
        res = await taker.receive_utxos(maker_response)
        assert not res[0]
        assert res[1] == ("Not enough counterparties responded to fill,"
                          " giving up")
        jmw.insert_fake_query_results(None)
        clean_up()

    @parametrize(
        ("schedule, highfee, toomuchcoins, minmakers, notauthed,"
         " ignored, nocommit"),
        [
            ([(0, 200000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
               0, NO_ROUNDING)], False, False,
             2, False, None, None),
            ([(0, 0, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw", 0,
               NO_ROUNDING)], False, False,
             2, False, None, None),  # sweep
            ([(0, 0.2, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
               0, NO_ROUNDING)], False, False,
             2, False, None, None),  # tumble style non-int amounts
            # edge case triggers that don't fail
            ([(0, 0, 4, "mxeLuX8PP7qLkcM8uarHmdZyvP1b5e1Ynf",
               0, NO_ROUNDING)], False, False,
             2, False, None, None),  # sweep rounding error case 1
            ([(0, 0, 4, "mteaYsGsLCL9a4cftZFTpGEWXNwZyDt5KS",
               0, NO_ROUNDING)], False, False,
             2, False, None, None),  # sweep rounding error case 2
            ([(0, 1998560, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
               0, NO_ROUNDING)], False, False,
             2, False, None, None),  # trigger sub dust change for taker
            # edge case triggers that do fail
            ([(0, 1998570, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
               0, NO_ROUNDING)], False, False,
             2, False, None, None),  # trigger negative change
            ([(0, 1995998, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
               0, NO_ROUNDING)], False, False,
             2, False, None, None),  # trigger sub dust change for maker
            ([(0, 200000, 3, "INTERNAL", 0, NO_ROUNDING)], True, False,
             2, False, None, None),  # test high fee
            ([(0, 200000, 3, "INTERNAL", 0, NO_ROUNDING)], False, False,
             7, False, None, None),  # test not enough cp
            ([(0, 800000, 3, "INTERNAL", 0, NO_ROUNDING)], False, False,
             2, False, None, 30000),  # test failed commit
            ([(0, 200000, 3, "INTERNAL", 0, NO_ROUNDING)], False, False,
             2, True, None, None),  # test unauthed response
            ([(0, 50000000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
               0, NO_ROUNDING)], False, True,
             2, False, None, None),  # test too much coins
            ([(0, 0, 5, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
               0, NO_ROUNDING)], False, False,
             # test inadequate for sweep
             2, False, ["J659UPUSLLjHJpaB", "J65z23xdjxJjC7er", 0], None),
        ])
    async def test_taker_init(self, schedule, highfee, toomuchcoins, minmakers,
                              notauthed, ignored, nocommit):
        jmman = self.jmman
        jmconf = jmman.jmconf
        # these tests do not trigger utxo_retries
        oldtakerutxoretries = jmconf.taker_utxo_retries
        oldtakerutxoamtpercent = jmconf.taker_utxo_amtpercent
        oldtxfees = jmconf.tx_fees
        oldmaxsweepfeechange = jmconf.max_sweep_fee_change
        jmconf.taker_utxo_retries = 20

        def clean_up():
            jmman.jmw = old_jmw
            jmman.minimum_makers = oldminmakers
            jmconf.taker_utxo_retries = oldtakerutxoretries
            jmconf.taker_utxo_amtpercent = oldtakerutxoamtpercent
            jmconf.tx_fees = oldtxfees
            jmconf.max_sweep_fee_change = oldmaxsweepfeechange

        old_jmw = jmman.jmw
        jmman.jmw = jmw = DummyJMWallet(jmman)
        jmw.jmconf = old_jmw.jmconf
        oldminmakers = jmconf.minimum_makers
        jmconf.minimum_makers = minmakers
        jmconf.max_sweep_fee_change = 3.0
        taker = get_taker(jmman, schedule)
        orderbook = copy.deepcopy(t_orderbook)
        if highfee:
            for o in orderbook:
                # trigger high-fee warning; but reset in next step
                o['cjfee'] = '1.0'
        if ignored:
            taker.ignored_makers = ignored
        if nocommit:
            jmconf.taker_utxo_amtpercent = nocommit
        if schedule[0][1] == 0.2:
            # triggers calc-ing amount based on a fraction
            jmconf.mincjamount = 500000
            res = await taker.initialize(orderbook, [])
            assert res[0]
            assert res[1] == jmconf.mincjamount
            return clean_up()
        res = await taker.initialize(orderbook, [])
        if toomuchcoins or ignored:
            assert not res[0]
            return clean_up()
        if nocommit:
            print(str(res))
            assert res[0] == "commitment-failure"
            return clean_up()
        # total_cjfee unaffected, all same
        taker.orderbook = copy.deepcopy(t_chosen_orders)
        maker_response = copy.deepcopy(t_maker_response)
        if notauthed:
            # Doctor one of the maker response data fields
            maker_response["J659UPUSLLjHJpaB"][1] = "xx"  # the auth pub
        if schedule[0][1] == 199857000:
            # triggers negative change
            # ((10 + 31 * outs + 41 * ins)*4 + 109 * ins)/4. plug in 9 ins and
            #  8 outs gives tx size estimate = 872.25 bytes.
            # Times 30 ~= 26167.5.
            # makers offer 3000 txfee, so we pay 23168, plus maker fees =
            # 3*0.0002*200000000 roughly, gives required
            # selected = amt + 120k+23k,
            # hence the above = 2btc - 143k sats = 199857000 (tweaked because
            # of aggressive coin selection)
            # simulate the effect of a maker giving us a lot more utxos
            taker.utxos["dummy_for_negative_change"] = [
                (struct.pack(b"B", a)*32, a + 1) for a in range(7, 12)]
            with pytest.raises(ValueError):
                res = await taker.receive_utxos(maker_response)
            return clean_up()
        if schedule[0][1] == 199856001:
            # our own change is greater than zero but less than dust
            # use the same edge case as for negative change, don't add dummy
            # inputs (because we need tx creation to complete), but trigger
            # case by bumping dust threshold
            jmconf.BITCOIN_DUST_THRESHOLD = 14000
            res = await taker.receive_utxos(maker_response)
            # should have succeeded to build tx
            assert res[0]
            # change should be none
            assert not taker.my_change_addr
            return clean_up()
        if schedule[0][1] == 199599800:
            # need to force negative fees to make this feasible
            for k, v in taker.orderbook.items():
                v['cjfee'] = '-0.002'
            #            change_amount = (total_input - self.cjamount -
            #                     self.orderbook[nick]['txfee'] + real_cjfee)
            # suppose change amount is 1000 (sub dust), then solve for x;
            # given that real_cjfee = -0.002*x
            # change = 200000000 - x - 1000 - 0.002*x
            # x*1.002 = 1999999000; x = 199599800
            res = await taker.receive_utxos(maker_response)
            assert not res[0]
            assert res[1] == ("Not enough counterparties responded"
                              " to fill, giving up")
            return clean_up()
        if schedule[0][3] == "mxeLuX8PP7qLkcM8uarHmdZyvP1b5e1Ynf":
            # to trigger rounding error for sweep (change non-zero),
            # modify the total_input via the values in self.input_utxos;
            # the amount to trigger a small + satoshi change is found by
            # trial-error.
            # TODO note this test is not adequate, because the code is not;
            # the code does not *DO* anything if a condition is unexpected.
            taker.input_utxos = copy.deepcopy(t_utxos_by_mixdepth)[0]
            for k, v in taker.input_utxos.items():
                v["value"] = int(0.999805228 * v["value"])
            res = await taker.receive_utxos(maker_response)
            assert res[0]
            return clean_up()
        if schedule[0][3] == "mteaYsGsLCL9a4cftZFTpGEWXNwZyDt5KS":
            # as above, but small -ve change instead of +ve.
            taker.input_utxos = copy.deepcopy(t_utxos_by_mixdepth)[0]
            for k, v in taker.input_utxos.items():
                v["value"] = int(0.999805028 * v["value"])
            res = await taker.receive_utxos(maker_response)
            assert res[0]
            return clean_up()

        res = await taker.receive_utxos(maker_response)
        if minmakers != 2:
            assert not res[0]
            assert res[1] == ("Not enough counterparties responded to fill,"
                              " giving up")
            return clean_up()

        assert res[0]
        # re-calling will trigger "finished" code, since schedule
        # is "complete".
        res = await taker.initialize(orderbook, [])
        assert not res[0]

        # some exception cases: no coinjoin address, no change address:
        # donations not yet implemented:
        taker.my_cj_addr = None
        with pytest.raises(NotImplementedError):
            await taker.prepare_my_bitcoin_data()
        with pytest.raises(NotImplementedError):
            taker.coinjoin_address()
        jmw.inject_addr_get_failure = True
        taker.my_cj_addr = "dummy"
        taker.my_change_addr = None
        assert not await taker.prepare_my_bitcoin_data()
        # clean up
        return clean_up()

    async def test_custom_change(self):
        # create three random custom change addresses, one of each
        # known type in Joinmarket.
        jmman = self.jmman

        def clean_up():
            jmman.jmw = old_jmw

        old_jmw = jmman.jmw
        jmman.jmw = jmw = DummyJMWallet(jmman)
        jmw.jmconf = old_jmw.jmconf

        privs = [x*32 + b"\x01"
                 for x in [struct.pack(b'B', y) for y in range(1, 4)]]
        pubs = [privkey_to_pubkey(priv) for priv in privs]
        pubs_hex = [pub.get_public_key_hex() for pub in pubs]
        addrs = [pubkey_to_address(txin_type, pubk) for txin_type, pubk in
                 zip(['p2pkh', 'p2wpkh-p2sh', 'p2wpkh'], pubs_hex)]
        scripts = [address_to_script(addr) for addr in addrs]
        schedule = [(0, 200000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
                     0, NO_ROUNDING)]
        for script, addr in zip(scripts, addrs):
            taker = get_taker(jmman, schedule, custom_change=addr)
            orderbook = copy.deepcopy(t_orderbook)
            res = await taker.initialize(orderbook, [])
            taker.orderbook = copy.deepcopy(t_chosen_orders)
            maker_response = copy.deepcopy(t_maker_response)
            res = await taker.receive_utxos(maker_response)
            assert res[0]
            # ensure that the transaction created for signing has
            # the address we intended with the right amount:
            custom_change_found = False
            for out in taker.latest_tx.outputs():
                # input utxo is 200M; amount is 20M; as per logs:
                # totalin=200000000
                # my_txfee=13650 <- this estimate ignores address type
                # makers_txfee=3000
                # cjfee_total=12000 => changevalue=179974350
                # note that there is a small variation in the size of
                # the transaction (a few bytes) for the different scriptPubKey
                # type, but this is currently ignored in coinjoins by the
                # Taker (not true for direct send operations), hence we get
                # the same value for each different output type.
                if out.scriptpubkey == script and out.value == 2247380:
                    # must be only one
                    assert not custom_change_found
                    custom_change_found = True
            assert custom_change_found
        clean_up()

    @parametrize(
        "schedule_len",
        [
            (7,),
        ])
    async def test_unconfirm_confirm(self, schedule_len):
        """These functions are: do-nothing by default (unconfirm, for Taker),
        and merely update schedule index for confirm (useful for
        schedules/tumbles).
        This tests that the on_finished callback correctly reports the fromtx
        variable as "False" once the schedule is complete.
        The exception to the above is that the txd passed in must match
        self.latest_tx, so we use a dummy value here for that.
        """
        test_unconfirm_confirm = self.test_unconfirm_confirm_0.__wrapped__
        jmman = self.jmman

        test_unconfirm_confirm.txflag = True

        def finished_for_confirms(res, fromtx=False, waittime=0,
                                  txdetails=None):
            assert res  # confirmed should always send true
            test_unconfirm_confirm.txflag = fromtx

        taker = get_taker(jmman, schedule_len=schedule_len,
                          on_finished=finished_for_confirms)
        txid = "blah"
        taker.latest_tx = DummyTx(txid)
        fake_txd = DummyTx(txid)
        taker.unconfirm_callback(fake_txd, txid)
        for i in range(schedule_len-1):
            taker.schedule_index += 1
            taker.confirm_callback(fake_txd, txid, 1)
            assert test_unconfirm_confirm.txflag
        taker.schedule_index += 1
        taker.confirm_callback(fake_txd, txid, 1)
        assert not test_unconfirm_confirm.txflag

    @parametrize(
        "dummyaddr, schedule",
        [
            ("mrcNu71ztWjAQA6ww9kHiW3zBWSQidHXTQ",
             [(0, 20000000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw", 0)])
        ])
    async def test_on_sig(self, dummyaddr, schedule):
        jmman = self.jmman

        def clean_up():
            jmman.jmw = old_jmw

        old_jmw = jmman.jmw
        jmman.jmw = jmw = DummyJMWallet(jmman)
        jmw.jmconf = old_jmw.jmconf
        network = jmman.network
        network.connected = True
        network.add_fake_raw_tx(on_sig_makers_txid, on_sig_makers_tx)

        # plan: create a new transaction with known inputs and dummy outputs;
        # then, create a signature with various inputs, pass in in b64 to
        # on_sig.
        # in order for it to verify, the DummyBlockchainInterface will have to
        # return the right values in query_utxo_set
        utxos = [(struct.pack(b"B", x) * 32, 1) for x in range(2)]
        # create 2 privkey + utxos that are to be ours
        privs = [x*32 + b"\x01"
                 for x in [struct.pack(b'B', y) for y in range(1, 3)]]
        pubs = [privkey_to_pubkey(priv) for priv in privs]
        pubs_hex = [pub.get_public_key_hex() for pub in pubs]
        addrs = [pubkey_to_address('p2wpkh', pubk) for pubk in pubs_hex]
        scripts = [address_to_script(addr) for addr in addrs]
        fake_query_results = [{
            'value': 20000, 'utxo': utxos[x], 'address': addrs[x],
            'script': scripts[x], 'confirms': 20} for x in range(2)]

        # make a transaction with all the fake results above, and some outputs
        outs = [{'value': 100000000, 'address': dummyaddr},
                {'value': 899990000, 'address': dummyaddr}]
        prevouts = [TxOutpoint(txid=u[0], out_idx=u[1]) for u in utxos]
        inputs = [PartialTxInput(prevout=p) for p in prevouts]
        inputs2 = [PartialTxInput(prevout=p) for p in prevouts]
        outputs = [PartialTxOutput.from_address_and_value(
            address=o['address'], value=o['value']) for o in outs]

        for i in range(2, 5):
            # maker inputs
            maker_data = on_sig_makers_data[i]
            privs.append(bfh(maker_data[2]))
            p = TxOutpoint.from_str(maker_data[0])
            utxos.append((p.txid, p.out_idx))
            inputs.append(PartialTxInput(prevout=p))
            inputs2.append(PartialTxInput(prevout=p))
            prev_tx = Transaction(on_sig_makers_tx)
            o = prev_tx.outputs()[p.out_idx]
            addr = o.address
            script = address_to_script(addr)
            fake_query_results += [{
                'value': o.value,
                'utxo': (p.txid, p.out_idx),
                'address': addr,
                'script': script,
                'confirms': 20}
            ]
        jmw.insert_fake_query_results(fake_query_results)

        tx = PartialTransaction.from_io(inputs=inputs, outputs=outputs,
                                        version=1, locktime=0,
                                        BIP69_sort=False)
        # since tx will be updated as it is signed, unlike in real life
        # (where maker signing operation doesn't happen here), we'll create
        # a second copy without the signatures:
        tx2 = PartialTransaction.from_io(inputs=inputs2, outputs=outputs,
                                         version=1, locktime=0,
                                         BIP69_sort=False)
        maker_pubs = {}
        for i in range(2, 5):
            # maker inputs
            maker_data = on_sig_makers_data[i]
            maker_pubs[i] = bfh(maker_data[3])
            await tx.inputs()[i].add_info_from_network(network)
            await tx2.inputs()[i].add_info_from_network(network)
            add_txin_descriptor(
                self.jmman, tx2, i, on_sig_makers_tx, maker_data[3])

        # prepare the Taker with the right intermediate data
        taker = get_taker(jmman, schedule=schedule)
        taker.nonrespondants = ["cp1", "cp2", "cp3"]
        taker.latest_tx = tx
        # my inputs are the first 2 utxos
        taker.input_utxos = {utxos[0]: {
                                'address': addrs[0],
                                'script': scripts[0],
                                'value': 200000000},
                             utxos[1]: {
                                'address': addrs[1],
                                'script': scripts[1],
                                'value': 200000000}}
        taker.utxos = {None: utxos[:2], "cp1": [utxos[2]],
                       "cp2": [utxos[3]], "cp3": [utxos[4]]}
        for i in range(2):
            # placeholders required for my inputs
            taker.latest_tx.inputs()[i].script_sig = bfh('deadbeef')
            tx2.inputs()[i].script_sig = bfh('deadbeef')
        # to prepare for my signing, need to mark cjaddr:
        taker.my_cj_addr = dummyaddr
        # make signatures for the last 3 fake utxos, considered as "not ours":
        sig = tx2.sign_txin(2, privs[2])
        assert sig, "Failed to sign"
        tx2.add_signature_to_txin(
            txin_idx=2, signing_pubkey=maker_pubs[2], sig=sig)
        pubk_prov = PubkeyProvider(None, maker_pubs[2].hex(), None)
        tx2.inputs()[2].script_descriptor = WPKHDescriptor(pubk_prov)
        tx2.inputs()[2].finalize()
        sig3 = b64encode(tx2.inputs()[2].witness[1:])
        await taker.on_sig("cp1", sig3)
        # try sending the same sig again; should be ignored
        await taker.on_sig("cp1", sig3)
        sig = tx2.sign_txin(3, privs[3])
        tx2.add_signature_to_txin(
            txin_idx=3, signing_pubkey=maker_pubs[3], sig=sig)
        pubk_prov = PubkeyProvider(None, maker_pubs[3].hex(), None)
        tx2.inputs()[3].script_descriptor = WPKHDescriptor(pubk_prov)
        tx2.inputs()[3].finalize()
        assert sig, "Failed to sign"
        sig4 = b64encode(tx2.inputs()[3].witness[1:])
        # try sending junk instead of cp2's correct sig
        assert not await taker.on_sig(
            "cp2", str("junk")), "incorrectly accepted junk signature"
        await taker.on_sig("cp2", sig4)
        sig = tx2.sign_txin(4, privs[4])
        assert sig, "Failed to sign"
        tx2.add_signature_to_txin(
            txin_idx=4, signing_pubkey=maker_pubs[4], sig=sig)
        pubk_prov = PubkeyProvider(None, maker_pubs[4].hex(), None)
        tx2.inputs()[4].script_descriptor = WPKHDescriptor(pubk_prov)
        tx2.inputs()[4].finalize()
        # Before completing with the final signature, which will trigger our
        # own signing, try with an injected failure of query utxo set, which
        # should prevent this signature being accepted.
        jmw.setQUSFail(True)
        sig5 = b64encode(tx2.inputs()[4].witness[1:])
        assert not await taker.on_sig("cp3", sig5), "incorrectly accepted sig5"
        # allow it to succeed, and try again
        jmw.setQUSFail(False)
        # this should succeed and trigger the we-sign code
        await taker.on_sig("cp3", sig5)
        clean_up()

    @parametrize(
        "schedule",
        [
            ([0, 20000000, 3, "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw"], ),
        ])
    async def test_auth_counterparty(self, schedule):
        jmman = self.jmman
        taker = get_taker(jmman, schedule=schedule)
        first_maker_response = t_maker_response["J659UPUSLLjHJpaB"]
        (
            utxo, auth_pub, cjaddr, changeaddr, sig, maker_pub
        ) = first_maker_response
        auth_pub_tweaked = auth_pub[:8] + auth_pub[6:8] + auth_pub[10:]
        sig_tweaked = sig[:8] + sig[6:8] + sig[10:]
        assert taker.auth_counterparty(sig, auth_pub, maker_pub)
        assert not taker.auth_counterparty(sig, auth_pub_tweaked, maker_pub)
        assert not taker.auth_counterparty(sig_tweaked, auth_pub, maker_pub)


class TakerUtilsTestCase(JMTestCase):

    async def test_get_total_tumble_amount(self):
        schedule = [[4, 0, 2, 'INTERNAL', 0.5, 16, 0],
                    [0, 0, 2, 'INTERNAL', 0.5, 16, 0],
                    [1, 0.48524737930877715, 2, 'INTERNAL', 0.5, 16, 0],
                    [1, 0, 2, 'INTERNAL', 0.5, 16, 0],
                    [2, 0.06803272390931159, 2, 'INTERNAL', 0.5, 16, 0],
                    [2, 0, 2, 'INTERNAL', 0.5, 16, 0]]

        mixdepth_balance_dict = {
            4: 1000000,
            0: 2000000,
            1: 3000000,
            2: 2000000,
        }

        assert get_total_tumble_amount(
            mixdepth_balance_dict, schedule) == 8000000

    async def test_restart_wait(self):
        restart_wait(self.jmman,  tx1_txid)

    async def test_unconf_update(self):

        def filter_orders(orders_feesl, cjamount):
            return True

        jmman = self.jmman
        taker = get_taker(jmman, filter_orders=filter_orders)
        taker.schedule = [[0, 20000000, 3,
                           "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
                           0, NO_ROUNDING]]
        orderbook = copy.deepcopy(t_orderbook)
        await taker.initialize(orderbook, [])
        taker.orderbook = copy.deepcopy(t_chosen_orders)
        unconf_update(taker, jmman.tumble_log, addtolog=True)

    async def test_tumbler_taker_finished_update(self):

        def filter_orders(orders_feesl, cjamount):
            return True

        jmman = self.jmman
        taker = get_taker(jmman, filter_orders=filter_orders)
        taker.schedule = [[0, 20000000, 3,
                           "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
                           0, NO_ROUNDING]]
        orderbook = copy.deepcopy(t_orderbook)
        await taker.initialize(orderbook, [])
        taker.orderbook = copy.deepcopy(t_chosen_orders)
        tumbler_taker_finished_update(
            taker, jmman.tumble_log, options=True, res=False, fromtx=False)

    async def test_tumbler_filter_orders_callback(self):

        def filter_orders(orders_feesl, cjamount):
            return True

        jmman = self.jmman
        taker = get_taker(jmman, filter_orders=filter_orders)
        taker.schedule = [[0, 20000000, 3,
                           "mnsquzxrHXpFsZeL42qwbKdCP2y1esN3qw",
                           0, NO_ROUNDING]]
        orderbook = copy.deepcopy(t_orderbook)
        await taker.initialize(orderbook, [])
        taker.orderbook = copy.deepcopy(t_chosen_orders)
        orders_fees = (None, 1000)
        tumbler_filter_orders_callback(
            self.jmman, orders_fees, 100000, taker)
