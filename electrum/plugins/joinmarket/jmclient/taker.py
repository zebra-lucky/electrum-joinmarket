# -*- coding: utf-8 -*-

import asyncio
import base64
import pprint
import random
from typing import Any, NamedTuple, Optional

from electrum.bitcoin import is_address
from electrum.util import bfh
from electrum.wallet import get_locktime_for_new_transaction

from .. import jmbitcoin as btc
from ..jmbase import commands, bintohex, hexbin, async_hexbin
from ..jmclient.cryptoengine import EngineError
from ..jmclient.support import (calc_cj_fee, choose_orders,
                                fidelity_bond_weighted_order_choose,
                                choose_sweep_orders)
from ..jmclient.podle import generate_podle, get_podle_commitments
from ..jmclient.fidelity_bond import FidelityBondProof
from .output import generate_podle_error_string
from .schedule import NO_ROUNDING
from ..jm_util import verify_txin_sig, add_txin_sig, UnknownAddressForLabel


class IoauthInputVerificationError(Exception):
    def __init__(self, messages):
        self.messages = messages
        super().__init__(messages)


class Taker(object):
    class _MakerTxData(NamedTuple):
        nick: Any
        utxo_data: Any
        total_input: Any
        change_amount: Any
        real_cjfee: Any
        utxo_list: Any = None
        cj_addr: Optional[str] = None
        change_addr: Optional[str] = None

    def __init__(self,
                 jmman,
                 schedule,
                 max_cj_fee,
                 order_chooser=fidelity_bond_weighted_order_choose,
                 callbacks=None,
                 tdestaddrs=None,
                 custom_change_address=None,
                 change_label=None,
                 ignored_makers=None):
        """`schedule`` must be a list of tuples: (see
        sample_schedule_for_testnet for explanation of syntax, also schedule.py
        module in this directory), which will be a sequence of joins to do.
        `max_cj_fee` must be a tuple of form: (float, int or float) where
        the first is the maximum relative fee as a decimal and the second
        is the maximum absolute fee in satoshis.
        Callbacks:
        External callers set the 3 callbacks for filtering orders,
        sending info messages to client, and action on completion.
        "None" is allowable for taker_info_callback, defaults to log msg.
        Callback function definitions:
        =====================
        filter_orders_callback
        =====================
        args:
        1. orders_fees - a list of two items 1. orders dict 2 total cjfee
        2. cjamount - coinjoin amount in satoshis
        returns:
        False - offers rejected OR
        True - offers accepted OR
        'retry' - offers not accepted but try again
        =======================
        on_finished_callback
        =======================
        args:
        1. res - True means tx successful, False means tx unsucessful
        2. fromtx - True means not the final transaction, False means final
         (end of schedule), 'unconfirmed' means tx seen on the network only.
        3. waittime - passed in minutes, time to wait after confirmation before
         continuing to next tx (thus, only used if fromtx is True).
        4. txdetails - a tuple (txd, txid) - only to be used when fromtx
         is 'unconfirmed', used for monitoring.
        returns:
        None
        ========================
        taker_info_callback
        ========================
        args:
        1. type - one of 'ABORT' or 'INFO', the former signals the client that
         processing of this transaction is aborted, the latter is only
         an update.
        2. message - an information message.
        returns:
        None
        """
        self.aborted = False
        self.jmman = jmman
        self.logger = jmman.logger
        self.schedule = schedule

        self.order_chooser = order_chooser
        self.max_cj_fee = max_cj_fee
        self.custom_change_address = custom_change_address
        self.change_label = change_label

        # List (which persists between transactions) of makers
        # who have not responded or behaved maliciously at any
        # stage of the protocol.
        self.ignored_makers = [] if not ignored_makers else ignored_makers

        # Used in attempts to complete with subset after second round failure:
        self.honest_makers = []
        # Toggle: if set, only honest makers will be used from orderbook
        self.honest_only = False

        # Temporary (per transaction) list of makers that keeps track of
        # which have responded, both in Stage 1 and Stage 2. Before each
        # stage, the list is set to the full set of expected responders,
        # and entries are removed when honest responses are received;
        # emptiness of the list can be used to trigger completion of
        # processing.
        self.nonrespondants = []

        self.waiting_for_conf = False
        self.txid = None
        self.schedule_index = -1
        self.utxos = {}
        self.maker_utxo_data = {}
        self.tdestaddrs = [] if not tdestaddrs else tdestaddrs
        self.filter_orders_callback = callbacks[0]
        self.taker_info_callback = callbacks[1]
        if not self.taker_info_callback:
            self.taker_info_callback = self.default_taker_info_callback
        self.on_finished_callback = callbacks[2]

    def default_taker_info_callback(self, infotype, msg):
        self.logger.info(infotype + ":" + msg)

    def add_ignored_makers(self, makers):
        """Makers should be added to this list when they have refused to
        complete the protocol honestly, and should remain in this set
        for the duration of the Taker run (so, the whole schedule).
        """
        self.ignored_makers.extend(makers)
        self.ignored_makers = list(set(self.ignored_makers))

    def add_honest_makers(self, makers):
        """A maker who has shown willigness to complete the protocol
        by returning a valid signature for a coinjoin can be added to
        this list, the taker can optionally choose to only source
        offers from thus-defined "honest" makers.
        """
        self.honest_makers.extend(makers)
        self.honest_makers = list(set(self.honest_makers))

    def set_honest_only(self, truefalse):
        """Toggle; if set, offers will only be accepted
        from makers in the self.honest_makers list.
        This should not be called unless we already have
        a list of such honest makers (see add_honest_makers()).
        """
        if truefalse:
            if not len(self.honest_makers):
                self.logger.debug("Attempt to set honest-only without "
                                  "any honest makers; ignored.")
                return
        self.honest_only = truefalse

    async def initialize(self, orderbook, fidelity_bonds_info):
        """Once the daemon is active and has returned the current orderbook,
        select offers, re-initialize variables and prepare a commitment,
        then send it to the protocol to fill offers.
        """
        if self.aborted:
            return (False,)
        self.taker_info_callback("INFO", "Received offers from joinmarket pit")
        # choose the next item in the schedule
        jmman = self.jmman
        self.schedule_index += 1
        if self.schedule_index == len(self.schedule):
            self.taker_info_callback("INFO",
                                     "Finished all scheduled transactions")
            self.on_finished_callback(True)
            return (False,)
        else:
            # read the settings from the schedule entry
            si = self.schedule[self.schedule_index]
            self.mixdepth = si[0]
            self.cjamount = si[1]
            rounding = si[5]
            # non-integer coinjoin amounts are treated as fractions
            # this is currently used by the tumbler algo
            if isinstance(self.cjamount, float):
                # the mixdepth balance is fixed at the *start* of each new
                # mixdepth in tumble schedules:
                if self.schedule_index == 0 or si[0] != self.schedule[
                    self.schedule_index - 1
                ]:
                    self.mixdepthbal = jmman.jmw.get_balance_by_mixdepth(
                        )[self.mixdepth]
                # reset to satoshis
                self.cjamount = int(self.cjamount * self.mixdepthbal)
                if rounding != NO_ROUNDING:
                    self.cjamount = round_to_significant_figures(
                        self.cjamount, rounding)
                if self.cjamount < jmman.jmconf.mincjamount:
                    self.logger.info(
                        "Coinjoin amount too low, bringing up to: " +
                        btc.amount_to_str(jmman.jmconf.mincjamount))
                    self.cjamount = jmman.jmconf.mincjamount
            self.n_counterparties = si[2]
            self.my_cj_addr = si[3]

            # if destination is flagged "INTERNAL", choose a destination
            # from the next mixdepth modulo the maxmixdepth
            if self.my_cj_addr == "INTERNAL":
                next_mixdepth = ((self.mixdepth + 1) %
                                 (jmman.jmconf.mixdepth + 1))
                self.logger.info("Choosing a destination from mixdepth: " +
                                 str(next_mixdepth))
                self.my_cj_addr = jmman.jmw.get_internal_addr(next_mixdepth)
                self.logger.info("Chose destination address: " +
                                 self.my_cj_addr)
            self.outputs = []
            self.cjfee_total = 0
            self.maker_txfee_contributions = 0
            self.latest_tx = None
            self.txid = None

        fidelity_bond_values = await calculate_fidelity_bond_values(
            fidelity_bonds_info, jmman)
        for offer in orderbook:
            # having no fidelity bond is like having a zero value fidelity bond
            offer["fidelity_bond_value"] = fidelity_bond_values.get(
                offer["counterparty"], 0)

        sweep = True if self.cjamount == 0 else False
        if not await self.filter_orderbook(orderbook, sweep):
            return (False,)
        # choose coins to spend
        self.taker_info_callback("INFO", "Preparing bitcoin data..")
        if not await self.prepare_my_bitcoin_data():
            return (False,)
        # Prepare a commitment
        commitment, revelation, errmsg = await self.make_commitment()
        if not commitment:
            utxo_pairs, to, ts = revelation
            if len(to) == 0:
                # If any utxos are too new, then we can continue retrying
                # until they get old enough; otherwise, we have to abort
                # (TODO, it's possible for user to dynamically add more coins,
                # consider if this option means we should stay alive).
                self.taker_info_callback("ABORT", errmsg)
                return ("commitment-failure",)
            else:
                self.taker_info_callback("INFO", errmsg)
                return (False,)
        else:
            self.taker_info_callback("INFO", errmsg)

        # Initialization has been successful. We must set the nonrespondants
        # now to keep track of what changed when we receive the utxo data
        self.nonrespondants = list(self.orderbook.keys())
        return (True, self.cjamount, commitment, revelation, self.orderbook)

    async def filter_orderbook(self, orderbook, sweep=False):
        # If honesty filter is set, we immediately filter to only the
        # prescribed honest makers before continuing. In this case,
        # the number of counterparties should already match, and this
        # has to be set by the script instantiating the Taker.
        # Note: If one or more of the honest makers has dropped out in the
        # meantime, we will just have insufficient offers and it will fail
        # in the usual way for insufficient liquidity.
        jmman = self.jmman
        if self.honest_only:
            orderbook = [o for o in orderbook
                         if o['counterparty'] in self.honest_makers]
        if sweep:
            self.orderbook = orderbook  # offers choosing deferred to next step
        else:
            txin_type = jmman.wallet.get_txin_type()
            if txin_type == "p2pkh":
                allowed_types = ["reloffer", "absoffer"]
            elif txin_type == "p2sh-p2wpkh":
                allowed_types = ["swreloffer", "swabsoffer"]
            elif txin_type == "p2wpkh":
                allowed_types = ["sw0reloffer", "sw0absoffer"]
            else:
                self.logger.error("Unrecognized wallet type,"
                                  " taker cannot continue.")
                return False
            self.orderbook, self.total_cj_fee = choose_orders(
                jmman, orderbook, self.cjamount, self.n_counterparties,
                self.order_chooser, self.ignored_makers,
                allowed_types=allowed_types, max_cj_fee=self.max_cj_fee)
            if self.orderbook is None:
                # Failure to get an orderbook means order selection failed
                # for some reason; no action is taken, we let the stallMonitor
                # + the finished callback decide whether to retry.
                return False
            if self.filter_orders_callback:
                accepted = self.filter_orders_callback([self.orderbook,
                                                        self.total_cj_fee],
                                                       self.cjamount)
                if isinstance(accepted, asyncio.Future):
                    accepted = await accepted
                if accepted == "retry":
                    # Special condition if Taker is "determined to continue"
                    # (such as tumbler); even though these offers are rejected,
                    # we don't trigger the finished callback; see above note on
                    # `if self.orderbook is None`
                    return False
                if not accepted:
                    return False
        return True

    async def prepare_my_bitcoin_data(self):
        """Get a coinjoin address and a change address; prepare inputs
        appropriate for this transaction"""
        jmman = self.jmman
        if not self.my_cj_addr:
            # previously used for donations; TODO reimplement?
            raise NotImplementedError
        if self.cjamount != 0:
            if self.custom_change_address:
                self.my_change_addr = self.custom_change_address
            else:
                try:
                    self.my_change_addr = jmman.jmw.get_internal_addr(
                        self.mixdepth)
                    if self.change_label:
                        try:
                            jmman.jmw.set_address_label(self.my_change_addr,
                                                        self.change_label)
                        except UnknownAddressForLabel:
                            # ignore, will happen with custom change
                            # not part of a wallet
                            pass
                except BaseException:
                    self.taker_info_callback("ABORT",
                                             "Failed to get a change address")
                    return False
            # adjust the required amount upwards to anticipate an increase in
            # transaction fees after re-estimation; this is sufficiently
            # conservative to make failures unlikely while keeping
            # the occurence of failure to find sufficient utxos extremely rare.
            # Indeed, a doubling of 'normal' txfee indicates undesirable
            # behaviour on maker side anyway.
            txin_type = jmman.wallet.get_txin_type()
            self.total_txfee = (
                jmman.jmw.estimate_tx_fee(3, 2, txtype=txin_type) *
                (self.n_counterparties - 1) +
                jmman.jmw.estimate_tx_fee(
                    3, 2, txtype=txin_type,
                    outtype=jmman.jmw.get_outtype(self.coinjoin_address())
                )
            )
            total_amount = self.cjamount + self.total_cj_fee + self.total_txfee
            self.logger.info('total estimated amount spent = ' +
                             btc.amount_to_str(total_amount))
            try:
                self.input_utxos = jmman.jmw.select_utxos(
                    self.mixdepth, total_amount, minconfs=1)
            except Exception as e:
                self.taker_info_callback("ABORT", "Unable to select sufficient"
                                                  " coins: " + repr(e))
                return False
        else:
            # sweep
            self.input_utxos = jmman.jmw.get_utxos_by_mixdepth()[self.mixdepth]
            self.my_change_addr = None
            # do our best to estimate the fee based on the number of
            # our own utxos; this estimate may be significantly higher
            # than the default set in option.txfee * makercount, where
            # we have a large number of utxos to spend. If it is smaller,
            # we'll be conservative and retain the original estimate.
            est_ins = len(self.input_utxos)+3*self.n_counterparties
            self.logger.debug("Estimated ins: "+str(est_ins))
            est_outs = 2*self.n_counterparties + 1
            self.logger.debug("Estimated outs: "+str(est_outs))
            self.total_txfee = jmman.jmw.estimate_tx_fee(
                est_ins, est_outs, txtype=jmman.wallet.get_txin_type(),
                outtype=jmman.jmw.get_outtype(self.coinjoin_address()))
            self.logger.debug("We have a fee estimate: "+str(self.total_txfee))
            total_value = sum([va['value']
                               for va in self.input_utxos.values()])
            txin_type = jmman.wallet.get_txin_type()
            if txin_type == "p2pkh":
                allowed_types = ["reloffer", "absoffer"]
            elif txin_type == "p2sh-p2wpkh":
                allowed_types = ["swreloffer", "swabsoffer"]
            elif txin_type == "p2wpkh":
                allowed_types = ["sw0reloffer", "sw0absoffer"]
            else:
                self.logger.error("Unrecognized wallet type,"
                                  " taker cannot continue.")
                return False
            self.orderbook, self.cjamount, self.total_cj_fee = \
                choose_sweep_orders(jmman, self.orderbook, total_value,
                                    self.total_txfee, self.n_counterparties,
                                    self.order_chooser, self.ignored_makers,
                                    allowed_types=allowed_types,
                                    max_cj_fee=self.max_cj_fee)
            if not self.orderbook:
                self.taker_info_callback("ABORT", "Could not find orders to"
                                                  " complete transaction")
                return False
            if self.filter_orders_callback:
                accepted = self.filter_orders_callback(
                    (self.orderbook, self.total_cj_fee), self.cjamount)
                if isinstance(accepted, asyncio.Future):
                    accepted = await accepted
                if not accepted:
                    return False

        self.utxos = {None: list(self.input_utxos.keys())}
        return True

    @async_hexbin
    async def receive_utxos(self, ioauth_data):
        """Triggered when the daemon returns utxo data from
        makers who responded; this is the completion of phase 1
        of the protocol
        """
        if self.aborted:
            return (False, "User aborted")

        self.maker_utxo_data = {}

        verified_data = await self._verify_ioauth_data(ioauth_data)
        for maker_inputs in verified_data:
            # We have succesfully processed the data from this nick
            self.utxos[maker_inputs.nick] = maker_inputs.utxo_list
            self.outputs.append({'address': maker_inputs.change_addr,
                                 'value': maker_inputs.change_amount})
            self.outputs.append({'address': maker_inputs.cj_addr,
                                 'value': self.cjamount})
            self.cjfee_total += maker_inputs.real_cjfee
            self.maker_txfee_contributions +=\
                self.orderbook[maker_inputs.nick]['txfee']
            self.maker_utxo_data[maker_inputs.nick] = maker_inputs.utxo_data
            self.logger.info(
                f"fee breakdown for {maker_inputs.nick} "
                f"totalin={maker_inputs.total_input:d} "
                f"cjamount={self.cjamount:d} "
                f"txfee={self.orderbook[maker_inputs.nick]['txfee']:d} "
                f"realcjfee={maker_inputs.real_cjfee:d}")

            try:
                self.nonrespondants.remove(maker_inputs.nick)
            except Exception as e:
                self.logger.warning(
                    "Failure to remove counterparty from nonrespondants list:"
                    f" {maker_inputs.nick}), error message: {repr(e)})")

        # Apply business logic of how many counterparties are enough; note that
        # this must occur after the above ioauth data processing, since
        # we only now know for sure that the data meets all business-logic
        # requirements.
        jmman = self.jmman
        if len(self.maker_utxo_data) < jmman.jmconf.minimum_makers:
            self.taker_info_callback("INFO", "Not enough counterparties,"
                                             " aborting.")
            return (False,
                    "Not enough counterparties responded to fill, giving up")

        self.taker_info_callback("INFO", "Got all parts, enough to build a tx")

        # The list self.nonrespondants is now reset and
        # used to track return of signatures for phase 2
        self.nonrespondants = list(self.maker_utxo_data.keys())

        my_total_in = sum([va['value'] for u, va in self.input_utxos.items()])
        if self.my_change_addr:
            # Estimate fee per choice of next/3/6 blocks targetting.
            estimated_fee = jmman.jmw.estimate_tx_fee(
                len(sum(self.utxos.values(), [])), len(self.outputs) + 2,
                txtype=jmman.wallet.get_txin_type(),
                outtype=jmman.jmw.get_outtype(self.coinjoin_address()))
            self.logger.info("Based on initial guess: " +
                             btc.amount_to_str(self.total_txfee) +
                             ", we estimated a miner fee of: " +
                             btc.amount_to_str(estimated_fee))
            # reset total
            self.total_txfee = estimated_fee
        my_txfee = max(self.total_txfee - self.maker_txfee_contributions, 0)
        my_change_value = (
            my_total_in - self.cjamount - self.cjfee_total - my_txfee)
        # Since we could not predict the maker's inputs, we may end up needing
        # too much such that the change value is negative or small. Note that
        # we have tried to avoid this based on over-estimating the needed
        # amount in SendPayment.create_tx(), but it is still a possibility
        # if one maker uses a *lot* of inputs.
        if self.my_change_addr:
            if my_change_value < -1:
                raise ValueError("Calculated transaction fee of: " +
                                 btc.amount_to_str(self.total_txfee) +
                                 " is too large for our inputs;"
                                 " Please try again.")
            if my_change_value <= jmman.jmconf.BITCOIN_DUST_THRESHOLD:
                self.logger.info("Dynamically calculated change lower"
                                 " than dust: " +
                                 btc.amount_to_str(my_change_value) +
                                 "; dropping.")
                self.my_change_addr = None
                my_change_value = 0
        self.logger.info('fee breakdown for me totalin=%d my_txfee=%d'
                         ' makers_txfee=%d cjfee_total=%d => changevalue=%d' %
                         (my_total_in, my_txfee,
                          self.maker_txfee_contributions,
                          self.cjfee_total, my_change_value))
        if self.my_change_addr is None:
            if my_change_value != 0 and abs(my_change_value) != 1:
                # seems you wont always get exactly zero because of integer
                # rounding so 1 satoshi extra or fewer being spent as miner
                # fees is acceptable
                self.logger.info(('WARNING CHANGE NOT BEING USED\n'
                                  'CHANGEVALUE = {}').format(my_change_value))
            # we need to check whether the *achieved* txfee-rate is outside
            # the range allowed by the user in config; if not, abort the tx.
            # this is done with using the same estimate fee function and
            # comparing the totals; this ratio will correspond to the ratio
            # of the feerates.
            num_ins = len([u for u in sum(self.utxos.values(), [])])
            num_outs = len(self.outputs) + 1
            new_total_fee = jmman.jmw.estimate_tx_fee(
                num_ins, num_outs, txtype=jmman.wallet.get_txin_type(),
                outtype=jmman.jmw.get_outtype(self.coinjoin_address()))
            feeratio = new_total_fee/self.total_txfee
            self.logger.debug("Ratio of actual to estimated sweep"
                              " fee: {}".format(feeratio))
            sweep_delta = float(jmman.jmconf.max_sweep_fee_change)
            if feeratio < 1 - sweep_delta or feeratio > 1 + sweep_delta:
                self.logger.warning(
                    "Transaction fee for sweep: {} too far from"
                    " expected: {}; check the setting"
                    " 'max_sweep_fee_change' in joinmarket.cfg"
                    ". Aborting this attempt.".
                    format(new_total_fee, self.total_txfee))
                return (False, "Unacceptable feerate for sweep, giving up.")
        else:
            self.outputs.append({'address': self.my_change_addr,
                                 'value': my_change_value})
        self.utxo_tx = [u for u in sum(self.utxos.values(), [])]
        self.outputs.append({'address': self.coinjoin_address(),
                             'value': self.cjamount})
        # pre-Nov-2020/v0.8.0: transactions used ver 1 and nlocktime 0
        # so only the new "pit" (using native segwit) will use the updated
        # version 2 and nlocktime ~ current block as per normal payments.
        # TODO makers do not check this; while there is no security risk,
        # it might be better for them to sanity check.
        if jmman.wallet.get_txin_type() == "p2wpkh":
            n_version = 2
            locktime = get_locktime_for_new_transaction(jmman.network)
        else:
            n_version = 1
            locktime = 0
        # pprint.pprint(self.utxo_tx)
        # pprint.pprint(self.outputs)
        self.latest_tx = btc.make_shuffled_tx(self.utxo_tx, self.outputs,
                                              version=n_version,
                                              locktime=locktime)
        # Add info to add maker signatures and self sign tx later
        self.latest_tx.add_info_from_wallet(jmman.wallet)
        await self.latest_tx.add_info_from_network(jmman.network)

        self.logger.info('obtained tx\n' + btc.human_readable_transaction(
            self.latest_tx))

        self.taker_info_callback("INFO", "Built tx, sending"
                                 " to counterparties.")
        return (True, list(self.maker_utxo_data.keys()),
                bfh(self.latest_tx.serialize_to_network(include_sigs=False)))

    async def _verify_ioauth_data(self, ioauth_data):
        verified_data = []
        # Need to authorize against the btc pubkey first.
        for nick, nickdata in ioauth_data.items():
            utxo_list, auth_pub, cj_addr, change_addr, btc_sig, maker_pk = \
                nickdata
            if not self.auth_counterparty(btc_sig, auth_pub, maker_pk):
                self.logger.debug("Counterparty encryption verification"
                                  " failed, aborting: " + nick)
                # This counterparty must be rejected
                continue

            if not is_address(cj_addr) or not is_address(change_addr):
                self.logger.warning("Counterparty provided invalid address: {}"
                                    .format((cj_addr, change_addr)))
                # Interpreted as malicious
                self.add_ignored_makers([nick])
                continue

            try:
                maker_inputs_data = await self._verify_ioauth_inputs(
                    nick, utxo_list, auth_pub)
            except IoauthInputVerificationError as e:
                for msg in e.messages:
                    self.logger.warning(msg)
                continue

            verified_data.append(maker_inputs_data._replace(
                utxo_list=utxo_list, cj_addr=cj_addr, change_addr=change_addr))
        return verified_data

    async def _verify_ioauth_inputs(self, nick, utxo_list, auth_pub):
        jmman = self.jmman
        utxo_data = await jmman.jmw.query_utxo_set(utxo_list,
                                                   includeconfs=True)
        if None in utxo_data:
            raise IoauthInputVerificationError([
                "ERROR: outputs unconfirmed or already spent. utxo_data="
                f"{pprint.pformat(utxo_data)}",
                "Disregarding this counterparty."])

        # Complete maker authorization:
        # Extract the address fields from the utxos
        # Construct the Bitcoin address for the auth_pub field
        # Ensure that at least one address from utxos corresponds.
        for inp in utxo_data:
            if inp["confirms"] <= 0:
                raise IoauthInputVerificationError([
                    f"maker's ({nick}) proposed utxo is not confirmed, "
                    "rejecting."])
            try:
                if jmman.jmw.pubkey_has_script(auth_pub, inp['script']):
                    break
            except EngineError:
                pass
        else:
            raise IoauthInputVerificationError([
                f"ERROR maker's ({nick}) authorising pubkey is not included "
                "in the transaction!"])

        total_input = sum([d['value'] for d in utxo_data])
        real_cjfee = calc_cj_fee(self.orderbook[nick]['ordertype'],
                                 self.orderbook[nick]['cjfee'],
                                 self.cjamount)
        change_amount = (total_input - self.cjamount -
                         self.orderbook[nick]['txfee'] + real_cjfee)

        # certain malicious and/or incompetent liquidity providers send
        # inputs totalling less than the coinjoin amount! this leads to
        # a change output of zero satoshis; this counterparty must be removed.
        if change_amount < jmman.jmconf.DUST_THRESHOLD:
            raise IoauthInputVerificationError([
                f"ERROR counterparty requires sub-dust change. nick={nick} "
                f"totalin={total_input:d} cjamount={self.cjamount:d} "
                f"change={change_amount:d}",
                f"Invalid change, too small, nick={nick}"])
        return self._MakerTxData(nick, utxo_data, total_input, change_amount,
                                 real_cjfee)

    @hexbin
    def auth_counterparty(self, btc_sig, auth_pub, maker_pk):
        """Validate the counterpartys claim to own the btc
        address/pubkey that will be used for coinjoining
        with an ecdsa verification.
        """
        try:
            # maker pubkey as message is in hex format:
            if not btc.ecdsa_verify(bintohex(maker_pk), btc_sig, auth_pub):
                self.logger.debug('signature didnt match pubkey and message')
                return False
        except Exception as e:
            self.logger.info("Failed ecdsa verify for maker pubkey: " +
                             bintohex(maker_pk))
            self.logger.info("Exception was: " + repr(e))
            return False
        return True

    async def on_sig(self, nick, sigb64):
        """Processes transaction signatures from counterparties.
        If all signatures received correctly, returns the result
        of self.self_sign_and_push() (i.e. we complete the signing
        and broadcast); else returns False (thus returns False for
        all but last signature).
        """
        if self.aborted:
            return False
        if nick not in self.nonrespondants:
            self.logger.debug('add_signature => nick={} not in nonrespondants'
                              ' {}'.format(nick, self.nonrespondants))
            return False
        jmman = self.jmman
        sig = base64.b64decode(sigb64)
        inserted_sig = False

        # batch retrieval of utxo data
        utxo = {}
        ctr = 0
        for index, ins in enumerate(self.latest_tx.inputs()):
            if self._is_our_input(ins) or ins.script_sig:
                continue
            utxo_for_checking = (ins.prevout.txid, ins.prevout.out_idx)
            utxo[ctr] = [index, utxo_for_checking]
            ctr += 1
        utxo_data = await jmman.jmw.query_utxo_set([x[1]
                                                    for x in utxo.values()])
        # insert signatures
        for i, u in utxo.items():
            if utxo_data[i] is None:
                continue

            txin_idx = u[0]
            txin = self.latest_tx.inputs()[txin_idx]
            if self._is_our_input(txin) or txin.script_sig or txin.witness:
                continue
            prevtx = txin.utxo.serialize()
            add_txin_sig(jmman, self.latest_tx, txin_idx, prevtx, sig)
            sig_good = verify_txin_sig(jmman, self.latest_tx, txin_idx, prevtx)

            if not sig_good:
                self.logger.debug(f'signature verification failed'
                                  f' at index={txin_idx}')
                self.latest_tx.inputs()[txin_idx].script_sig = None
                self.latest_tx.inputs()[txin_idx].witness = None
            else:
                self.logger.debug('found good sig at index=%d' % (u[0]))
                inserted_sig = True

                # check if maker has sent everything possible
                try:
                    self.utxos[nick].remove(u[1])
                except ValueError:
                    pass
                if len(self.utxos[nick]) == 0:
                    self.logger.debug('nick = {} sent all sigs, removing'
                                      ' from nonrespondant list'.format(nick))
                    try:
                        self.nonrespondants.remove(nick)
                    except ValueError:
                        pass
                break
        if not inserted_sig:
            self.logger.debug('signature did not match anything in the tx')
            # TODO what if the signature doesnt match anything
            # nothing really to do except drop it, carry on and wonder why the
            # other guy sent a failed signature

        tx_signed = True
        for ins in self.latest_tx.inputs():
            if (not self._is_our_input(ins) and
                    not ins.script_sig and not ins.witness):
                tx_signed = False
        if not tx_signed:
            return False
        assert not len(self.nonrespondants)
        self.logger.info('all makers have sent their signatures')
        self.taker_info_callback("INFO", "Transaction is valid, signing..")
        self.logger.debug("schedule item was: " +
                          str(self.schedule[self.schedule_index]))
        return await self.self_sign_and_push()

    async def make_commitment(self):
        """The Taker default commitment function, which uses PoDLE.
        Alternative commitment types should use a different commit type byte.
        This will allow future upgrades to provide different style commitments
        by subclassing Taker and changing the commit_type_byte; existing makers
        will simply not accept this new type of commitment.
        In case of success, return the (commitment, commitment opening).
        In case of failure returns (None, None, err) where 'err' is a detailed
        error string for the user to read and discern the reason.
        """

        async def filter_by_coin_age_amt(utxos, age, amt):
            results = await self.jmman.jmw.query_utxo_set(utxos,
                                                          includeconfs=True)
            newresults = []
            too_new = []
            too_small = []
            for i, r in enumerate(results):
                # results return "None" if txo is spent; drop this
                if not r:
                    continue
                valid_age = r['confirms'] >= age
                valid_amt = r['value'] >= amt
                if not valid_age:
                    too_new.append(utxos[i])
                if not valid_amt:
                    too_small.append(utxos[i])
                if valid_age and valid_amt:
                    newresults.append(utxos[i])
            return newresults, too_new, too_small

        async def priv_utxo_pairs_from_utxos(utxos, age, amt):
            # returns pairs list of (priv, utxo) for each valid utxo;
            # also returns lists "too_new" and "too_small" for any
            # utxos that did not satisfy the criteria for debugging.
            priv_utxo_pairs = []
            new_utxos, too_new, too_small = await filter_by_coin_age_amt(
                list(utxos.keys()), age, amt)
            new_utxos_dict = {k: v for k, v in utxos.items() if k in new_utxos}
            for k, v in new_utxos_dict.items():
                # filter out any non-standard utxos:
                script = v["script"]
                if not self.jmman.jmw.is_standard_wallet_script(script):
                    continue
                addr = self.jmman.jmw.script_to_addr(script)
                priv = self.jmman.jmw.get_key_from_addr(addr)
                if priv:  # can be null from create-unsigned
                    priv_utxo_pairs.append((priv, k))
            return priv_utxo_pairs, too_new, too_small

        commit_type_byte = "P"
        jmman = self.jmman
        tries = jmman.jmconf.taker_utxo_retries
        age = jmman.jmconf.taker_utxo_age
        # Minor rounding errors don't matter here
        amt = int(self.cjamount * jmman.jmconf.taker_utxo_amtpercent / 100.0)
        priv_utxo_pairs, to, ts = await priv_utxo_pairs_from_utxos(
            self.input_utxos, age, amt)

        # For podle data format see: podle.PoDLE.reveal()
        # In first round try, don't use external commitments
        podle_data = generate_podle(jmman, priv_utxo_pairs, tries)
        if not podle_data:
            # Pre-filter the set of external commitments that work for this
            # transaction according to its size and age.
            dummy, extdict = get_podle_commitments(jmman)
            if len(extdict) > 0:
                ext_valid, ext_to, ext_ts = filter_by_coin_age_amt(
                    list(extdict.keys()), age, amt)
            else:
                ext_valid = None
            # We defer to a second round to try *all* utxos in spending
            # mixdepth; this is because it's much cleaner to use the utxos
            # involved in the transaction, about to be consumed, rather
            # than use random utxos that will persist after. At this step
            # we also allow use of external utxos in the json file.
            mixdepth_utxos = jmman.jmw.get_utxos_by_mixdepth()[self.mixdepth]
            if len(self.input_utxos) == len(mixdepth_utxos):
                # Already tried the whole mixdepth
                podle_data = generate_podle(jmman, [], tries, ext_valid)
            else:
                priv_utxo_pairs, to, ts = await priv_utxo_pairs_from_utxos(
                    mixdepth_utxos, age, amt)
                podle_data = generate_podle(jmman, priv_utxo_pairs, tries,
                                            ext_valid)
        if podle_data:
            self.logger.debug("Generated PoDLE: " + repr(podle_data))
            return (commit_type_byte + bintohex(podle_data.commitment),
                    podle_data.serialize_revelation(),
                    "Commitment sourced OK")
        else:
            errmsgheader, errmsg = generate_podle_error_string(
                priv_utxo_pairs, to, ts, jmman, self.cjamount,
                jmman.jmconf.taker_utxo_age,
                jmman.jmconf.taker_utxo_amtpercent)

            return (None, (priv_utxo_pairs, to, ts), errmsgheader + errmsg)

    def coinjoin_address(self):
        if self.my_cj_addr:
            return self.my_cj_addr
        else:
            # Note: donation code removed (possibly temporarily)
            raise NotImplementedError

    def self_sign(self):
        # now sign it ourselves
        signed_ok = self.jmman.jmw.sign_coinjoin_transaction(self.latest_tx)
        if not signed_ok:
            self.logger.error("Failed to self sign transaction")
        else:
            self.logger.info("Transaction successfully self signed")
        return signed_ok

    async def handle_unbroadcast_transaction(self, txid, tx):
        """ The wallet service will handle dangling
        callbacks for transactions but we want to reattempt
        broadcast in case the cause of the problem is a
        counterparty who refused to broadcast it for us.
        """
        if not self.jmman.jmw.check_callback_called(
                self.txid, self.unconfirm_callback, "unconfirmed",
                "transaction with txid: " + str(self.txid) +
                " not broadcast."):
            # we now know the transaction was not pushed, so we reinstigate
            # the cancelledcallback with the same logic as explained
            # in Taker.push():
            self.jmman.jmw.wallet_service_register_callbacks(
                [self.unconfirm_callback], txid, "unconfirmed")
            if self.jmman.jmconf.tx_broadcast == "not-self":
                warnmsg = ("You have chosen not to broadcast from your own "
                           "node. The transaction is NOT broadcast.")
                self.taker_info_callback("ABORT", warnmsg +
                                         "\nSee log for details.")
                # warning is arguably not correct but it will stand out more:
                self.logger.warning(warnmsg)
                self.logger.info(btc.human_readable_transaction(tx))
                return
            if not await self.push_ourselves():
                self.logger.error("Failed to broadcast transaction: ")
                self.logger.info(btc.human_readable_transaction(tx))

    async def push_ourselves(self):
        return await self.jmman.network.try_broadcasting(
            self.latest_tx, 'JoinMakret Ttransaction')

    async def push(self):
        self.logger.debug('\n' + self.latest_tx.serialize())
        self.txid = self.latest_tx.txid()
        self.logger.info('txid = ' + self.txid)
        # add the callbacks *before* pushing to ensure triggering;
        # this does leave a dangling notify callback if the push fails, but
        # that doesn't cause problems.
        self.jmman.jmw.wallet_service_register_callbacks(
            [self.unconfirm_callback], self.txid, "unconfirmed")
        self.jmman.jmw.wallet_service_register_callbacks(
            [self.confirm_callback], self.txid, "confirmed")
        commands.deferLater(self.jmman.jmconf.unconfirm_timeout_sec,
                            self.handle_unbroadcast_transaction, self.txid,
                            self.latest_tx)

        tx_broadcast = self.jmman.jmconf.tx_broadcast
        nick_to_use = None
        if tx_broadcast == 'self':
            pushed = await self.push_ourselves()
        elif tx_broadcast in ['random-peer', 'not-self']:
            n = len(self.maker_utxo_data)
            if tx_broadcast == 'random-peer':
                i = random.randrange(n + 1)
            else:
                i = random.randrange(n)
            if i == n:
                pushed = await self.push_ourselves()
            else:
                nick_to_use = list(self.maker_utxo_data.keys())[i]
                pushed = True
        else:
            self.logger.info("Only self, random-peer and not-self broadcast "
                             "methods supported. Reverting to self-broadcast.")
            pushed = await self.push_ourselves()
        if not pushed:
            self.on_finished_callback(False, fromtx=True)
        else:
            if nick_to_use:
                return (
                    nick_to_use,
                    bfh(
                        self.latest_tx.serialize_to_network(
                            estimate_size=False, include_sigs=True)
                    )
                )
        # if push was not successful, return None
        return

    async def self_sign_and_push(self):
        signed_ok = self.self_sign()
        if not signed_ok:
            return signed_ok
        return await self.push()

    def tx_match(self, txd):
        # Takers process only in series, so this should not occur:
        assert self.latest_tx is not None
        # check if the transaction matches our created tx:
        if txd.txid() != self.latest_tx.txid():
            return False
        return True

    def unconfirm_callback(self, txd, txid):
        if not self.tx_match(txd):
            return False
        self.logger.info("Transaction seen on network, waiting for"
                         " confirmation")
        # To allow client to mark transaction as "done"
        # (e.g. by persisting state)
        self.on_finished_callback(True, fromtx="unconfirmed")
        self.waiting_for_conf = True
        confirm_timeout_sec = self.jmman.jmconf.confirm_timeout_hours * 3600
        commands.deferLater(confirm_timeout_sec,
                            self.jmman.jmw.check_callback_called, txid,
                            self.confirm_callback, "confirmed",
                            "transaction with txid " + str(txid) +
                            " not confirmed.")
        return True

    def confirm_callback(self, txd, txid, confirmations):
        if not self.tx_match(txd):
            return False
        self.waiting_for_conf = False
        if self.aborted:
            # do not trigger on_finished processing (abort whole schedule),
            # but we still return True as we have finished our listening
            # for this tx:
            return True
        self.logger.debug("Confirmed callback in taker, confs: " +
                          str(confirmations))
        fromtx = (False if self.schedule_index + 1 == len(self.schedule)
                  else True)
        waittime = self.schedule[self.schedule_index][4]
        self.on_finished_callback(True, fromtx=fromtx, waittime=waittime,
                                  txdetails=(txd, txid))
        return True

    def _is_our_input(self, tx_input):
        utxo = (tx_input.prevout.txid, tx_input.prevout.out_idx)
        return utxo in self.input_utxos


def round_to_significant_figures(d, sf):
    '''Rounding number d to sf significant figures in base 10'''
    for p in range(-10, 15):
        power10 = 10**p
        if power10 > d:
            sf_power10 = 10**sf
            sigfiged = int(round(d/power10*sf_power10)*power10/sf_power10)
            return sigfiged
    raise RuntimeError()


async def calculate_fidelity_bond_values(fidelity_bonds_info, jmman):
    jmw = jmman.jmw
    if len(fidelity_bonds_info) == 0:
        return {}
    interest_rate = jmman.jmconf.interest_rate
    blocks = jmman.wallet.adb.get_local_height()
    blockchain = jmman.network.blockchain()
    mediantime = jmw.get_median_time_past(blockchain)
    if mediantime is None:
        return {}

    validated_bonds = {}
    for bond_data in fidelity_bonds_info:
        try:
            fb_proof = FidelityBondProof.parse_and_verify_proof_msg(
                bond_data["counterparty"], bond_data["takernick"],
                bond_data["proof"])
        except ValueError:
            continue
        if fb_proof.utxo in validated_bonds:
            continue
        utxo_data = await jmw.get_validated_timelocked_fidelity_bond_utxo(
            fb_proof.utxo, fb_proof.utxo_pub, fb_proof.locktime,
            fb_proof.cert_expiry, blocks)
        if utxo_data is not None:
            validated_bonds[fb_proof.utxo] = (fb_proof, utxo_data)

    header = None
    if blocks and utxo_data is not None:
        header = blockchain.read_header(blocks - utxo_data["confirms"] + 1)
    if header is None:
        return {}
    block_time = header['timestamp']
    fidelity_bond_values = {
        bond_data.maker_nick:
            jmw.calculate_timelocked_fidelity_bond_value(
                utxo_data["value"],
                block_time,
                bond_data.locktime,
                mediantime,
                interest_rate)
        for bond_data, utxo_data in validated_bonds.values()
    }
    return fidelity_bond_values
