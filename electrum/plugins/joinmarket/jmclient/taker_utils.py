# -*- coding: utf-8 -*-

import asyncio
import logging
import datetime
import pathlib
import pprint
import os
import numbers
from typing import Callable, List, Optional, Tuple, Union

from electrum.bitcoin import is_address
from electrum.wallet import get_locktime_for_new_transaction

from .schedule import (human_readable_schedule_entry, tweak_tumble_schedule,
                       schedule_to_text)
from ..jmbitcoin import (make_shuffled_tx, amount_to_str,
                         human_readable_transaction)
from ..jm_util import UnknownAddressForLabel


"""
Utility functions for tumbler-style takers;
Currently re-used by CLI script tumbler.py and joinmarket-qt
"""


def get_utxo_scripts(jmman, utxos: dict) -> list:
    # given a Joinmarket wallet and a set of utxos
    # as passed from `get_utxos_by_mixdepth` at one mixdepth,
    # return the list of script types for each utxo
    script_types = []
    for utxo in utxos.values():
        script_types.append(jmman.jmw.get_outtype(utxo["address"]))
    return script_types


async def direct_send(
    jmman,
    mixdepth: int,
    dest_and_amounts: List[Tuple[str, int]],
    answeryes: bool = False,
    accept_callback: Optional[
        Callable[[str, str, int, int, Optional[str]], bool]] = None,
    info_callback: Optional[Callable[[str], None]] = None,
    error_callback: Optional[Callable[[str], None]] = None,
    return_transaction: bool = False,
    optin_rbf: bool = True,
    custom_change_addr: Optional[str] = None,
    change_label: Optional[str] = None
) -> Union[bool, str]:
    try:
        await _direct_send(
            jmman=jmman, mixdepth=mixdepth, dest_and_amounts=dest_and_amounts,
            answeryes=answeryes, accept_callback=accept_callback,
            info_callback=info_callback, error_callback=error_callback,
            return_transaction=return_transaction, optin_rbf=optin_rbf,
            custom_change_addr=custom_change_addr, change_label=change_label)
    except Exception as e:
        cb = jmman.logger.error if not error_callback else error_callback
        cb(f'Direct send error: {repr(e)}')


async def _direct_send(
    jmman,
    mixdepth: int,
    dest_and_amounts: List[Tuple[str, int]],
    answeryes: bool = False,
    accept_callback: Optional[
        Callable[[str, str, int, int, Optional[str]], bool]] = None,
    info_callback: Optional[Callable[[str], None]] = None,
    error_callback: Optional[Callable[[str], None]] = None,
    return_transaction: bool = False,
    optin_rbf: bool = True,
    custom_change_addr: Optional[str] = None,
    change_label: Optional[str] = None
) -> Union[bool, str]:
    """Send coins directly from one mixdepth to one destination address;
    does not need IRC. Sweep as for normal sendpayment (set amount=0).
    If answeryes is True, callback/command line query is not performed.
    If optin_rbf is True, the nSequence values are changed as appropriate.
    """
    is_sweep = False
    outtypes = []
    total_outputs_val = 0

    # Sanity checks
    assert isinstance(dest_and_amounts, list)
    assert len(dest_and_amounts) > 0
    assert custom_change_addr is None or is_address(custom_change_addr)
    assert isinstance(mixdepth, numbers.Integral)
    assert mixdepth >= 0

    for target in dest_and_amounts:
        destination = target[0]
        amount = target[1]
        assert is_address(destination)
        if amount == 0:
            assert custom_change_addr is None and len(dest_and_amounts) == 1
            is_sweep = True
        assert isinstance(amount, numbers.Integral)
        assert amount >= 0
        # if the output is of a script type not currently
        # handled by our wallet code, we can't use information
        # to help us calculate fees, but fall back to default.
        # This is represented by a return value `None`.
        # Note that this does *not* imply we accept any nonstandard
        # output script, because we already called `validate_address`.
        outtypes.append(jmman.jmw.get_outtype(destination))
        total_outputs_val += amount

    txtype = jmman.wallet.get_txin_type()

    if is_sweep:
        # doing a sweep
        destination = dest_and_amounts[0][0]
        amount = dest_and_amounts[0][1]
        utxos = jmman.jmw.get_utxos_by_mixdepth()[mixdepth]
        if utxos == {}:
            errormsg = ("There are no available utxos in mixdepth: " +
                        str(mixdepth) + ", quitting.")
            cb = jmman.logger.error if not error_callback else error_callback
            cb(errormsg)
            return
        total_inputs_val = sum([va['value'] for u, va in utxos.items()])
        script_types = get_utxo_scripts(jmman, utxos)
        fee_est = jmman.jmw.estimate_tx_fee(len(utxos), 1, txtype=script_types,
                                            outtype=outtypes[0])
        outs = [{"address": destination, "value": total_inputs_val - fee_est}]
    else:
        if custom_change_addr:
            change_type = jmman.jmw.get_outtype(custom_change_addr)
            if change_type is None:
                # we don't recognize this type; best we can do is revert
                # to default, even though it may be inaccurate:
                change_type = txtype
        else:
            change_type = txtype
        if outtypes[0] is None:
            # we don't recognize the destination script type,
            # so set it as the same as the change (which will usually
            # be the same as the spending wallet, but see above for custom)
            # Notice that this is handled differently to the sweep case above,
            # because we must use a list - there is more than one output
            outtypes[0] = change_type
        outtypes.append(change_type)
        # not doing a sweep; we will have change.
        # 8 inputs to be conservative; note we cannot account for the
        # possibility of non-standard input types at this point.
        initial_fee_est = jmman.jmw.estimate_tx_fee(
            8, len(dest_and_amounts) + 1, txtype=txtype, outtype=outtypes)
        utxos = jmman.jmw.select_utxos(mixdepth, amount + initial_fee_est,
                                       includeaddr=True)
        script_types = get_utxo_scripts(jmman, utxos)
        if len(utxos) < 8:
            fee_est = jmman.jmw.estimate_tx_fee(
                len(utxos), len(dest_and_amounts) + 1,
                txtype=script_types, outtype=outtypes)
        else:
            fee_est = initial_fee_est
        total_inputs_val = sum([va['value'] for u, va in utxos.items()])
        changeval = total_inputs_val - fee_est - total_outputs_val
        outs = []
        for out in dest_and_amounts:
            outs.append({"value": out[1], "address": out[0]})
        change_addr = (jmman.jmw.get_internal_addr(mixdepth)
                       if custom_change_addr is None else custom_change_addr)
        outs.append({"value": changeval, "address": change_addr})

    # compute transaction locktime, has special case for spending
    # timelocked coins
    tx_locktime = get_locktime_for_new_transaction(jmman.network)

    # Now ready to construct transaction
    jmman.logger.info("Using a fee of: " + amount_to_str(fee_est) + ".")
    if not is_sweep:
        jmman.logger.info("Using a change value of: " +
                          amount_to_str(changeval) + ".")
    tx = make_shuffled_tx(list(utxos.keys()), outs,
                          version=2, locktime=tx_locktime)
    tx.add_info_from_wallet(jmman.wallet)
    await tx.add_info_from_network(jmman.network)

    if optin_rbf:
        for txin in tx.inputs():
            txin.nsequence = 0xffffffff - 2

    success = jmman.jmw.sign_coinjoin_transaction(tx)
    if not success:
        errormsg = "Failed to sign transaction, quitting."
        cb = jmman.logger.error if not error_callback else error_callback
        cb(errormsg)
        return
    jmman.logger.info("Got signed transaction:\n")
    jmman.logger.info(human_readable_transaction(tx))
    actual_amount = amount if amount != 0 else total_inputs_val - fee_est
    sending_info = ("Sends: " + amount_to_str(actual_amount) +
                    " to destination: " + destination)
    if custom_change_addr:
        sending_info += ", custom change to: " + custom_change_addr
    jmman.logger.info(sending_info)
    if not answeryes:
        if not accept_callback:
            cb = jmman.logger.error if not error_callback else error_callback
            cb('No accept callback, quitting')
            return
        else:
            accepted = accept_callback(human_readable_transaction(tx),
                                       destination, actual_amount, fee_est,
                                       custom_change_addr)
            if isinstance(accepted, asyncio.Future):
                accepted = await accepted
            if not accepted:
                cb = jmman.logger.info if not info_callback else info_callback
                cb('Not accepted, quitting', False)
                return
    if change_label:
        try:
            jmman.jmw.set_address_label(change_addr, change_label)
        except UnknownAddressForLabel:
            # ignore, will happen with custom change not part of a wallet
            pass
    if await jmman.network.try_broadcasting(tx, 'JoinMakret Direct'
                                                ' Send Ttransaction'):
        txid = tx.txid()
        successmsg = "Transaction sent: " + txid
        txinfo = txid if not return_transaction else tx
        cb = jmman.logger.info if not info_callback else info_callback
        cb(successmsg, txinfo)
        return
    else:
        errormsg = "Transaction broadcast failed!"
        cb = jmman.logger.error if not error_callback else error_callback
        cb(errormsg)
        return


def delete_old_logs(jmman, path, *, num_files_keep: int):
    files = sorted(list(pathlib.Path(path).glob("TUMBLE_*.log")), reverse=True)
    for f in files[num_files_keep:]:
        try:
            os.remove(str(f))
        except OSError as e:
            jmman.logger.warning(f"cannot delete old tumble logfile: {e}")


def get_tumble_log(jmman, logsdir, config):
    logsdir.mkdir(exist_ok=True)
    num_files_keep = config.LOGS_NUM_FILES_KEEP
    delete_old_logs(jmman, logsdir, num_files_keep=num_files_keep)
    tumble_log = logging.getLogger('tumbler')
    tumble_log.setLevel(logging.DEBUG)
    logFormatter = logging.Formatter(
        ('%(asctime)s %(message)s'))
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    PID = os.getpid()
    _logfile_path = logsdir / f"TUMBLE_{timestamp}_{PID}.log"
    fileHandler = logging.FileHandler(_logfile_path)
    fileHandler.setFormatter(logFormatter)
    tumble_log.addHandler(fileHandler)
    return tumble_log


def get_total_tumble_amount(mixdepth_balance_dict, schedule):
    # calculating total coins that will be included in a tumble;
    # in almost all cases all coins (unfrozen) in wallet will be tumbled,
    # though it's technically possible with a very small mixdepthcount,
    # to start at say m0, and only go through to 2 or 3, such that coins
    # in 4 are untouched in phase 2 (after having been swept in phase 1).
    used_mixdepths = set()
    [used_mixdepths.add(x[0]) for x in schedule]
    total_tumble_amount = int(0)
    for i in used_mixdepths:
        total_tumble_amount += mixdepth_balance_dict[i]
    # Note; we assert since callers will have called `get_tumble_schedule`,
    # which will already have thrown if no funds, so this would be
    # a logic error.
    assert total_tumble_amount > 0, "no coins to tumble."
    return total_tumble_amount


def restart_wait(jmman, txid):
    """ Returns true only if the transaction txid is seen in the wallet,
    and confirmed (it must be an in-wallet transaction since it always
    spends coins from the wallet).
    """
    tx_mined_info = jmman.wallet.adb.get_tx_height(txid)
    if not tx_mined_info:
        return False
    if tx_mined_info.conf == 0:
        return False
    if tx_mined_info.conf < 0:
        jmman.logger.warning("Tx: " + txid + " has a conflict.")
    else:
        jmman.logger.debug("Tx: " + str(txid) + " has " +
                           str(tx_mined_info.conf) + " confirmations.")
        return True


def unconf_update(taker, tumble_log, addtolog=False):
    """Provide a Taker object, a logging instance for tumble log,
    and a parameter for whether to update TUMBLE.log.
    Makes the necessary state updates explained below, including to
    the wallet.
    Note that this is re-used for confirmation with addtolog=False,
    to avoid a repeated entry in the log.
    """
    # on taker side, cache index update is only required after tx
    # push, to avoid potential of address reuse in case of a crash,
    # because addresses are not public until broadcast (whereas for makers,
    # they are public *during* negotiation). So updating the cache here
    # is sufficient
    jmman = taker.jmman
    jmman.wallet.save_db()

    # If honest-only was set, and we are going to continue (e.g. Tumbler),
    # we switch off the honest-only filter. We also wipe the honest maker
    # list, because the intention is to isolate the source of liquidity
    # to exactly those that participated, in 1 transaction (i.e. it's a 1
    # transaction feature). This code is here because it *must* be called
    # before any continuation, even if confirm_callback happens before
    # unconfirm_callback
    taker.set_honest_only(False)
    taker.honest_makers = []

    # We persist the fact that the transaction is complete to the
    # schedule file. Note that if a tweak to the schedule occurred,
    # it only affects future (non-complete) transactions, so the final
    # full record should always be accurate; but TUMBLE.log should be
    # used for checking what actually happened.
    completion_flag = 1 if not addtolog else taker.txid
    taker.schedule[taker.schedule_index][-1] = completion_flag
    jmman.jmconf.set_schedule(schedule_to_text(taker.schedule))
    jmman.wallet.save_db()

    if addtolog:
        tumble_log.info("Completed successfully this entry:")
        # the log output depends on if it's to INTERNAL
        hrdestn = None
        if taker.schedule[taker.schedule_index][3] in ["INTERNAL", "addrask"]:
            hrdestn = taker.my_cj_addr
        # Whether sweep or not, the amt is not in satoshis; use taker data
        hramt = taker.cjamount
        tumble_log.info(human_readable_schedule_entry(
            taker.schedule[taker.schedule_index], hramt, hrdestn))
        tumble_log.info(f"Txid was: {taker.txid}")


def tumbler_taker_finished_update(taker, tumble_log, options,
                                  res, fromtx=False, waittime=0.0,
                                  txdetails=None):
    """on_finished_callback processing for tumbler.
    Note that this is *not* the full callback, but provides common
    processing across command line and other GUI versions.
    """
    jmman = taker.jmman

    if fromtx == "unconfirmed":
        # unconfirmed event means transaction has been propagated,
        # we update state to prevent accidentally re-creating it in
        # any crash/restart condition
        unconf_update(taker, tumble_log, True)
        return
    if fromtx:
        if res:
            # this has no effect except in the rare case that confirmation
            # is immediate; also it does not repeat the log entry.
            unconf_update(taker, tumble_log, False)

            waiting_message = "Waiting for: " + str(waittime) + " minutes."
            tumble_log.info(waiting_message)
            jmman.logger.info(waiting_message)
        else:
            # a transaction failed, either because insufficient makers
            # (acording to minimum_makers) responded in Phase 1, or not all
            # makers responded in Phase 2, or the tx was a mempool conflict.
            # If the tx was a mempool conflict, we should restart with random
            # maker choice as usual. If someone didn't respond, we'll try to
            # repeat without the troublemakers.
            jmman.logger.info("Schedule entry: " + str(
                              taker.schedule[taker.schedule_index]) +
                              " failed after timeout, trying again")
            taker.add_ignored_makers(taker.nonrespondants)
            # Is the failure in Phase 2?
            if taker.latest_tx is not None:
                if len(taker.nonrespondants) == 0:
                    # transaction was created validly but conflicted in the
                    # mempool; just try again without honest settings;
                    # i.e. fallback to same as Phase 1 failure.
                    jmman.logger.info("Invalid transaction; possible"
                                      " mempool conflict.")
                else:
                    # Now we have to set the specific group we want to use,
                    # and hopefully they will respond again as they showed
                    # honesty last time.
                    # Note that we must wipe the list first; other honest
                    # makers needn't have the right settings (e.g. max
                    # cjamount), so can't be carried over from
                    # earlier transactions.
                    taker.honest_makers = []
                    taker.add_honest_makers(list(set(
                        taker.maker_utxo_data.keys()).symmetric_difference(
                            set(taker.nonrespondants))))
                    # If insufficient makers were honest, we can only tweak
                    # the schedule.
                    # If enough were, we prefer to restart with them only:
                    jmman.logger.info("Inside a Phase 2 failure; number"
                                      " of honest respondants was: " +
                                      str(len(taker.honest_makers)))
                    jmman.logger.info("They were: " + str(taker.honest_makers))
                    if len(taker.honest_makers) >= jmman.jmconf.minimum_makers:
                        tumble_log.info("Transaction attempt failed,"
                                        " attempting to restart with subset.")
                        tumble_log.info("The paramaters of the failed"
                                        " attempt: ")
                        tumble_log.info(
                            str(taker.schedule[taker.schedule_index]))
                        # we must reset the number of counterparties, as well
                        # as fix who they
                        # are; this is because the number is used to e.g.
                        # calculate fees.
                        # cleanest way is to reset the number in the
                        # schedule before restart.
                        taker.schedule[taker.schedule_index][2] = len(
                            taker.honest_makers)
                        retry_str = "Retrying with: " + str(taker.schedule[
                            taker.schedule_index][2]) + " counterparties."
                        tumble_log.info(retry_str)
                        jmman.logger.info(retry_str)
                        taker.set_honest_only(True)
                        taker.schedule_index -= 1
                        return

            # There were not enough honest counterparties.
            # Tumbler is aggressive in trying to complete; we tweak
            # the schedule from this point in the mixdepth, then try again.
            tumble_log.info("Transaction attempt failed, tweaking schedule"
                            " and trying again.")
            tumble_log.info("The paramaters of the failed attempt: ")
            tumble_log.info(str(taker.schedule[taker.schedule_index]))
            taker.schedule_index -= 1
            taker.schedule = tweak_tumble_schedule(jmman,
                                                   options,
                                                   taker.schedule,
                                                   taker.schedule_index,
                                                   taker.tdestaddrs)
            tumble_log.info("We tweaked the schedule, the new schedule is:")
            tumble_log.info(pprint.pformat(taker.schedule))
    else:
        if not res:
            failure_msg = "Did not complete successfully, shutting down"
            tumble_log.info(failure_msg)
            jmman.logger.info(failure_msg)
        else:
            jmman.logger.info("All transactions completed correctly")
            if not taker.schedule:
                return
            tumble_log.info("Completed successfully the last entry:")
            # Whether sweep or not, the amt is not in satoshis; use taker data
            hramt = taker.cjamount
            tumble_log.info(human_readable_schedule_entry(
                taker.schedule[taker.schedule_index], hramt))
            # copy of above, TODO refactor out
            taker.schedule[taker.schedule_index][-1] = 1
            jmman.jmconf.set_schedule(schedule_to_text(taker.schedule))
            jmman.wallet.save_db()


def tumbler_filter_orders_callback(jmman, orders_fees, cjamount, taker):
    """Since the tumbler does not use interactive fee checking,
    we use the -x values from the command line instead.
    """
    orders, total_cj_fee = orders_fees
    abs_cj_fee = 1.0 * total_cj_fee / taker.n_counterparties
    rel_cj_fee = abs_cj_fee / cjamount
    jmman.logger.info('rel/abs average fee = ' + str(rel_cj_fee) + ' / ' +
                      str(abs_cj_fee))

    if rel_cj_fee > taker.max_cj_fee[0] and abs_cj_fee > taker.max_cj_fee[1]:
        jmman.logger.info("Rejected fees as too high according to options,"
                          " will retry.")
        return "retry"
    return True
