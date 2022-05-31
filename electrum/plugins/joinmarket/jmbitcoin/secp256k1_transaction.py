# -*- coding: utf-8 -*-

import json
# note, only used for non-cryptographic randomness:
import random
from typing import List, Tuple, Union

from electrum.transaction import (PartialTransaction, PartialTxInput,
                                  PartialTxOutput, TxOutpoint)


def human_readable_transaction(tx: PartialTransaction) -> str:
    """ Given a PartialTransaction object, output a human
    readable json-formatted string (suitable for terminal
    output or large GUI textbox display) containing
    all details of that transaction.
    """
    assert isinstance(tx, PartialTransaction)
    return json.dumps(tx.to_json(), indent=4)


def there_is_one_segwit_input(input_types: List[str]) -> bool:
    # note that we need separate input types for
    # any distinct types of scripthash inputs supported,
    # since each may have a different size of witness; in
    # that case, the internal list in this list comprehension
    # will need updating.
    # note that there is no support yet for paying *from* p2tr.
    return any(y in ["p2sh-p2wpkh", "p2wpkh", "p2wsh"] for y in input_types)


def estimate_tx_size(
            ins: List[str], outs: List[str]
        ) -> Union[int, Tuple[int]]:
    '''Estimate transaction size.
    Both arguments `ins` and `outs` must be lists of script types,
    and they must be present in the keys of the dicts `inmults`,
    `outmults` defined here.
    Note that variation in ECDSA signature sizes means
    we will sometimes see small inaccuracies in this estimate, but
    that this is ameliorated by the existence of the witness discount,
    in actually estimating fees.
    The value '72' is used for the most-likely size of these ECDSA
    signatures, due to
        30[1 byte] + len(rest)[1 byte] + type:02 [1 byte] +
        len(r)[1] + r[32 or 33] + type:02[1] + len(s)[1] +
        s[32] + sighash_all [1]
    ... though as can be seen, 71 is also likely:
    r length 33 occurs when the value is 'negative' (>N/2) and a byte x80
    is prepended, but shorter values for r are possible if rare.
    Returns:
    Either a single integer, if the transaction will be non-segwit,
    or a tuple (int, int) for witness and non-witness bytes respectively).
    '''

    # All non-witness input sizes include: txid, index, sequence,
    # which is 32, 4 and 4; the remaining is scriptSig which is 1
    # at minimum, for native segwit (the byte x00). Hence 41 is the minimum.
    # The witness field for p2wpkh consists of sig, pub so 72 + 33 + 1 byte
    # for the number of witness elements and 2 bytes for the size of each
    # element, hence 108.
    # For p2pkh, 148 comes from 32+4+1+1+~72+1+33+4
    # For p2sh-p2wpkh there is an additional 23 bytes of witness for the
    # redeemscript.
    #
    # Note that p2wsh here is specific to the script
    # we use for fidelity bonds; 43 is the bytes required for that
    # script's redeemscript field in the witness, but for arbitrary scripts,
    # the witness portion could be any other size.
    # Hence, we may need to modify this later.
    #
    # Note that there is no support yet for spending *from* p2tr:
    # we should fix this soon, since it is desirable to be able to support
    # coinjoins with counterparties sending taproot, but note, JM coinjoins
    # do not allow non-standard (usually v0 segwit) inputs, anyway.
    inmults = {"p2wsh": {"w": 1 + 72 + 43, "nw": 41},
               "p2wpkh": {"w": 108, "nw": 41},
               "p2sh-p2wpkh": {"w": 108, "nw": 64},
               "p2pkh": {"w": 0, "nw": 148}}

    # Notes: in outputs, there is only 1 'scripthash'
    # type for either segwit/nonsegwit (hence "p2sh-p2wpkh"
    # is a bit misleading, but is kept to the same as inputs,
    # for simplicity. See notes on inputs above).
    # p2wsh has structure 8 bytes output, then:
    # x22,x00,x20,(32 byte hash), so 32 + 3 + 8
    # note also there is no need to distinguish witness
    # here, outputs are always entirely nonwitness.
    # p2tr is also 32 byte hash with x01 instead of x00 version.
    outmults = {
        "p2wsh": 43,
        "p2wpkh": 31,
        "p2sh-p2wpkh": 32,
        "p2pkh": 34,
        "p2tr": 43
    }

    # nVersion, nLockTime, nins, nouts:
    nwsize = 4 + 4 + 2
    wsize = 0
    tx_is_segwit = there_is_one_segwit_input(ins)
    if tx_is_segwit:
        # flag and marker bytes are included in witness
        wsize += 2

    for i in ins:
        if i not in inmults:
            raise NotImplementedError(f"Script type not supported for"
                                      f" transaction size estimation: {i}")
        inmult = inmults[i]
        nwsize += inmult["nw"]
        wsize += inmult["w"]
    for o in outs:
        if o not in outmults:
            raise NotImplementedError(f"Script type not supported for"
                                      f" transaction size estimation: {o}")
        nwsize += outmults[o]

    if not tx_is_segwit:
        return nwsize
    return (wsize, nwsize)


def make_shuffled_tx(ins: List[Tuple[bytes, int]],
                     outs: List[dict],
                     version: int = 1,
                     locktime: int = 0) -> PartialTransaction:
    """ Simple wrapper to ensure transaction
    inputs and outputs are randomly ordered.
    NB: This mutates ordering of `ins` and `outs`.
    """
    random.shuffle(ins)
    random.shuffle(outs)
    prevouts = [TxOutpoint(txid=i[0], out_idx=i[1]) for i in ins]
    inputs = [PartialTxInput(prevout=p) for p in prevouts]
    outputs = [PartialTxOutput.from_address_and_value(
        address=o['address'], value=o['value']) for o in outs]
    return PartialTransaction.from_io(inputs=inputs, outputs=outputs,
                                      version=version, locktime=locktime,
                                      BIP69_sort=False)
