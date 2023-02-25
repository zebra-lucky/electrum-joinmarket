#!/usr/bin/env python3

import sys
from pprint import pprint

from electrum import constants
from electrum.bitcoin import public_key_to_p2wpkh
from electrum.crypto import sha256d
from electrum.transaction import tx_from_any, Sighash
from electrum.util import bfh, bh2u

IS_TESTNET = True
if IS_TESTNET:
    constants.set_testnet()

def prehash_txin(tx, txin_index) -> str:
    txin = tx.inputs()[txin_index]
    txin.set_script_type()
    txin.validate_data(for_signing=True)
    pre_hash = sha256d(bfh(tx.serialize_preimage(txin_index)))
    return pre_hash

def sign_with_mpc(tx, pubkey, addr):
    for i, txin in enumerate(tx.inputs()):
        if txin.address != addr:
            continue
        if txin.script_sig:
            continue
        print(f'input {i}')
        if txin.script_type in ('address', 'unknown'):
            txin.script_type = tx.guess_txintype_from_address(txin.address)
        print('address', txin.address)
        print('script_type', txin.script_type)
        if not txin.pubkeys:
            txin.pubkeys = [pubkey]
        prehash = prehash_txin(tx, i)
        print(f'Prehash: {bh2u(prehash)}')
        sig_hex = input('Enter signautre:')
        sighash = txin.sighash if txin.sighash is not None else Sighash.ALL
        sighash_type = sighash.to_bytes(length=1, byteorder="big").hex()
        sig = sig_hex + sighash_type
        pubk_hex = bh2u(pubkey)
        tx.add_signature_to_txin(txin_idx=i, signing_pubkey=pubk_hex, sig=sig)
    print(f'Tx:\n{tx.serialize()}')

try:
    psbt = sys.argv[1]
    pubkey_hex = sys.argv[2]
    tx = tx_from_any(psbt)
    pubkey = bfh(pubkey_hex)
    addr = public_key_to_p2wpkh(pubkey)
    sign_with_mpc(tx, pubkey, addr)
except Exception:
    #import traceback
    #traceback.print_exc()
    print("usage: sign_witn_mpc <PSBT> <pubkey_hex>")
    sys.exit(1)

