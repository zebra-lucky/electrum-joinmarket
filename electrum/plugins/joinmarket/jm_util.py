# -*- coding: utf-8 -*-

import attr
import logging
import re
from enum import IntEnum

import electrum_ecc as ecc

from electrum import constants
from electrum.bitcoin import sha256d, address_to_script, is_address, opcodes
from electrum.descriptor import (PubkeyProvider, PKHDescriptor, WPKHDescriptor,
                                 SHDescriptor)
from electrum.crypto import hash_160
from electrum.transaction import (PartialTransaction, Transaction,
                                  get_script_type_from_output_script)
from electrum.util import to_bytes


# secp256k1 prime
prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def decompress_secp256k1_pubkey(pk):
    x = int.from_bytes(pk[1:33], byteorder='big')
    y_sq = (pow(x, 3, prime) + 7) % prime
    y = pow(y_sq, (prime + 1) // 4, prime)
    if y % 2 != pk[0] % 2:
        y = prime - y
    y = y.to_bytes(32, byteorder='big')
    return b'\x04' + pk[1:33] + y


class UnknownAddressForLabel(Exception):

    def __init__(self, addr: str):
        super().__init__(f"Unknown address for this wallet: {addr}.")


def verify_signature(pubkey: bytes, sig: bytes, h: bytes) -> bool:
    return ecc.ECPubkey(pubkey).ecdsa_verify(sig, h)


def guess_address_script_type(addr):
    net = constants.net
    if not is_address(addr, net=net):
        return 'invalid bitcoin address'
    try:
        script = address_to_script(addr, net=net)
        return get_script_type_from_output_script(to_bytes(script))
    except Exception:
        return 'unknown address type'


def add_txin_sig(jmman, tx, txin_idx, txin_prevtx, sigmsg):
    if not isinstance(tx, Transaction):
        tx = Transaction(tx)
    if not isinstance(tx, PartialTransaction):
        tx = PartialTransaction.from_tx(tx)
    inputs = tx.inputs()
    if len(inputs) - 1 < txin_idx:
        jmman.logger.info(f'add_txin_sig: txin_idx {txin_idx} too big')
        return
    txin = inputs[txin_idx]

    if not isinstance(txin_prevtx, Transaction):
        txin_prevtx = Transaction(txin_prevtx)
    if txin.prevout.txid.hex() != txin_prevtx.txid():
        jmman.logger.info('add_txin_sig: wrong txin_prevtx')
        return

    prevout_o = txin_prevtx.outputs()[txin.prevout.out_idx]
    scriptPubKey = prevout_o.scriptpubkey
    script_type = get_script_type_from_output_script(scriptPubKey)
    sig = None

    if script_type in ['p2pkh', 'p2wpkh', 'p2sh']:
        sig_len = sigmsg[0]
        sig = sigmsg[1:1+sig_len]
        pubk = sigmsg[2+sig_len:]
    else:
        jmman.logger.info(f'add_txin_sig: not implemented'
                          f' scripttype {script_type}')
        return

    if not sig:
        jmman.logger.info(f'add_txin_sig: no sig found'
                          f' for {script_type}')
        return

    if sig_len not in [70, 71, 72]:  # DER 70, 71, 72
        jmman.logger.info(f'add_txin_sig: scriptsig wrong'
                          f' DER length: {sig_len}')
        return
    add_txin_descriptor(jmman, tx, txin_idx, txin_prevtx, pubk.hex())
    tx.add_signature_to_txin(txin_idx=txin_idx, signing_pubkey=pubk, sig=sig)
    tx.inputs()[txin_idx].finalize()


def add_txin_descriptor(jmman, tx, txin_idx, txin_prevtx, pubk_hex):
    if not isinstance(tx, Transaction):
        tx = Transaction(tx)
    if not isinstance(tx, PartialTransaction):
        tx = PartialTransaction.from_tx(tx)
    inputs = tx.inputs()
    if len(inputs) - 1 < txin_idx:
        jmman.logger.debug(f'add_txin_descriptor: txin_idx {txin_idx} too big')
        return
    txin = inputs[txin_idx]

    if not isinstance(txin_prevtx, Transaction):
        txin_prevtx = Transaction(txin_prevtx)
    if txin.prevout.txid.hex() != txin_prevtx.txid():
        jmman.logger.debug('add_txin_descriptor: wrong txin_prevtx')
        return

    prevout_o = txin_prevtx.outputs()[txin.prevout.out_idx]
    scriptPubKey = prevout_o.scriptpubkey
    script_type = get_script_type_from_output_script(scriptPubKey)
    pubk_prov = PubkeyProvider(None, pubk_hex, None)

    if script_type == 'p2pkh':
        d = PKHDescriptor(pubk_prov)
        txin.script_descriptor = d
    elif script_type == 'p2wpkh':
        d = WPKHDescriptor(pubk_prov)
        txin.script_descriptor = d
        txin.witness_utxo = prevout_o
    elif script_type == 'p2sh':
        sub_d = WPKHDescriptor(pubk_prov)
        d = SHDescriptor(sub_d)
        if d.expand().output_script != scriptPubKey:
            jmman.logger.debug(f'add_txin_descriptor: prevout p2sh sriptPubKey'
                               f' seems not p2sh-p2wpkh script for {pubk_hex}')
            return
        txin.script_descriptor = d
        txin.witness_utxo = prevout_o
    else:
        jmman.logger.debug(f'add_txin_descriptor: not implemented'
                           f' scripttype {script_type}')
        return


def verify_txin_sig(jmman, tx, txin_idx, txin_prevtx):
    if not isinstance(tx, Transaction):
        tx = Transaction(tx)
    inputs = tx.inputs()
    if len(inputs) - 1 < txin_idx:
        jmman.logger.debug(f'verify_txin_sig: txin_idx {txin_idx} too big')
        return False
    txin = inputs[txin_idx]

    if not isinstance(txin_prevtx, Transaction):
        txin_prevtx = Transaction(txin_prevtx)
    if txin.prevout.txid.hex() != txin_prevtx.txid():
        jmman.logger.debug('verify_txin_sig: wrong txin_prevtx')
        return False

    prevout_o = txin_prevtx.outputs()[txin.prevout.out_idx]
    scriptPubKey = prevout_o.scriptpubkey
    witness = txin.witness
    scriptSig = txin.script_sig
    script_type = get_script_type_from_output_script(scriptPubKey)

    if script_type != 'p2wpkh' and not scriptSig:
        jmman.logger.debug(f'verify_txin_sig: empty scriptSig'
                           f' for {script_type}')
        return False

    sig = None
    if witness and script_type in ['p2wpkh', 'p2sh']:
        c_elements = witness[0]
        if c_elements != 2:
            jmman.logger.debug(f'verify_txin_sig: wrong count of {script_type}'
                               f' withess elements: {c_elements}')
        sig_len = witness[1]
        sig = witness[2:2+sig_len]
        pubk = witness[3+sig_len:]
    elif script_type == 'p2pkh':
        sig_len = scriptSig[0]
        sig = scriptSig[1:1+sig_len]
        pubk = scriptSig[2+sig_len:]

    if not sig:
        jmman.logger.debug(f'verify_txin_sig: no sig found for {script_type}')
        return False

    if sig_len not in [71, 72, 73]:  # DER 70, 71, 72 + sighash type byte
        jmman.logger.debug(f'verify_txin_sig: scriptsig wrong'
                           f' DER length: {sig_len}, sig={sig.hex()}')
        return False

    sighash = sig[-1]
    if sighash not in [1, 2, 3, 0x80]:
        jmman.logger.debug(f'verify_txin_sig: wrong SIGHASH {sighash}')
        return False

    if not pubk:
        jmman.logger.debug(f'verify_txin_sig: no pubk found for {script_type}')
        return False

    pubk_len = len(pubk)
    if pubk_len != 33:
        jmman.logger.debug(f'verify_txin_sig: wrong pubk lenght {pubk_len}')
        return False

    pubk_prov = PubkeyProvider(None, pubk.hex(), None)
    part_tx = PartialTransaction.from_tx(tx)
    part_txin = part_tx.inputs()[txin_idx]
    part_txin.sighash = sighash

    if script_type == 'p2pkh':
        pk_hash160 = scriptPubKey[3:-2]
        if pk_hash160 != hash_160(pubk):
            jmman.logger.debug('verify_txin_sig: hash160 differ for p2pkh')

        d = PKHDescriptor(pubk_prov)
        part_txin.script_descriptor = d
    elif witness and script_type == 'p2wpkh':
        pk_hash160 = scriptPubKey[2:]
        if pk_hash160 != hash_160(pubk):
            jmman.logger.debug('verify_txin_sig: hash160 differ for p2wpkh')

        d = WPKHDescriptor(pubk_prov)
        part_txin.script_descriptor = d
        part_txin.witness_utxo = prevout_o
    elif witness and script_type == 'p2sh':
        if (len(scriptPubKey) != 23
                or scriptPubKey[0] != opcodes.OP_HASH160
                or scriptPubKey[1] != 20
                or scriptPubKey[-1] != opcodes.OP_EQUAL):
            jmman.logger.debug('verify_txin_sig: invalid scriptPubKey'
                               ' for p2wpkh-psh')
            return False
        if (len(scriptSig) != 23
                or scriptSig[0] != 22       # length of scriptSig
                or scriptSig[1] != 0        # version byte
                or scriptSig[2] != 20):     # witness program
            jmman.logger.debug('verify_txin_sig: invalid scriptSig'
                               ' for p2wpkh-psh')
            return False

        script_hash = scriptPubKey[2:-1]
        if script_hash != hash_160(scriptSig[1:]):
            jmman.logger.debug('verify_txin_sig: hash160 differ'
                               ' for p2wpkh-p2sh')

        sub_d = WPKHDescriptor(pubk_prov)
        d = SHDescriptor(sub_d)
        part_txin.script_descriptor = d
        part_txin.witness_utxo = prevout_o
    else:
        jmman.logger.debug(f'verify_txin_sig: unknown script_type'
                           f' {script_type}')
        return False

    pre_hash = sha256d(part_tx.serialize_preimage(txin_idx))
    sig = ecc.ecdsa_sig64_from_der_sig(sig[:-1])
    return verify_signature(pubk, sig, pre_hash)


class JMStates(IntEnum):
    '''JMManager states'''
    Unsupported = 0         # JM is unsupported on this wallet
    Disabled = 1            # JM is disabled yet
    Ready = 3               # Ready to mixing
    Mixing = 4              # Mixing is running


class KPStates(IntEnum):
    '''Keypairs cache states'''
    Empty = 0
    Ready = 1


class JMGUILogHandler(logging.Handler):
    '''Write log to maxsize limited queue'''

    def __init__(self, jmman):
        super(JMGUILogHandler, self).__init__()
        self.shortcut = jmman.LOGGING_SHORTCUT
        self.jmman = jmman
        self.jmman_id = id(jmman)
        self.head = 0
        self.tail = 0
        self.log = dict()
        jmman.logger.addHandler(self)
        self.setLevel(logging.DEBUG)
        self.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        self.notify = False

    def handle(self, record):
        if (not hasattr(record, 'jmman_id')
                or record.jmman_id != self.jmman_id):
            return False
        self.log[self.tail] = record
        self.tail += 1
        if self.tail - self.head > 1000:
            self.clear_log(100)
        if self.notify:
            self.jmman.postpone_notification('jm_log_changes', self.jmman)
        return True

    def clear_log(self, count=0):
        head = self.head
        if not count:
            count = self.tail - head
        for i in range(head, head+count):
            self.log.pop(i, None)
        self.head = head + count
        if self.notify:
            self.jmman.postpone_notification('jm_log_changes', self.jmman)


@attr.s
class JMAddress:
    mixdepth = attr.ib(type=int)
    branch = attr.ib(type=int)
    index = attr.ib(type=tuple)


@attr.s
class JMUtxo:
    addr = attr.ib(type=str)
    value = attr.ib(type=int)
    mixdepth = attr.ib(type=int)
