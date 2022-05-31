# -*- coding: utf-8 -*-

import base64
from typing import List, Tuple, Union

from electrum import ecc
from electrum.bitcoin import sha256d, usermessage_magic
from electrum.ecc import (ECPrivkey, ECPubkey, ecdsa_der_sig_from_r_and_s,
                          ecdsa_sig64_from_der_sig)
from electrum.util import to_bytes

from ..jmbase import bintohex


"""PoDLE related primitives
"""


# Required only for PoDLE calculation
N = ecc.CURVE_ORDER


def getG(compressed=True):
    '''Returns the public key binary representation of secp256k1 G'''
    return ecc.GENERATOR.get_public_key_bytes(compressed)


podle_PublicKey_class = ECPubkey
podle_PrivateKey_class = ECPrivkey


def podle_PublicKey(P: bytes) -> ECPubkey:
    """Returns a PublicKey object from a binary string
    """
    return ECPubkey(P)


def podle_PrivateKey(priv: bytes) -> ECPrivkey:
    """Returns a PrivateKey object from a binary string
    """
    return ECPrivkey(priv)


def read_privkey(priv: bytes) -> Tuple[bool, bytes]:
    if len(priv) == 33:
        if priv[-1:] == b'\x01':
            compressed = True
        else:
            raise Exception("Invalid private key")
    elif len(priv) == 32:
        compressed = False
    else:
        raise Exception("Invalid private key")
    return (compressed, priv[:32])


def privkey_to_pubkey(priv: bytes) -> ECPubkey:
    '''Take 32/33 byte raw private key as input.
    If 32 bytes, return as uncompressed raw public key.
    If 33 bytes and the final byte is 01, return
    compresse public key. Else throws Exception.'''
    compressed, priv = read_privkey(priv)
    privk = ECPrivkey(priv)
    return ECPubkey(privk.get_public_key_bytes())


def ecdsa_sign(msg: str, priv: bytes) -> str:
    h = sha256d(usermessage_magic(to_bytes(msg)))
    sig = ecdsa_raw_sign(h, priv, rawmsg=True)
    return base64.b64encode(sig).decode('ascii')


def ecdsa_verify(msg: str, sig: str, pub: bytes) -> bool:
    h = sha256d(usermessage_magic(to_bytes(msg)))
    sig = base64.b64decode(sig)
    return ecdsa_raw_verify(h, pub, sig, rawmsg=True)


def ecdsa_raw_sign(msg: Union[bytes, bytearray],
                   priv: bytes,
                   rawmsg: bool = False) -> bytes:
    '''Take the binary message msg and sign it with the private key
    priv.
    If rawmsg is True, no sha256 hash is applied to msg before signing.
    In this case, msg must be a precalculated hash (256 bit).
    If rawmsg is False, the secp256k1 lib will hash the message as part
    of the ECDSA-SHA256 signing algo.
    Return value: the calculated signature.'''
    if rawmsg and len(msg) != 32:
        raise Exception("Invalid hash input to ECDSA raw sign.")
    compressed, p = read_privkey(priv)
    newpriv = ECPrivkey(p)
    if rawmsg:
        sig = newpriv.ecdsa_sign(msg, sigencode=ecdsa_der_sig_from_r_and_s)
    else:
        msg = sha256d(usermessage_magic(to_bytes(msg)))
        sig = newpriv.ecdsa_sign(msg, sigencode=ecdsa_der_sig_from_r_and_s)
    return sig


def ecdsa_raw_verify(msg: bytes,
                     pub: bytes,
                     sig: bytes,
                     rawmsg: bool = False) -> bool:
    '''Take the binary message msg and binary signature sig,
    and verify it against the pubkey pub.
    If rawmsg is True, no sha256 hash is applied to msg before verifying.
    In this case, msg must be a precalculated hash (256 bit).
    If rawmsg is False, the secp256k1 lib will hash the message as part
    of the ECDSA-SHA256 verification algo.
    Return value: True if the signature is valid for this pubkey, False
    otherwise.
    Since the arguments may come from external messages their content is
    not guaranteed, so return False on any parsing exception.
    '''
    try:
        sig = ecdsa_sig64_from_der_sig(sig)
        if rawmsg:
            assert len(msg) == 32
        newpub = ECPubkey(pub)
        if rawmsg:
            retval = newpub.ecdsa_verify(sig, msg)
        else:
            msg = sha256d(usermessage_magic(to_bytes(msg)))
            retval = newpub.ecdsa_verify(msg, sig)
    except Exception:
        return False
    return retval


def multiply(s: bytes, pub: bytes, return_serialized: bool = True) -> bytes:
    '''Input binary compressed pubkey P(33 bytes)
    and scalar s(32 bytes), return s*P.
    The return value is a binary compressed public key,
    or a PublicKey object if return_serialized is False.
    Note that the called function does the type checking
    of the scalar s.
    ('raw' options passed in)
    '''
    try:
        ECPrivkey(int.to_bytes(s, length=32, byteorder="big"))
    except ValueError:
        raise ValueError("Invalid tweak for libsecp256k1 "
                         "multiply: {}".format(bintohex(s)))

    pub_obj = ECPubkey(pub)
    res = pub_obj * s
    if not return_serialized:
        return res
    return res.get_public_key_bytes()


def add_pubkeys(pubkeys: List[bytes]) -> ECPubkey:
    '''Input a list of binary compressed pubkeys
    and return their sum as a binary compressed pubkey.'''
    pubkey_list = [ECPubkey(x) for x in pubkeys]
    if pubkey_list:
        r = pubkey_list[0]
        for p in pubkey_list[1:]:
            r = r + p
    return r.get_public_key_bytes()
