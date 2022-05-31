# -*- coding: utf-8 -*-

import base64
import secrets
import binascii

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,
                                                              X25519PublicKey)
from cryptography.hazmat.primitives.poly1305 import Poly1305

from electrum.util import to_bytes


MASK_8 = 0xff         # 8-bit mask
MASK_32 = 0xffffffff  # 32-bit mask
LE_BO = 'little'      # byte order


# CryptoBox code
CRYPTO_BOX_NONCEBYTES = 24
CRYPTO_BOX_BEFORENMBYTES = 32
CRYPTO_BOX_BOXZEROBYTES = 16
CRYPTO_BOX_MACBYTES = 16
CRYPTO_BOX_ZEROBYTES = CRYPTO_BOX_BOXZEROBYTES + CRYPTO_BOX_MACBYTES


def _rotl32(w, r):
    return (((w << r) & MASK_32) | (w >> (32 - r)))


def _littleendian(b):
    assert len(b) == 4
    return b[0] ^ (b[1] << 8) ^ (b[2] << 16) ^ (b[3] << 24)


def core_salsa20(data: bytes, key: bytes, c: bytes = b''):
    assert len(data) == 16, f'data length not 16 bytes: {len(data)}'
    assert len(key) == 32, f'key length not 32 bytes: {len(key)}'
    assert not c or len(c) == 16, f'c length not 16 bytes: {len(c)}'
    return core_salsa(data, key, c, 20)


def core_salsa(data: bytes, key: bytes, c: bytes = b'', rounds: int = 20):
    if c:
        assert len(c) == 16, f'c length not 32 bytes: {len(key)}'
        j0 = x0 = _littleendian(c[0:4])
        j5 = x5 = _littleendian(c[4:8])
        j10 = x10 = _littleendian(c[8:12])
        j15 = x15 = _littleendian(c[12:16])
    else:
        j0 = x0 = 0x61707865
        j5 = x5 = 0x3320646e
        j10 = x10 = 0x79622d32
        j15 = x15 = 0x6b206574

    j1 = x1 = _littleendian(key[0:4])
    j2 = x2 = _littleendian(key[4:8])
    j3 = x3 = _littleendian(key[8:12])
    j4 = x4 = _littleendian(key[12:16])
    j11 = x11 = _littleendian(key[16:20])
    j12 = x12 = _littleendian(key[20:24])
    j13 = x13 = _littleendian(key[24:28])
    j14 = x14 = _littleendian(key[28:32])

    j6 = x6 = _littleendian(data[0:4])
    j7 = x7 = _littleendian(data[4:8])
    j8 = x8 = _littleendian(data[8:12])
    j9 = x9 = _littleendian(data[12:16])

    for i in range(0, 20, 2):
        x4 ^= _rotl32((x0 + x12) & MASK_32, 7)
        x8 ^= _rotl32((x4 + x0) & MASK_32, 9)
        x12 ^= _rotl32((x8 + x4) & MASK_32, 13)
        x0 ^= _rotl32((x12 + x8) & MASK_32, 18)
        x9 ^= _rotl32((x5 + x1) & MASK_32, 7)
        x13 ^= _rotl32((x9 + x5) & MASK_32, 9)
        x1 ^= _rotl32((x13 + x9) & MASK_32, 13)
        x5 ^= _rotl32((x1 + x13) & MASK_32, 18)
        x14 ^= _rotl32((x10 + x6) & MASK_32, 7)
        x2 ^= _rotl32((x14 + x10) & MASK_32, 9)
        x6 ^= _rotl32((x2 + x14) & MASK_32, 13)
        x10 ^= _rotl32((x6 + x2) & MASK_32, 18)
        x3 ^= _rotl32((x15 + x11) & MASK_32, 7)
        x7 ^= _rotl32((x3 + x15) & MASK_32, 9)
        x11 ^= _rotl32((x7 + x3) & MASK_32, 13)
        x15 ^= _rotl32((x11 + x7) & MASK_32, 18)
        x1 ^= _rotl32((x0 + x3) & MASK_32, 7)
        x2 ^= _rotl32((x1 + x0) & MASK_32, 9)
        x3 ^= _rotl32((x2 + x1) & MASK_32, 13)
        x0 ^= _rotl32((x3 + x2) & MASK_32, 18)
        x6 ^= _rotl32((x5 + x4) & MASK_32, 7)
        x7 ^= _rotl32((x6 + x5) & MASK_32, 9)
        x4 ^= _rotl32((x7 + x6) & MASK_32, 13)
        x5 ^= _rotl32((x4 + x7) & MASK_32, 18)
        x11 ^= _rotl32((x10 + x9) & MASK_32, 7)
        x8 ^= _rotl32((x11 + x10) & MASK_32, 9)
        x9 ^= _rotl32((x8 + x11) & MASK_32, 13)
        x10 ^= _rotl32((x9 + x8) & MASK_32, 18)
        x12 ^= _rotl32((x15 + x14) & MASK_32, 7)
        x13 ^= _rotl32((x12 + x15) & MASK_32, 9)
        x14 ^= _rotl32((x13 + x12) & MASK_32, 13)
        x15 ^= _rotl32((x14 + x13) & MASK_32, 18)

    return (((x0 + j0) & MASK_32).to_bytes(4, LE_BO) +
            ((x1 + j1) & MASK_32).to_bytes(4, LE_BO) +
            ((x2 + j2) & MASK_32).to_bytes(4, LE_BO) +
            ((x3 + j3) & MASK_32).to_bytes(4, LE_BO) +
            ((x4 + j4) & MASK_32).to_bytes(4, LE_BO) +
            ((x5 + j5) & MASK_32).to_bytes(4, LE_BO) +
            ((x6 + j6) & MASK_32).to_bytes(4, LE_BO) +
            ((x7 + j7) & MASK_32).to_bytes(4, LE_BO) +
            ((x8 + j8) & MASK_32).to_bytes(4, LE_BO) +
            ((x9 + j9) & MASK_32).to_bytes(4, LE_BO) +
            ((x10 + j10) & MASK_32).to_bytes(4, LE_BO) +
            ((x11 + j11) & MASK_32).to_bytes(4, LE_BO) +
            ((x12 + j12) & MASK_32).to_bytes(4, LE_BO) +
            ((x13 + j13) & MASK_32).to_bytes(4, LE_BO) +
            ((x14 + j14) & MASK_32).to_bytes(4, LE_BO) +
            ((x15 + j15) & MASK_32).to_bytes(4, LE_BO))


def core_hsalsa20(k: bytes, nonce: bytes = b'\x00'*16):
    '''produces 256-bits of output suitable for use as a Salsa20 key'''
    assert len(k) == 32, f'key length not 32 bytes: {len(k)}'
    assert len(nonce) == 16, f'nonce length not 16 bytes: {len(nonce)}'
    x0 = 0x61707865
    x1 = (k[0] | k[1] << 8 | k[2] << 16 | k[3] << 24) & MASK_32
    x2 = (k[4] | k[5] << 8 | k[6] << 16 | k[7] << 24) & MASK_32
    x3 = (k[8] | k[9] << 8 | k[10] << 16 | k[11] << 24) & MASK_32
    x4 = (k[12] | k[13] << 8 | k[14] << 16 | k[15] << 24) & MASK_32
    x5 = 0x3320646e
    x6 = (nonce[0] | nonce[1] << 8 |
          nonce[2] << 16 | nonce[3] << 24) & MASK_32
    x7 = (nonce[4] | nonce[5] << 8 |
          nonce[6] << 16 | nonce[7] << 24) & MASK_32
    x8 = (nonce[8] | nonce[9] << 8 |
          nonce[10] << 16 | nonce[11] << 24) & MASK_32
    x9 = (nonce[12] | nonce[13] << 8 |
          nonce[14] << 16 | nonce[15] << 24) & MASK_32
    x10 = 0x79622d32
    x11 = (k[16] | k[17] << 8 | k[18] << 16 | k[19] << 24) & MASK_32
    x12 = (k[20] | k[21] << 8 | k[22] << 16 | k[23] << 24) & MASK_32
    x13 = (k[24] | k[25] << 8 | k[26] << 16 | k[27] << 24) & MASK_32
    x14 = (k[28] | k[29] << 8 | k[30] << 16 | k[31] << 24) & MASK_32
    x15 = 0x6b206574

    for i in range(0, 20, 2):
        u = (x0 + x12) & MASK_32
        x4 ^= (u << 7 | u >> (32-7)) & MASK_32
        u = (x4 + x0) & MASK_32
        x8 ^= (u << 9 | u >> (32-9)) & MASK_32
        u = (x8 + x4) & MASK_32
        x12 ^= (u << 13 | u >> (32-13)) & MASK_32
        u = (x12 + x8) & MASK_32
        x0 ^= (u << 18 | u >> (32-18)) & MASK_32

        u = (x5 + x1) & MASK_32
        x9 ^= (u << 7 | u >> (32-7)) & MASK_32
        u = (x9 + x5) & MASK_32
        x13 ^= (u << 9 | u >> (32-9)) & MASK_32
        u = (x13 + x9) & MASK_32
        x1 ^= (u << 13 | u >> (32-13)) & MASK_32
        u = (x1 + x13) & MASK_32
        x5 ^= (u << 18 | u >> (32-18)) & MASK_32

        u = (x10 + x6) & MASK_32
        x14 ^= (u << 7 | u >> (32-7)) & MASK_32
        u = (x14 + x10) & MASK_32
        x2 ^= (u << 9 | u >> (32-9)) & MASK_32
        u = (x2 + x14) & MASK_32
        x6 ^= (u << 13 | u >> (32-13)) & MASK_32
        u = (x6 + x2) & MASK_32
        x10 ^= (u << 18 | u >> (32-18)) & MASK_32

        u = (x15 + x11) & MASK_32
        x3 ^= (u << 7 | u >> (32-7)) & MASK_32
        u = (x3 + x15) & MASK_32
        x7 ^= (u << 9 | u >> (32-9)) & MASK_32
        u = (x7 + x3) & MASK_32
        x11 ^= (u << 13 | u >> (32-13)) & MASK_32
        u = (x11 + x7) & MASK_32
        x15 ^= (u << 18 | u >> (32-18)) & MASK_32

        u = (x0 + x3) & MASK_32
        x1 ^= (u << 7 | u >> (32-7)) & MASK_32
        u = (x1 + x0) & MASK_32
        x2 ^= (u << 9 | u >> (32-9)) & MASK_32
        u = (x2 + x1) & MASK_32
        x3 ^= (u << 13 | u >> (32-13)) & MASK_32
        u = (x3 + x2) & MASK_32
        x0 ^= (u << 18 | u >> (32-18)) & MASK_32

        u = (x5 + x4) & MASK_32
        x6 ^= (u << 7 | u >> (32-7)) & MASK_32
        u = (x6 + x5) & MASK_32
        x7 ^= (u << 9 | u >> (32-9)) & MASK_32
        u = (x7 + x6) & MASK_32
        x4 ^= (u << 13 | u >> (32-13)) & MASK_32
        u = (x4 + x7) & MASK_32
        x5 ^= (u << 18 | u >> (32-18)) & MASK_32

        u = (x10 + x9) & MASK_32
        x11 ^= (u << 7 | u >> (32-7)) & MASK_32
        u = (x11 + x10) & MASK_32
        x8 ^= (u << 9 | u >> (32-9)) & MASK_32
        u = (x8 + x11) & MASK_32
        x9 ^= (u << 13 | u >> (32-13)) & MASK_32
        u = (x9 + x8) & MASK_32
        x10 ^= (u << 18 | u >> (32-18)) & MASK_32

        u = (x15 + x14) & MASK_32
        x12 ^= (u << 7 | u >> (32-7)) & MASK_32
        u = (x12 + x15) & MASK_32
        x13 ^= (u << 9 | u >> (32-9)) & MASK_32
        u = (x13 + x12) & MASK_32
        x14 ^= (u << 13 | u >> (32-13)) & MASK_32
        u = (x14 + x13) & MASK_32
        x15 ^= (u << 18 | u >> (32-18)) & MASK_32

    return (x0.to_bytes(4, LE_BO) +
            x5.to_bytes(4, LE_BO) +
            x10.to_bytes(4, LE_BO) +
            x15.to_bytes(4, LE_BO) +
            x6.to_bytes(4, LE_BO) +
            x7.to_bytes(4, LE_BO) +
            x8.to_bytes(4, LE_BO) +
            x9.to_bytes(4, LE_BO))


def stream_salsa20(clen: int, nonce: bytes, key: bytes):
    assert len(nonce) == 8, f'nonce length not 8 bytes: {len(nonce)}'
    assert len(key) == 32, f'key length not 32 bytes: {len(key)}'
    data = bytearray(nonce + b'\x00'*8)
    res = b''

    while clen >= 64:
        res += core_salsa20(bytes(data), key)
        clen -= 64
        u = 1
        for i in range(8, 16):
            u += data[i]
            data[i] = u & MASK_8
            u >>= 8

    if clen > 0:
        res += core_salsa20(bytes(data), key)[:clen]
    return res


def stream_xsalsa20(clen: int, nonce: bytes, key: bytes):
    assert len(nonce) == 24, f'nonce length not 24 bytes: {len(nonce)}'
    assert len(key) == 32, f'key length not 32 bytes: {len(key)}'
    subkey = core_hsalsa20(key, nonce[:16])
    return stream_salsa20(clen, nonce[16:], subkey)[:clen]


def stream_salsa20_xor_ic(msg: bytes, nonce: bytes, ic: int, key: bytes):
    assert len(nonce) == 8, f'nonce length not 8 bytes: {len(nonce)}'
    assert len(key) == 32, f'key length not 32 bytes: {len(key)}'
    mlen = len(msg)
    data = bytearray(nonce + ic.to_bytes(8, LE_BO))
    res = bytearray([0]*mlen)

    offset = 0
    while mlen >= 64:
        block = core_salsa20(bytes(data), key)
        for i in range(64):
            res[offset+i] = msg[offset+i] ^ block[i]
        offset += 64
        mlen -= 64

        u = 1
        for i in range(8, 16):
            u += data[i]
            data[i] = u & MASK_8
            u >>= 8

    if mlen > 0:
        block = core_salsa20(bytes(data), key)
        for i in range(mlen):
            res[offset+i] = msg[offset+i] ^ block[i]
    return bytes(res)


def stream_xsalsa20_xor_ic(msg: bytes, nonce: bytes, ic: int, key: bytes):
    assert len(nonce) == 24, f'nonce length not 24 bytes: {len(nonce)}'
    assert len(key) == 32, f'key length not 32 bytes: {len(key)}'
    subkey = core_hsalsa20(key, nonce[:16])
    return stream_salsa20_xor_ic(msg, nonce[16:], ic, subkey)


def stream_xsalsa20_xor(msg: bytes, nonce: bytes, key: bytes):
    assert len(nonce) == 24, f'nonce length not 24 bytes: {len(nonce)}'
    assert len(key) == 32, f'key length not 32 bytes: {len(key)}'
    return stream_xsalsa20_xor_ic(msg, nonce, 0, key)


def secretbox_xsalsa20poly1305(msg: bytes, nonce: bytes, key: bytes):
    assert len(msg) >= 32, f'msg length less than 32 bytes: {len(msg)}'
    assert len(nonce) == 24, f'nonce length not 24 bytes: {len(nonce)}'
    assert len(key) == 32, f'key length not 32 bytes: {len(key)}'
    c = stream_xsalsa20_xor(msg, nonce, key)
    p = Poly1305(c[:32])
    p.update(c[32:])
    a = p.finalize()
    return b'\x00' * 16 + a + c[32:]


def secretbox_xsalsa20poly1305_open(ctxt: bytes, nonce: bytes, key: bytes):
    assert len(ctxt) >= 32, f'ctxt length less than 32 bytes: {len(ctxt)}'
    assert len(nonce) == 24, f'nonce length not 24 bytes: {len(nonce)}'
    assert len(key) == 32, f'key length not 32 bytes: {len(key)}'
    subkey = stream_xsalsa20(32, nonce, key)
    p = Poly1305(subkey)
    p.update(ctxt[32:])
    p.verify(ctxt[16:32])
    msg = stream_xsalsa20_xor(ctxt, nonce, key)
    return b'\x00' * 32 + msg[32:]


box_curve25519xsalsa20poly1305_afternm = secretbox_xsalsa20poly1305
box_curve25519xsalsa20poly1305_open_afternm = secretbox_xsalsa20poly1305_open


def crypto_box_afternm(msg: bytes, nonce: bytes, key: bytes):
    assert len(nonce) == 24, f'nonce length not 24 bytes: {len(nonce)}'
    assert len(key) == 32, f'key length not 32 bytes: {len(key)}'
    pad = b'\x00' * CRYPTO_BOX_ZEROBYTES + msg
    ctxt = box_curve25519xsalsa20poly1305_afternm(pad, nonce, key)
    return ctxt[CRYPTO_BOX_BOXZEROBYTES:]


def crypto_box_open_afternm(ctxt: bytes, nonce: bytes, key: bytes):
    assert len(nonce) == 24, f'nonce length not 24 bytes: {len(nonce)}'
    assert len(key) == 32, f'key length not 32 bytes: {len(key)}'
    pad = b'\x00' * CRYPTO_BOX_BOXZEROBYTES + ctxt
    msg = box_curve25519xsalsa20poly1305_open_afternm(pad, nonce, key)
    return msg[CRYPTO_BOX_ZEROBYTES:]


class CryptoBox:

    def __init__(self, sec, pub):
        assert isinstance(sec, X25519PrivateKey), type(sec)
        assert isinstance(pub, X25519PublicKey), type(pub)
        self._k = core_hsalsa20(sec.exchange(pub))

    def encrypt(self, msg, nonce=None, pack_nonce=True):
        if nonce is None:
            nonce = secrets.token_bytes(nbytes=CRYPTO_BOX_NONCEBYTES)
        elif len(nonce) != CRYPTO_BOX_NONCEBYTES:
            raise ValueError('Invalid nonce size')
        ctxt = crypto_box_afternm(to_bytes(msg), nonce, self._k)
        if pack_nonce:
            return nonce + ctxt
        else:
            return nonce, ctxt

    def decrypt(self, ctxt, nonce=None):
        if nonce is None:
            nonce = ctxt[:CRYPTO_BOX_NONCEBYTES]
            ctxt = ctxt[CRYPTO_BOX_NONCEBYTES:]
        elif len(nonce) != CRYPTO_BOX_NONCEBYTES:
            raise ValueError('Invalid nonce')
        msg = crypto_box_open_afternm(ctxt, nonce, self._k)
        return msg


class X25519Error(Exception):
    pass


def init_keypair(fname=None):
    """Create a new encryption
    keypair; The keypair object
    is returned.
    """
    kp = X25519PrivateKey.generate()
    return kp


# the next two functions are useful
# for exchaging pubkeys with counterparty
def get_pubkey(kp, as_hex=False):
    """Given a keypair object,
    return its public key,
    optionally in hex."""
    if not isinstance(kp, X25519PrivateKey):
        raise X25519Error("Object is not a X25519PrivateKey")
    pubk = kp.public_key()
    pubk_hex = pubk.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return pubk_hex if as_hex else pubk


def init_pubkey(hexpk, fname=None):
    """Create a pubkey object from a
    hex formatted string.
    """
    try:
        bin_pk = binascii.unhexlify(hexpk)
    except (TypeError, binascii.Error):
        raise X25519Error("Invalid hex")
    if not len(bin_pk) == 32:
        raise X25519Error("Public key must be 32 bytes")
    pk = X25519PublicKey.from_public_bytes(bin_pk)
    return pk


def as_init_encryption(kp, c_pk):
    """Given an initialised
    keypair kp and a counterparty
    pubkey c_pk, create a Box
    ready for encryption/decryption.
    """
    if not isinstance(c_pk, X25519PublicKey):
        raise X25519Error("Object is not a public key")
    if not isinstance(kp, X25519PrivateKey):
        raise X25519Error("Object is not a X25519PrivateKey")
    return CryptoBox(kp, c_pk)


'''
After initialisation, it's possible
to use the box object returned from
as_init_encryption to directly change
from plaintext to ciphertext:
    ciphertext = box.encrypt(plaintext)
    plaintext = box.decrypt(ciphertext)
Notes:
 1. use binary format for ctext/ptext
 2. Nonce is handled at the implementation layer.
'''


# TODO: Sign, verify. At the moment we are using
# bitcoin signatures so it isn't necessary.


# encoding for passing over the wire
def encrypt_encode(msg, box):
    encrypted = box.encrypt(msg)
    return base64.b64encode(encrypted).decode('ascii')


def decode_decrypt(msg, box):
    decoded = base64.b64decode(msg)
    return box.decrypt(decoded)
