# -*- coding: utf-8 -*-

import binascii
from functools import wraps


# JoinMarket version
JM_CORE_VERSION = '0.9.12dev'

# global Joinmarket constants
JM_APP_NAME = "joinmarket"


# hex/binary conversion routines used by dependent packages
def hextobin(h):
    """Convert a hex string to bytes"""
    return binascii.unhexlify(h.encode('utf8'))


def bintohex(b):
    """Convert bytes to a hex string"""
    return binascii.hexlify(b).decode('utf8')


def utxostr_to_utxo(x):
    if not isinstance(x, str):
        return (False, "not a string")
    y = x.split(":")
    if len(y) != 2:
        return (False,
                "string is not two items separated by :")
    try:
        n = int(y[1])
    except BaseException:
        return (False, "utxo index was not an integer.")
    if n < 0:
        return (False, "utxo index must not be negative.")
    if len(y[0]) != 64:
        return (False, "txid is not 64 hex characters.")
    try:
        txid = binascii.unhexlify(y[0])
    except BaseException:
        return (False, "txid is not hex.")
    return (True, (txid, n))


def utxo_to_utxostr(u):
    if not isinstance(u, tuple):
        return (False, "utxo is not a tuple.")
    if not len(u) == 2:
        return (False, "utxo should have two elements.")
    if not isinstance(u[0], bytes):
        return (False, "txid should be bytes.")
    if not isinstance(u[1], int):
        return (False, "index should be int.")
    if u[1] < 0:
        return (False, "index must be a positive integer.")
    if not len(u[0]) == 32:
        return (False, "txid must be 32 bytes.")
    txid = binascii.hexlify(u[0]).decode("ascii")
    return (True, txid + ":" + str(u[1]))


def chunks(d, n):
    return [d[x:x + n] for x in range(0, len(d), n)]


# helper functions for conversions of format between over-the-wire JM
# and internal. See details in hexbin() docstring.

def _convert(x):
    good, utxo = utxostr_to_utxo(x)
    if good:
        return utxo
    else:
        try:
            b = hextobin(x)
            return b
        except BaseException:
            return x


def listchanger(list_data):
    rlist = []
    for x in list_data:
        if isinstance(x, list):
            rlist.append(listchanger(x))
        elif isinstance(x, dict):
            rlist.append(dictchanger(x))
        else:
            rlist.append(_convert(x))
    return rlist


def dictchanger(dict_data):
    rdict = {}
    for k, v in dict_data.items():
        if isinstance(v, dict):
            rdict[_convert(k)] = dictchanger(v)
        elif isinstance(v, list):
            rdict[_convert(k)] = listchanger(v)
        else:
            rdict[_convert(k)] = _convert(v)
    return rdict


def hexbin(func):
    """ Decorator for functions of taker and maker receiving over
    the wire AMP arguments that may be in hex or hextxid:n format
    and converting all to binary.
    Functions to which this decorator applies should have all arguments
    be one of:
    - hex string (keys), converted here to binary
    - lists of keys or txid:n strings (converted here to binary, or
      (txidbytes, n))
    - lists of lists or dicts, to which these rules apply recursively.
    - any other string (unchanged)
    - dicts with keys as per above; values are altered recursively according
      to the rules above.
    """
    @wraps(func)
    def func_wrapper(inst, *args, **kwargs):
        newargs = []
        for arg in args:
            if isinstance(arg, (list, tuple)):
                newargs.append(listchanger(arg))
            elif isinstance(arg, dict):
                newargs.append(dictchanger(arg))
            else:
                newargs.append(_convert(arg))
        return func(inst, *newargs, **kwargs)

    return func_wrapper


def async_hexbin(func):

    @wraps(func)
    async def func_wrapper(inst, *args, **kwargs):
        newargs = []
        for arg in args:
            if isinstance(arg, (list, tuple)):
                newargs.append(listchanger(arg))
            elif isinstance(arg, dict):
                newargs.append(dictchanger(arg))
            else:
                newargs.append(_convert(arg))
        return await func(inst, *newargs, **kwargs)

    return func_wrapper
