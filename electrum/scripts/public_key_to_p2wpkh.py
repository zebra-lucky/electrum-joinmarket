#!/usr/bin/env python3

import sys

from electrum import constants
from electrum.bitcoin import public_key_to_p2wpkh
from electrum.util import bfh, bh2u

IS_TESTNET = True
if IS_TESTNET:
    constants.set_testnet()

try:
    pubkey_hex = sys.argv[1]
    pubkey = bfh(pubkey_hex)
    addr = public_key_to_p2wpkh(pubkey)
    print(f'Address: {addr}')
except Exception:
    print("usage: public_key_to_p2wpkh <pubkey_hex>")
    sys.exit(1)
