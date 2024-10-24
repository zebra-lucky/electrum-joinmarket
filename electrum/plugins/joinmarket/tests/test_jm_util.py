# -*- coding: utf-8 -*-

import os

import electrum_ecc as ecc
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from electrum.bitcoin import sha256
from electrum.transaction import Transaction
from electrum.util import to_bytes, bfh

from electrum.plugins.joinmarket.jm_util import verify_txin_sig
from electrum.plugins.joinmarket.jmbase import utxostr_to_utxo, utxo_to_utxostr
from electrum.plugins.joinmarket.jmclient import (
    PoDLE, getNUMS, getP2, PoDLEError)
from electrum.plugins.joinmarket.jmbitcoin import (
    N, multiply, add_pubkeys, getG)
from electrum.plugins.joinmarket.jmdaemon.enc_wrapper import (
    core_salsa20, core_hsalsa20, stream_salsa20, stream_xsalsa20_xor,
    stream_salsa20_xor_ic, stream_xsalsa20, stream_xsalsa20_xor_ic, core_salsa,
    secretbox_xsalsa20poly1305_open, secretbox_xsalsa20poly1305, CryptoBox,
    crypto_box_afternm, crypto_box_open_afternm, CRYPTO_BOX_ZEROBYTES,
    encrypt_encode, decode_decrypt)

from electrum.plugins.joinmarket.tests import JMTestCase


class CryptoBoxTestCase(JMTestCase):

    async def test_core_salsa(self):
        data = b'\x01\x02\x03\x04' * 4
        key = b'\x05\x06\x07\x08' * 8
        c = b'\x04\x03\x02\x01' * 4
        wrong_c = c + b'\x05'
        res = bfh('9a357b4b062d7b74bd21b3937ee4bc94'
                  '525ed648acae612f5bf6f3059274f38e'
                  '14c6badf679f1e1bbeed6b8fc508f1ec'
                  'ea0d45359bf6b272e5765309ec9b0111')
        c_res = bfh('fd0777b560a17196022d48b3b1071c93'
                    '15f7bda24c314cfc148d648a7265d317'
                    '87635683536168977f890626f9998e2e'
                    '8c3416edcfd15e022b887d1ff940f7d9')
        assert core_salsa(data, key, b'') == res
        assert core_salsa(data, key, c) == c_res
        with self.assertRaises(AssertionError):
            assert core_salsa(data, key, wrong_c)

    async def test_core_salsa20(self):
        key = bytes(range(1, 33))
        nonce = bytes([3, 1, 4, 1, 5, 9, 2, 6])
        block_counter = bytes([7, 0, 0, 0, 0, 0, 0, 0])
        s_int = [0xb9a205a3, 0x0695e150, 0xaa94881a, 0xadb7b12c,
                 0x798942d4, 0x26107016, 0x64edb1a4, 0x2d27173f,
                 0xb1c7f1fa, 0x62066edc, 0xe035fa23, 0xc4496f04,
                 0x2131e6b3, 0x810bde28, 0xf62cb407, 0x6bdede3d]

        s = b''.join([s.to_bytes(4, 'little') for s in s_int])
        assert core_salsa20(nonce + block_counter, key) == s

    async def test_core_hsalsa20(self):
        sk1_hex = ('f4bd945d9554aeadaf589d4bd93c00a7'
                   '06a3bce1b9d21e1748d70ae06d334349')
        sk2_hex = ('4d4cd62cb727351f273d6e999bc8f99d'
                   '8e14c95fedcce9591e2500eefb786147')
        shared_hex = ('3b6bd938b8b43f23a8530b291e76c2b5'
                      '08932421875487785266dfa6ec49a948')
        k_hex = ('1f2d9875e1dacd7642257a1318595e9c'
                 '0588f313b79ef263905769c4d44618c7')
        k2_hex = ('81514eb8a907a83980ebefac8c824eff'
                  '7853698dfea8bde2324484bd2f140ed5')
        sk1 = X25519PrivateKey.from_private_bytes(bfh(sk1_hex))
        sk2 = X25519PrivateKey.from_private_bytes(bfh(sk2_hex))
        assert sk1.exchange(sk2.public_key()) == bfh(shared_hex)
        assert core_hsalsa20(bfh(shared_hex)) == bfh(k_hex)
        assert core_hsalsa20(bfh(shared_hex), nonce=b'\xff'*16) == bfh(k2_hex)

    async def test_stream_salsa20(self):
        nonce = bytes([3, 1, 4, 1, 5, 9, 2, 6])
        key = bytes(range(1, 33))
        s_hex = ('6ebcbdbf76fccc64ab05542bee8a67cb'
                 'c28fa2e141fbefbb3a2f9b221909c8d7')
        s_hex_128 = ('6ebcbdbf76fccc64ab05542bee8a67cb'
                     'c28fa2e141fbefbb3a2f9b221909c8d7'
                     'd4295258cb539770dd24d7ac3443769f'
                     'fa27a50e60644264dc8b6b612683372e'
                     '085d0a12bf240b189ce2b78289862b56'
                     'fdc9fcffc33bef9325a2e81b98fb3fb9'
                     'aa04cf434615ceffeb985c1cb08d8440'
                     'e90b1d56ddeaea16d9e15affff1f698c')
        assert stream_salsa20(32, nonce, key) == bfh(s_hex)
        assert stream_salsa20(128, nonce, key) == bfh(s_hex_128)

    async def test_stream_xsalsa20(self):
        nonce = bytes([3, 1, 4, 1, 5, 9, 2, 6]*3)
        key = bytes(range(1, 33))
        s_hex = ('6f0b37b2a23c7d05b66ca1cc5785723f'
                 '125b295e69497d07d4e7e72c0ed79e0e')
        assert stream_xsalsa20(32, nonce, key) == bfh(s_hex)

    async def test_stream_salsa20_xor_ic(self):
        msg = to_bytes('test_msg ' * 10)
        nonce = bytes([3, 1, 4, 1, 5, 9, 2, 6])
        ic = 0
        key = bytes(range(1, 33))
        s_hex = ('1ad9cecb2991bf038b7131589ad50ab8a5afd684328fb0'
                 'd64948bb567c7abc88b95a3578bf36e4048249a4cb1437'
                 '13ec8e78c87d07443601afff340c55e4175a6d2e7e4dd2'
                 '576c38e887c4f6d6eb5831ddbd998cb76482e04282')
        assert stream_salsa20_xor_ic(msg, nonce, ic, key) == bfh(s_hex)

    async def test_stream_xsalsa20_xor_ic(self):
        msg = to_bytes('test_msg ' * 10)
        nonce = bytes([3, 1, 4, 1, 5, 9, 2, 6]*3)
        ic = 0
        key = bytes(range(1, 33))
        s_hex = ('1b6e44c6fd510e629618c4bf23da1f4c757b5d3b1a3d22'
                 '6aa780c7586ba4ea51c389c2282f37bfe617d6147a8fb9'
                 '8110d35abbaf91a69f0e326ec82564362b00fe949fae0c'
                 'c2037d96cc9829be8c807cb3c5a86c1c190ac90ae2')
        assert stream_xsalsa20_xor_ic(msg, nonce, ic, key) == bfh(s_hex)

    async def test_stream_xsalsa20_xor(self):
        msg = to_bytes('test_msg ' * 10)
        nonce = bytes([3, 1, 4, 1, 5, 9, 2, 6]*3)
        key = bytes(range(1, 33))
        s_hex = ('1b6e44c6fd510e629618c4bf23da1f4c757b5d3b1a3d22'
                 '6aa780c7586ba4ea51c389c2282f37bfe617d6147a8fb9'
                 '8110d35abbaf91a69f0e326ec82564362b00fe949fae0c'
                 'c2037d96cc9829be8c807cb3c5a86c1c190ac90ae2')
        assert stream_xsalsa20_xor(msg, nonce, key) == bfh(s_hex)

    async def test_secretbox_xsalsa20poly1305(self):
        msg = to_bytes('test_msg ' * 10)
        nonce = bytes([3, 1, 4, 1, 5, 9, 2, 6]*3)
        key = bytes(range(1, 33))
        pad = b'\x00' * CRYPTO_BOX_ZEROBYTES
        s_hex = ('00000000000000000000000000000000046cebaf04688d6a42dcec49f0'
                 '72e6e0da9fd67c043fbff568cf026edb928910c025a2b985f2b406327d'
                 'b73c72227f2bf6948cd115d41729bdc4983ac1959668e7eea06c0f6613'
                 'df1eb6ccd93e1827c769410c084bf7d628bb63f34ddda70914b390ee45'
                 '229e2d85df36')
        assert secretbox_xsalsa20poly1305(pad+msg, nonce, key) == bfh(s_hex)

    async def test_secretbox_xsalsa20poly1305_open(self):
        msg = to_bytes('test_msg ' * 10)
        nonce = bytes([3, 1, 4, 1, 5, 9, 2, 6]*3)
        key = bytes(range(1, 33))
        pad = b'\x00' * CRYPTO_BOX_ZEROBYTES
        ctxt = ('00000000000000000000000000000000046cebaf04688d6a42dcec49f0'
                '72e6e0da9fd67c043fbff568cf026edb928910c025a2b985f2b406327d'
                'b73c72227f2bf6948cd115d41729bdc4983ac1959668e7eea06c0f6613'
                'df1eb6ccd93e1827c769410c084bf7d628bb63f34ddda70914b390ee45'
                '229e2d85df36')
        assert secretbox_xsalsa20poly1305_open(bfh(ctxt), nonce, key) == \
            (pad + msg)

    async def test_crypto_box_afternm(self):
        msg = to_bytes('test_msg ' * 10)
        nonce = bytes([3, 1, 4, 1, 5, 9, 2, 6]*3)
        key = bytes(range(1, 33))
        ctxt = ('046cebaf04688d6a42dcec49f072e6e0da9fd67c043fbff568cf026edb92'
                '8910c025a2b985f2b406327db73c72227f2bf6948cd115d41729bdc4983a'
                'c1959668e7eea06c0f6613df1eb6ccd93e1827c769410c084bf7d628bb63'
                'f34ddda70914b390ee45229e2d85df36')
        assert crypto_box_afternm(msg, nonce, key) == bfh(ctxt)

    async def test_crypto_box_open_afternm(self):
        msg = to_bytes('test_msg ' * 10)
        nonce = bytes([3, 1, 4, 1, 5, 9, 2, 6]*3)
        key = bytes(range(1, 33))
        ctxt = ('046cebaf04688d6a42dcec49f072e6e0da9fd67c043fbff568cf026edb92'
                '8910c025a2b985f2b406327db73c72227f2bf6948cd115d41729bdc4983a'
                'c1959668e7eea06c0f6613df1eb6ccd93e1827c769410c084bf7d628bb63'
                'f34ddda70914b390ee45229e2d85df36')
        assert crypto_box_open_afternm(bfh(ctxt), nonce, key) == msg

    async def test_CryptoBox_encrypt_decrypt(self):
        sk1_hex = ('f4bd945d9554aeadaf589d4bd93c00a7'
                   '06a3bce1b9d21e1748d70ae06d334349')
        sk2_hex = ('4d4cd62cb727351f273d6e999bc8f99d'
                   '8e14c95fedcce9591e2500eefb786147')
        k_hex = ('1f2d9875e1dacd7642257a1318595e9c'
                 '0588f313b79ef263905769c4d44618c7')
        sk1 = X25519PrivateKey.from_private_bytes(bfh(sk1_hex))
        sk2 = X25519PrivateKey.from_private_bytes(bfh(sk2_hex))
        box1 = CryptoBox(sk1, sk2.public_key())
        assert box1._k == bfh(k_hex)
        msg = to_bytes('test msg')
        ctxt = box1.encrypt(msg)
        ctxt_b64 = encrypt_encode(msg, box1)
        box2 = CryptoBox(sk2, sk1.public_key())
        with self.assertRaises(ValueError):
            assert box2.decrypt(ctxt, b'\x01\x02') == msg
        assert box2.decrypt(ctxt) == msg
        assert decode_decrypt(ctxt_b64, box2) == msg
        with self.assertRaises(ValueError):
            box1.encrypt(msg, b'\x01\x02')
        assert isinstance(box1.encrypt(msg, None, False), tuple)


class PoDLETestCase(JMTestCase):

    async def _init_all_data(self):
        txid = ('f4bd945d9554aeadaf589d4bd93c00a7'
                'f4bd945d9554aeadaf589d4bd93c00a7')
        u = (bfh(txid), 0)
        privk = ecc.ECPrivkey.generate_random_key()
        privk_bytes = privk.get_secret_bytes()
        pubk = ecc.ECPubkey(privk.get_public_key_bytes())
        pubk_bytes = pubk.get_public_key_bytes()
        J = getNUMS(0)
        J_bytes = J.get_public_key_bytes()
        k = os.urandom(32)
        k_int = int.from_bytes(k, byteorder='big')
        P2 = getP2(privk, J)
        P2_bytes = P2.get_public_key_bytes()
        KG = ecc.ECPubkey(ecc.ECPrivkey(k).get_public_key_bytes())
        KJ = multiply(k_int, J_bytes, return_serialized=False)
        e = sha256(b''.join([x.get_public_key_bytes()
                             for x in [KG, KJ, privk, P2]]))
        priv_int, e_int = (int.from_bytes(x, byteorder='big')
                           for x in [privk_bytes, e])
        sig_int = (k_int + priv_int * e_int) % N
        s = (sig_int).to_bytes(32, byteorder='big')
        return (u, privk, privk_bytes, pubk, pubk_bytes, J, J_bytes, k, k_int,
                P2, P2_bytes, KG, KJ, e, priv_int, e_int, sig_int, s)

    async def test_PoDLE_init(self):
        (u, privk, privk_bytes, pubk, pubk_bytes, J, J_bytes, k, k_int,
         P2, P2_bytes, KG, KJ, e, priv_int, e_int, sig_int, s) = \
            await self._init_all_data()
        podle = PoDLE(u=u, priv=privk_bytes, P2=P2_bytes, s=s, e=e)
        with self.assertRaises(PoDLEError):
            PoDLE(u=u, priv=privk_bytes, P=pubk_bytes, P2=P2_bytes, s=s, e=e)
        assert repr(podle)

    async def test_PoDLE_reveal(self):
        (u, privk, privk_bytes, pubk, pubk_bytes, J, J_bytes, k, k_int,
         P2, P2_bytes, KG, KJ, e, priv_int, e_int, sig_int, s) = \
            await self._init_all_data()
        podle = PoDLE(u=u, priv=privk_bytes, P2=P2_bytes, s=s, e=e)
        with self.assertRaises(PoDLEError):
            podle.s = None
            podle.reveal()

    async def test_PoDLE_get_commitment(self):
        (u, privk, privk_bytes, pubk, pubk_bytes, J, J_bytes, k, k_int,
         P2, P2_bytes, KG, KJ, e, priv_int, e_int, sig_int, s) = \
            await self._init_all_data()
        podle = PoDLE(u=u, P=pubk_bytes, P2=P2_bytes, s=s, e=e)
        podle.get_commitment()

        podle2 = PoDLE()
        with self.assertRaises(PoDLEError):
            podle2.get_commitment()
        podle2.P2 = P2_bytes
        with self.assertRaises(PoDLEError):
            podle2.get_commitment()
        podle2.P2 = P2
        podle.get_commitment()

    async def test_PoDLE_generate_podle(self):
        (u, privk, privk_bytes, pubk, pubk_bytes, J, J_bytes, k, k_int,
         P2, P2_bytes, KG, KJ, e, priv_int, e_int, sig_int, s) = \
            await self._init_all_data()
        podle = PoDLE(u=u, priv=privk_bytes)
        r = podle.generate_podle()
        assert r
        assert r['utxo']
        assert r['commit']

    async def test_PoDLE_serialize_deserialize_revelation(self):
        (u, privk, privk_bytes, pubk, pubk_bytes, J, J_bytes, k, k_int,
         P2, P2_bytes, KG, KJ, e, priv_int, e_int, sig_int, s) = \
            await self._init_all_data()
        podle = PoDLE(u=u, priv=privk_bytes)
        r1 = podle.generate_podle()
        sr = podle.serialize_revelation()
        sr_split = sr.split('|')
        assert len(sr_split) == 5
        r2 = PoDLE.deserialize_revelation(sr)
        assert r2['P'] == r1['P']
        assert r2['P2'] == r1['P2']
        assert r2['e'] == r1['e']
        assert r2['sig'] == r1['sig']
        assert r2['utxo'] == r1['utxo']
        with self.assertRaises(PoDLEError):
            r2 = PoDLE.deserialize_revelation(sr + '|00')

    async def test_PoDLE_verify(self):
        (u, privk, privk_bytes, pubk, pubk_bytes, J, J_bytes, k, k_int,
         P2, P2_bytes, KG, KJ, e, priv_int, e_int, sig_int, s) = \
            await self._init_all_data()
        podle = PoDLE(u=u, priv=privk_bytes, P2=P2_bytes, s=s, e=e)
        commitment = podle.get_commitment()
        podle2 = PoDLE(u=u, P=pubk_bytes, P2=P2_bytes, s=s, e=e)
        assert podle2.verify(commitment, [0])
        assert not podle2.verify(commitment, [1])
        assert not podle2.verify(commitment + b'\x00', [0])
        podle2.s = None
        with self.assertRaises(PoDLEError):
            podle2.verify(commitment, [0])


class PoDLEFunctionsTestCase(JMTestCase):

    async def test_utxostr_to_utxo(self):
        txid = ('f4bd945d9554aeadaf589d4bd93c00a7'
                'f4bd945d9554aeadaf589d4bd93c00a7')
        assert not utxostr_to_utxo(5)[0]                        # not a str
        assert not utxostr_to_utxo(txid)[0]                     # has no ':'
        assert not utxostr_to_utxo(f'{txid}:z')[0]              # not int n
        assert not utxostr_to_utxo(f'{txid}:-1')[0]             # n < 0
        assert not utxostr_to_utxo(f'{txid[2:]}:0')[0]          # txid len < 64
        assert not utxostr_to_utxo(f'g{txid[1:]}:0')[0]         # txid not hex
        assert utxostr_to_utxo(f'{txid}:0') == (True, (bfh(txid), 0))

    async def test_utxo_to_utxostr(self):
        txid = ('f4bd945d9554aeadaf589d4bd93c00a7'
                'f4bd945d9554aeadaf589d4bd93c00a7')
        assert not utxo_to_utxostr(f'{txid}:0')[0]              # not a tuple
        assert not utxo_to_utxostr((1, 2, 3))[0]                # utxo len != 2
        assert not utxo_to_utxostr((txid, 0))[0]                # not bytes
        assert not utxo_to_utxostr((bfh(txid), '0'))[0]         # n not int
        assert not utxo_to_utxostr((bfh(txid), -1))[0]          # n < 0
        assert not utxo_to_utxostr((bfh(txid[2:]), 0))[0]       # txid len < 32
        assert utxo_to_utxostr((bfh(txid), 0)) == (True, f'{txid}:0')

    async def test_multiply(self):
        privk = ecc.ECPrivkey.generate_random_key()
        pubk = ecc.ECPubkey(privk.get_public_key_bytes())
        pubk_bytes = pubk.get_public_key_bytes()
        assert multiply(10, pubk_bytes) == (pubk * 10).get_public_key_bytes()
        assert multiply(10, pubk_bytes, False) == (pubk * 10)

    async def test_add_pubkeys(self):
        privk1 = ecc.ECPrivkey.generate_random_key()
        pubk1 = ecc.ECPubkey(privk1.get_public_key_bytes())
        pubk1_bytes = pubk1.get_public_key_bytes()
        privk2 = ecc.ECPrivkey.generate_random_key()
        pubk2 = ecc.ECPubkey(privk2.get_public_key_bytes())
        pubk2_bytes = pubk2.get_public_key_bytes()
        privk3 = ecc.ECPrivkey.generate_random_key()
        pubk3 = ecc.ECPubkey(privk3.get_public_key_bytes())
        pubk3_bytes = pubk3.get_public_key_bytes()
        assert add_pubkeys([pubk1_bytes, pubk2_bytes, pubk3_bytes]) == \
            (pubk1 + pubk2 + pubk3).get_public_key_bytes()

    async def test_getG(self):
        assert getG() == ecc.GENERATOR.get_public_key_bytes()
        assert getG(False) == ecc.GENERATOR.get_public_key_bytes(False)

    async def test_getNUMS(self):
        for i in range(256):
            pubk = getNUMS(i)
            pubk_bytes = pubk.get_public_key_bytes()
            assert len(pubk_bytes.hex()) == 66
        with self.assertRaises(AssertionError):
            getNUMS(256)
        with self.assertRaises(AssertionError):
            getNUMS(-1)

    async def test_getP2(self):
        privk = ecc.ECPrivkey.generate_random_key()
        nums0 = getNUMS(0)
        nums0_bytes = nums0.get_public_key_bytes()
        assert getP2(privk, nums0) == multiply(privk.secret_scalar,
                                               nums0_bytes, False)


class TxUtilTestCase(JMTestCase):

    raw_tx = ('0200000002a3c3741aebeec8b8c62cb057ea549b0d3643bfebe523628b063c'
              '9db5e4c90353000000006a47304402204644617dd2b5840820f30d63cf4508'
              '26bab7437f57a45a761f9224731900338802205d4403ee8bed1741af6ad640'
              '1b529b51344e5da96f94becbc2a98d2b1f26565801210220083a2355781ff1'
              'f57bae38b8a143c058faed25fd60d90186f5c4ea8741b131feffffff96c205'
              '1bc69b2a0b2629e2df1e3c298502235a72752fbabbbd39da72334e8e810000'
              '00006a473044022014baa38694ce16a7cd00468ef1dc4afb4b2953d05030da'
              '0b7928d270c62c8ede02202cb9c751424eb826b1c3a5f09afcc04393f31d9a'
              '1d844f853adba8c0da04ddd5012102ef66d742685f5bfb22c5364f8d13c899'
              '5a9c776a9b3ad1d25e823414ab307fa5feffffff0130660000000000001976'
              'a91467e333a26ba6ebbc26067034e7d4fd5036f53e0e88ac08010900')

    prevtx = ('02000000027366833e954d625d2c7c323a33bdedba986cf3153ff1c1bd1e14'
              '3ca789278b27000000006b483045022100c36856a7341f75b6f4e36f74a2da'
              '12e19e7881abd4e29bae2e4e4587fad2bcb9022002f2e6184684d2ade510c1'
              '84c8ebdea063f8fcb65f7c17b62cf70f25915a666401210287b3a996386eb7'
              '798222ff1575b0325c3a51ccbe8aff238132b60b2a6f2bec02feffffff715f'
              '25c2d747193a26dc9085b57b49470b13b63760191206041b0839cd0b697600'
              '0000006a47304402204cb360acc74874afac4a4ecd91e96d9d6259bac05af2'
              '632096139f911fa66cf102207c83dc64f0ef3612c326dd91ad161ebd4cf0db'
              '398847ef4120b086baf9af7142012102ef66d742685f5bfb22c5364f8d13c8'
              '995a9c776a9b3ad1d25e823414ab307fa5feffffff03641900000000000019'
              '76a91467e333a26ba6ebbc26067034e7d4fd5036f53e0e88ac641900000000'
              '00001976a914c67034239c66de4b562469db89f1b834733c22c388ac19b19a'
              '3b000000001976a9149f1708ce9b84576b4b5cca5816886bb609da94b888ac'
              '00000000')

    raw_tx_native_segwit = (
        '020000000001016102df5977d8479baa63e0de187f5fb16d46da05ab26df8f6738fc'
        'dd627097420100000000feffffff0240420f0000000000160014c380cfad0316be20'
        'cc1d4bc94f7f620d8d8d74b80ca92200000000001600144c079970fecec16b29e283'
        '3bdb380767fdc2c2f402473044022074e78765a4d27279012165b8db490f4a51b129'
        'de6a7a4057563538f57cbc9566022015f5f20920c3d03eb3a3d058ca4156f03f8110'
        '69c6f107ef2218341c7fe884370121026572d52c070a27d3dacc5f085298d56d5966'
        '36cfbef9be83103ee4d0f81208b46b662200')

    prevtx_native_segwit = (
        '02000000000103c17208c443a3d3d2223884ef11ac83dadb1a3abe4d3474694414c8'
        'dcd3c697510000000000feffffffe8e58405385783c155108da5193dff0b9fd6ab60'
        '1a5e8e5c4af73d8e96af0f730000000000feffffffa2fdfbaf5fda84096b34f08afd'
        'cfb28d0d43231127f2d5d0da41831aa0e7db830100000000feffffff0260ae0a0000'
        '0000001600147a01e4c62b173c6cac94628687b6aa467adbfa2714ec310000000000'
        '160014f5dfeaace8e313a161fcb670193f38efd97b7bce0247304402205554e284e1'
        '96d6b3dc4a96cdc24f857dca68f41f65124bab91ec46251004a396022019339072cd'
        '717aac0e9e1d142e482fe7a6513593cf99521b2b861b10f471238501210242276a06'
        '847935a063f8f9973f7dea10a720152ee789c4c72fcbc64a7749f46f024730440220'
        '4b1ea07b9dd27db75d50ff35535fe7ed123aed81eba9fa41f56c3d9ec08a7b2f0220'
        '73164defcbf577c7168508bdfea8be698d2f1e09913f925459c7cb8382aa81f30121'
        '0242276a06847935a063f8f9973f7dea10a720152ee789c4c72fcbc64a7749f46f02'
        '4730440220155ddb1f9815bbdd25c86e9edda7adf88d3e9e944a08bdf41b319fc714'
        '4da95802205e022944be559f6525131d82b54f0dcf22383c2a589e7d61da4d1ac46a'
        '3e246601210242276a06847935a063f8f9973f7dea10a720152ee789c4c72fcbc64a'
        '7749f46f76832100')

    raw_tx_p2sh_segwit = (
        '02000000000101923694e55341a1065e92351464928652d107e2c7e7efa40ee7ceea'
        '665357645401000000171600147e316097bd838a8de7afa7b45ef4b2e24a90a6b7fd'
        'ffffff018a2600000000000017a914a12bfecbd723838fea79ce3d709ab09f3f46da'
        '738702473044022002ed167bdcca402715f796c015eed1cd28647c2af465abfe2867'
        '09c2a4917ad702202f41b4567c95213c65c64f754554a40550491bafc33844e0f0cc'
        'eb99e20c22740121038623a41ac0d23be7015ba711706bc23ddf385f559565a69885'
        '291d38c80c2a9d7faa2600')

    prevtx_p2sh_segwit = (
        '02000000000101bf2d2d42655d0e2cd9f282df619a22036cde72ff61d365492772a5'
        '6f32793f930100000000fdffffff021c0c0000000000001600145b058870c3f1296f'
        '71262b78be0f389110e95213102700000000000017a9147d8cbb88869840e0deaceb'
        '980a2943472f36513d870247304402200c58deeb5474d02460fff10fb96794512044'
        'bb8f5015d2ad038f3a606eb4ca6502202038a8263f71fa459cdc947897c7ddfe921a'
        'c012cd38be692903c13463034d81012102218051896d4a685aed1437eb2e982741a8'
        '2c232284158ab6edae97bc94cb0ba9abaa2600')

    async def test_verify_txin_sig(self):
        jmman = self.jmman
        txin_idx = 1
        assert verify_txin_sig(jmman, self.raw_tx, txin_idx, self.prevtx)
        txin_idx = 0
        assert verify_txin_sig(jmman, self.raw_tx_native_segwit, txin_idx,
                               self.prevtx_native_segwit)
        txin_idx = 0
        assert verify_txin_sig(jmman, self.raw_tx_p2sh_segwit, txin_idx,
                               self.prevtx_p2sh_segwit)

    async def test_verify_txin_sig_fails(self):
        prevout_idx = 0
        txin_idx = 1
        txin_idx10 = 10

        jmman = self.jmman
        assert not verify_txin_sig(jmman, self.raw_tx, txin_idx10, self.prevtx)

        prevtx = Transaction(self.prevtx)
        prevout = prevtx.outputs()[prevout_idx]
        prevout.scriptpubkey = prevout.scriptpubkey[:-1]
        prevtx = prevtx.serialize_to_network()
        assert not verify_txin_sig(jmman, self.raw_tx, txin_idx, prevtx)

        prevtx = Transaction(self.prevtx)
        prevout = prevtx.outputs()[prevout_idx]
        prevout.scriptpubkey = prevout.scriptpubkey[:-1] + b'\x00'
        prevtx = prevtx.serialize_to_network()
        assert not verify_txin_sig(jmman, self.raw_tx, txin_idx, prevtx)

        tx = Transaction(self.raw_tx)
        tx.inputs()[txin_idx].script_sig = b''
        raw_tx = tx.serialize_to_network()
        assert not verify_txin_sig(jmman, raw_tx, txin_idx, self.prevtx)

        tx = Transaction(self.raw_tx)
        script_sig = bytearray(tx.inputs()[txin_idx].script_sig)
        script_sig[0] = 70
        tx.inputs()[txin_idx].script_sig = bytes(script_sig)
        raw_tx = tx.serialize_to_network()
        assert not verify_txin_sig(jmman, raw_tx, txin_idx, self.prevtx)

        tx = Transaction(self.raw_tx)
        script_sig = tx.inputs()[txin_idx].script_sig
        tx.inputs()[txin_idx].script_sig = script_sig[:-1]
        raw_tx = tx.serialize_to_network()
        assert not verify_txin_sig(jmman, raw_tx, txin_idx, self.prevtx)

        tx = Transaction(self.raw_tx)
        script_sig = tx.inputs()[txin_idx].script_sig
        tx.inputs()[txin_idx].script_sig = script_sig[:-1] + b'\x00'
        raw_tx = tx.serialize_to_network()
        assert not verify_txin_sig(jmman, raw_tx, txin_idx, self.prevtx)

        tx = Transaction(self.raw_tx)
        script_sig = bytearray(tx.inputs()[txin_idx].script_sig)
        sighash_type_pos = 1 + script_sig[0] - 1
        script_sig[sighash_type_pos] = 127
        tx.inputs()[txin_idx].script_sig = bytes(script_sig)
        raw_tx = tx.serialize_to_network()
        assert not verify_txin_sig(jmman, raw_tx, txin_idx, self.prevtx)
