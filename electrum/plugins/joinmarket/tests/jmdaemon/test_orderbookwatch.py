# -*- coding: utf-8 -*-

from unittest_parametrize import parametrize, ParametrizedTestCase

from electrum.plugins.joinmarket.jmdaemon.orderbookwatch import OrderbookWatch
from electrum.plugins.joinmarket.jmdaemon import (
    IRCMessageChannel, fidelity_bond_cmd_list)
from electrum.plugins.joinmarket.jmdaemon.protocol import (
    JM_VERSION, ORDER_KEYS, FIDELITY_BOND_KEYS)
from electrum.plugins.joinmarket.jmbase.support import hextobin
from electrum.plugins.joinmarket.jmclient.fidelity_bond import (
    FidelityBondProof)

from electrum.plugins.joinmarket.tests import JMTestCase


class DummyDaemon(OrderbookWatch):

    def __init__(self, jmman):
        self.logger = jmman.logger

    def request_signature_verify(self, a, b, c, d, e, f, g, h):
        return True


class DummyMC(IRCMessageChannel):
    def __init__(self, jmman, configdata, nick, daemon):
        super().__init__(jmman, configdata)
        self.set_nick(nick)


def on_welcome(x):
    print("Simulated on-welcome")


def get_ob(jmman):
    dm = DummyDaemon(jmman)
    jmconf = jmman.jmconf
    mchannels = list(jmconf.get_msg_channels().values())
    mc = DummyMC(jmman, mchannels[0], "test", dm)
    ob = dm  # DummyDaemon based on OrderBook mixin
    ob.on_welcome = on_welcome
    ob.set_msgchan(mc)
    # would usually be set in JMInit; we use
    # a fake small value to allow small orders:
    ob.dust_threshold = 2
    return ob


class OrderBookTestCase(JMTestCase, ParametrizedTestCase):

    async def asyncSetUp(self):
        await super().asyncSetUp()

    @parametrize(
        "badtopic",
        [("abc|", ),
         ("abcd|def", ),
         ("abc| 0 a qvd", ),
         ])
    async def test_ob(self, badtopic):
        ob = get_ob(self.jmman)
        topic = (
            "JoinMarket open outcry pit. /r/joinmarket Discussion in "
            "#joinmarket| 0 5 LATEST RELEASE v0.2.2. Useful new features. "
            "Update ASAP, and do not use pre-0.2.0! https://bitcointalk.org/"
            "index.php?topic=919116.msg16714124#msg16714124")
        ob.on_set_topic(topic, self.jmman.logger)
        # should not throw:
        ob.on_set_topic(badtopic, self.jmman.logger)
        # test old version
        future_ver = str(JM_VERSION + 2)

        deprecated = topic.replace("| 0 5", "| 0 "+future_ver)
        ob.on_set_topic(deprecated, self.jmman.logger)

    @parametrize(
        ("counterparty, oid, ordertype, minsize, maxsize,"
         " txfee, cjfee, expected"),
        [
            # good absoffer
            ("test", "0", "absoffer", "3000", "4000", "2", "300", True),
            # good reloffer
            ("test", "0", "reloffer", "3000", "4000", "2", "0.3", True),
            # dusty minsize OK
            ("test", "0", "reloffer", "1000", "4000", "2", "0.3", True),
            # invalid oid
            ("test", "-2", "reloffer", "3000", "4000", "2", "0.3", False),
            # invalid minsize
            ("test", "2", "reloffer", "-3000", "4000", "2", "0.3", False),
            # invalid maxsize
            ("test", "2", "reloffer", "3000", "2200000000000000", "2", "0.3",
             False),
            # invalid txfee
            ("test", "2", "reloffer", "3000", "4000", "-1", "0.3", False),
            # min bigger than max
            ("test", "2", "reloffer", "4000", "3000", "2", "0.3", False),
            # non-integer absoffer
            ("test", "2", "absoffer", "3000", "4000", "2", "0.3", False),
            # invalid syntax for cjfee
            ("test", "2", "reloffer", "3000", "4000", "2", "0.-1", False),
            # invalid type for oid
            ("test", "xxx", "reloffer", "3000", "4000", "2", "0.3", False),
        ])
    async def test_order_seen_cancel(self, counterparty, oid, ordertype,
                                     minsize, maxsize, txfee, cjfee, expected):
        ob = get_ob(self.jmman)
        ob.on_order_seen(
            counterparty, oid, ordertype, minsize, maxsize, txfee, cjfee)
        if expected:
            # offer should now be in the orderbook
            orderbook = []
            for by_counterparty in ob.ob.values():
                for by_oid in by_counterparty.values():
                    orderbook.append(dict(zip(ORDER_KEYS, by_oid)))
            assert len(orderbook) == 1
            # test it can be removed
            ob.on_order_cancel(counterparty, oid)
            orderbook = []
            for by_counterparty in ob.ob.values():
                for by_oid in by_counterparty.values():
                    orderbook.append(dict(zip(ORDER_KEYS, by_oid)))
            assert len(orderbook) == 0

    async def test_disconnect_leave(self):
        ob = get_ob(self.jmman)
        t_orderbook = [
            {'counterparty': 'J5FA1Gj7Ln4vSGne', 'ordertype': 'reloffer',
             'oid': 0, 'minsize': 7500000, 'txfee': 1000, 'maxsize': 599972700,
             'cjfee': '0.0002'},
            {'counterparty': 'J5CFffuuewjG44UJ', 'ordertype': 'reloffer',
             'oid': 0, 'minsize': 7500000, 'txfee': 1000, 'maxsize': 599972700,
             'cjfee': '0.0002'},
            {'counterparty': 'J55z23xdjxJjC7er', 'ordertype': 'reloffer',
             'oid': 0, 'minsize': 7500000, 'txfee': 1000, 'maxsize': 599972700,
             'cjfee': '0.0002'},
            {'counterparty': 'J54Ghp5PXCdY9H3t', 'ordertype': 'reloffer',
             'oid': 0, 'minsize': 7500000, 'txfee': 1000, 'maxsize': 599972700,
             'cjfee': '0.0002'},
            {'counterparty': 'J559UPUSLLjHJpaB', 'ordertype': 'reloffer',
             'oid': 0, 'minsize': 7500000, 'txfee': 1000, 'maxsize': 599972700,
             'cjfee': '0.0002'},
            {'counterparty': 'J5cBx1FwUVh9zzoO', 'ordertype': 'reloffer',
             'oid': 0, 'minsize': 7500000, 'txfee': 1000, 'maxsize': 599972700,
             'cjfee': '0.0002'}]
        for o in t_orderbook:
            ob.on_order_seen(o['counterparty'], o['oid'], o['ordertype'],
                             o['minsize'], o['maxsize'], o['txfee'],
                             o['cjfee'])
        orderbook = []
        for by_counterparty in ob.ob.values():
            for by_oid in by_counterparty.values():
                orderbook.append(dict(zip(ORDER_KEYS, by_oid)))
        assert len(orderbook) == 6
        # simulate one cp leaves:
        ob.on_nick_leave("J5cBx1FwUVh9zzoO")
        orderbook = []
        for by_counterparty in ob.ob.values():
            for by_oid in by_counterparty.values():
                orderbook.append(dict(zip(ORDER_KEYS, by_oid)))
        assert len(orderbook) == 5
        # simulate quit
        await ob.on_disconnect()
        orderbook = []
        for by_counterparty in ob.ob.values():
            for by_oid in by_counterparty.values():
                orderbook.append(dict(zip(ORDER_KEYS, by_oid)))
        assert len(orderbook) == 0

    @parametrize(
        "valid, fidelity_bond_proof, maker_nick, taker_nick",
        [
            (
                True,
                {
                    # nicksig len = 71, certsig len = 71
                    "nick-signature":
                        b'0E\x02!\x00\xdbb\x15\x96\xa0\x87\xb8\x1d\xe05\xddV'
                        b'\xa1\x1bn\x8fq\x90&\x8cG@\x89"2\xb2\x81\x9b\xc00\xa5'
                        b'\xb6\x02 \x03\x14l\xd7BR\xba\x8c:\x88(\x8e3l\xac\xf5'
                        b'`T\x87\xfa\xf5\xa9\x1f\x19\xc0\xb6\xe9\xbb\xdc'
                        b'\xc7y\x99',
                    "certificate-signature":
                        "3045022100eb512af938113badb4d7b2"
                        "9e0c22061c51dadb113a9395e"
                        "9ed81a46103391213022029170de4149"
                        "64f07228c4f0d404b1386272b"
                        "ae337f0133f1329d948a252fa2a0",
                    "certificate-pubkey": "0258efb077960d6848f001904857f062"
                                          "fa453de26c1ad8736f55497254f56e8a74",
                    "certificate-expiry": 1,
                    "utxo-pubkey": "02f54f027377e84171296453828aa863"
                                   "c23fc4489453025f49bd3addfb3a359b3d",
                    "txid": "84c88fafe0bb75f507fe3bfb29a93d10"
                            "b2e80c15a63b2943c1a5fecb5a55cba2",
                    "vout": 0,
                    "locktime": 1640995200
                },
                "J5A4k9ecQzRRDfBx",
                "J55VZ6U6ZyFDNeuv"
            ),
            (
                True,
                {
                    # nicksig len = 71, certsig len = 70
                    "nick-signature":
                        b'0E\x02!\x00\x80\xc6$\x0c\xa1\x15YS\xacHB\xb33\xfa~'
                        b'\x9f\xb9`\xb3\xfe\xed0\xadHq\xc1~\x03.B\xbb#\x02'
                        b' #y~]\xd9\xbbX2\xc0\x1b\xe57\xf4\x0f\x1f\xd6$\x01'
                        b'\xf9\x15Z\xc9X\xa5\x18\xbe\x83\x1a&4Y\xd4',
                    "certificate-signature":
                        "304402205669ea394f7381e9abf0b3c0"
                        "13fac2b79d24c02feb86ff153"
                        "cff83c658d7cf7402200b295ace65568"
                        "7f80738f3733c1dc5f1e2b8f3"
                        "51c017a05b8bd31983dd4d723f",
                    "certificate-pubkey": "031d1c006a6310dbdf57341efc19c3a4"
                                          "3c402379d7ccd2480416cadc7579f973f7",
                    "certificate-expiry": 1,
                    "utxo-pubkey": "02616c56412eb738a9eacfb0550b43a5"
                                   "a2e77e5d5205ea9e2ca8dfac34e50c9754",
                    "txid": "84c88fafe0bb75f507fe3bfb29a93d10"
                            "b2e80c15a63b2943c1a5fecb5a55cba2",
                    "vout": 1,
                    "locktime": 1893456000
                },
                "J54LS6YyJPoseqFS",
                "J55VZ6U6ZyFDNeuv"
            ),
            (
                True,
                {
                    # nicksig len = 70, certsig len = 71
                    "nick-signature":
                        b'0D\x02 K)\xe9\x17d\x0b\xc0\x82(\xd1\xa2*l\xd8\x0eJ'
                        b'\xc7\x01NV\xbf\xcb\x02O]\xc0\x11\x01\x01B"\xed\x02'
                        b' ob\xa1\xf8>\x80U)\xc8\x96\x86\x1b \x0e\x00.\xf8'
                        b'\x86}\xcd\xf8\x82T\xa2\xb5\x8a4\xdb4\xbe\xf3{',
                    "certificate-signature":
                        "3045022100d3beb5660bef33d095f92a"
                        "3023bbbab15ece48ab2f211fa"
                        "935b62fe8b764c8c002204892deffb4c"
                        "9aa0d734aa3f55cc8e2baae4a"
                        "03fc5a9e571b4f671493f1254df9",
                    "certificate-pubkey": "03a2d1d15290d6d21204d1153c062970"
                                          "b4ff757a675e47a451fd0ba5c084127807",
                    "certificate-expiry": 1,
                    "utxo-pubkey": "03b9c12c9c31286772349b986653d072"
                                   "32327b284bd0787ad5829a04ac68f59b89",
                    "txid": "70c2995b283db086813d97817264f10b"
                            "8823b870298d30ab09cb43c6bf2670cf",
                    "vout": 0,
                    "locktime": 1735689600
                },
                "J59PRzM6ZsdA5uyJ",
                "J55VZ6U6ZyFDNeuv"
            ),
            (
                False,
                {
                    # nick signature with no DER header
                    "nick-signature":
                        b'ZD\x02 K)\xe9\x17d\x0b\xc0\x82(\xd1\xa2*l\xd8\x0eJ'
                        b'\xc7\x01NV\xbf\xcb\x02O]\xc0\x11\x01\x01B"\xed\x02'
                        b' ob\xa1\xf8>\x80U)\xc8\x96\x86\x1b \x0e\x00.\xf8'
                        b'\x86}\xcd\xf8\x82T\xa2\xb5\x8a4\xdb4\xbe\xf3{',
                    "certificate-signature":
                        "3045022100d3beb5660bef33d095f92a"
                        "3023bbbab15ece48ab2f211fa"
                        "935b62fe8b764c8c002204892deffb4c"
                        "9aa0d734aa3f55cc8e2baae4a"
                        "03fc5a9e571b4f671493f1254df9",
                    "certificate-pubkey": "03a2d1d15290d6d21204d1153c062970"
                                          "b4ff757a675e47a451fd0ba5c084127807",
                    "certificate-expiry": 1,
                    "utxo-pubkey": "03b9c12c9c31286772349b986653d072"
                                   "32327b284bd0787ad5829a04ac68f59b89",
                    "txid": "70c2995b283db086813d97817264f10b"
                            "8823b870298d30ab09cb43c6bf2670cf",
                    "vout": 0,
                    "locktime": 1735689600
                },
                "J59PRzM6ZsdA5uyJ",
                "J55VZ6U6ZyFDNeuv"
            ),
            (
                False,
                {
                    # nick signature which fails ecdsa_verify
                    "nick-signature":
                        b'0E\x02 K)\xe9\x17d\x0b\xc0\x82(\xd1\xa2*l\xd8\x0eJ'
                        b'\xc7\x01NV\xbf\xcb\x02O]\xc0\x11\x01\x01B"\xed\x02'
                        b' ob\xa1\xf8>\x80U)\xc8\x96\x86\x1b \x0e\x00.\xf8'
                        b'\x86}\xcd\xf8\x82T\xa2\xb5\x8a4\xdb4\xbe\xf3{',
                    "certificate-signature":
                        "3045022100d3beb5660bef33d095f92a"
                        "3023bbbab15ece48ab2f211fa"
                        "935b62fe8b764c8c002204892deffb4c"
                        "9aa0d734aa3f55cc8e2baae4a"
                        "03fc5a9e571b4f671493f1254df9",
                    "certificate-pubkey": "03a2d1d15290d6d21204d1153c062970"
                                          "b4ff757a675e47a451fd0ba5c084127807",
                    "certificate-expiry": 1,
                    "utxo-pubkey": "03b9c12c9c31286772349b986653d072"
                                   "32327b284bd0787ad5829a04ac68f59b89",
                    "txid": "70c2995b283db086813d97817264f10b"
                            "8823b870298d30ab09cb43c6bf2670cf",
                    "vout": 0,
                    "locktime": 1735689600
                },
                "J59PRzM6ZsdA5uyJ",
                "J55VZ6U6ZyFDNeuv"
            ),
            (
                False,
                {
                    # cert signature which fails ecdsa_verify
                    "nick-signature":
                        b'0D\x02 K)\xe9\x17d\x0b\xc0\x82(\xd1\xa2*l\xd8\x0eJ'
                        b'\xc7\x01NV\xbf\xcb\x02O]\xc0\x11\x01\x01B"\xed\x02'
                        b' ob\xa1\xf8>\x80U)\xc8\x96\x86\x1b \x0e\x00.\xf8'
                        b'\x86}\xcd\xf8\x82T\xa2\xb5\x8a4\xdb4\xbe\xf3{',
                    "certificate-signature":
                        "3055022100d3beb5660bef33d095f92a"
                        "3023bbbab15ece48ab2f211fa"
                        "935b62fe8b764c8c002204892deffb4c"
                        "9aa0d734aa3f55cc8e2baae4a"
                        "03fc5a9e571b4f671493f1254df9",
                    "certificate-pubkey": "03a2d1d15290d6d21204d1153c062970"
                                          "b4ff757a675e47a451fd0ba5c084127807",
                    "certificate-expiry": 1,
                    "utxo-pubkey": "03b9c12c9c31286772349b986653d072"
                                   "32327b284bd0787ad5829a04ac68f59b89",
                    "txid": "70c2995b283db086813d97817264f10b"
                            "8823b870298d30ab09cb43c6bf2670cf",
                    "vout": 0,
                    "locktime": 1735689600
                },
                "J59PRzM6ZsdA5uyJ",
                "J55VZ6U6ZyFDNeuv"
            )
        ])
    async def test_fidelity_bond_seen(self, valid, fidelity_bond_proof,
                                      maker_nick, taker_nick):
        proof = FidelityBondProof(
            maker_nick, taker_nick,
            hextobin(fidelity_bond_proof['certificate-pubkey']),
            fidelity_bond_proof['certificate-expiry'],
            hextobin(fidelity_bond_proof['certificate-signature']),
            (hextobin(fidelity_bond_proof['txid']),
             fidelity_bond_proof['vout']),
            hextobin(fidelity_bond_proof['utxo-pubkey']),
            fidelity_bond_proof['locktime']
        )
        serialized = proof._serialize_proof_msg(
            fidelity_bond_proof['nick-signature'])

        ob = get_ob(self.jmman)
        ob.msgchan.nick = taker_nick
        ob.on_fidelity_bond_seen(
            maker_nick, fidelity_bond_cmd_list[0], serialized)
        rows = []
        for by_nick in ob.fb.values():
            rows.append(dict(zip(FIDELITY_BOND_KEYS, by_nick)))
        assert len(rows) == 1
        assert rows[0]["counterparty"] == maker_nick
        assert rows[0]["takernick"] == taker_nick
        try:
            parsed_proof = FidelityBondProof.parse_and_verify_proof_msg(
                rows[0]["counterparty"], rows[0]["takernick"],
                rows[0]["proof"])
        except ValueError:
            parsed_proof = None
        if valid:
            assert parsed_proof is not None
            assert parsed_proof.utxo[0] == hextobin(
                fidelity_bond_proof["txid"])
            assert parsed_proof.utxo[1] == fidelity_bond_proof["vout"]
            assert parsed_proof.locktime == fidelity_bond_proof["locktime"]
            assert parsed_proof.cert_expiry == fidelity_bond_proof[
                "certificate-expiry"]
            assert parsed_proof.utxo_pub == hextobin(
                fidelity_bond_proof["utxo-pubkey"])
        else:
            assert parsed_proof is None

    async def test_duplicate_fidelity_bond_rejected(self):

        fidelity_bond_info = (
            (
                {
                    "nick-signature":
                        (b'0E\x02!\x00\xdbb\x15\x96\xa0\x87\xb8\x1d\xe05\xddV'
                         b'\xa1\x1bn\x8fq\x90&\x8cG@\x89"2\xb2\x81\x9b\xc00'
                         b'\xa5\xb6\x02 \x03\x14l\xd7BR\xba\x8c:\x88(\x8e3l'
                         b'\xac\xf5`T\x87\xfa\xf5\xa9\x1f\x19\xc0\xb6\xe9\xbb'
                         b'\xdc\xc7y\x99'),
                    "certificate-signature":
                        "3045022100eb512af938113badb4d7b2"
                        "9e0c22061c51dadb113a9395e"
                        "9ed81a46103391213022029170de4149"
                        "64f07228c4f0d404b1386272b"
                        "ae337f0133f1329d948a252fa2a0",
                    "certificate-pubkey": "0258efb077960d6848f001904857f062"
                                          "fa453de26c1ad8736f55497254f56e8a74",
                    "certificate-expiry": 1,
                    "utxo-pubkey": "02f54f027377e84171296453828aa863"
                                   "c23fc4489453025f49bd3addfb3a359b3d",
                    "txid": "84c88fafe0bb75f507fe3bfb29a93d10"
                            "b2e80c15a63b2943c1a5fecb5a55cba2",
                    "vout": 0,
                    "locktime": 1640995200
                },
                "J5A4k9ecQzRRDfBx",
                "J55VZ6U6ZyFDNeuv"
            ),
            (
                {
                    "nick-signature":
                        (b'0E\x02!\x00\x80\xc6$\x0c\xa1\x15YS\xacHB\xb33\xfa~'
                         b'\x9f\xb9`\xb3\xfe\xed0\xadHq\xc1~\x03.B\xbb#\x02 '
                         b'#y~]\xd9\xbbX2\xc0\x1b\xe57\xf4\x0f\x1f\xd6$\x01'
                         b'\xf9\x15Z\xc9X\xa5\x18\xbe\x83\x1a&4Y\xd4'),
                    "certificate-signature":
                        "304402205669ea394f7381e9abf0b3c0"
                        "13fac2b79d24c02feb86ff153"
                        "cff83c658d7cf7402200b295ace65568"
                        "7f80738f3733c1dc5f1e2b8f3"
                        "51c017a05b8bd31983dd4d723f",
                    "certificate-pubkey": "031d1c006a6310dbdf57341efc19c3a4"
                                          "3c402379d7ccd2480416cadc7579f973f7",
                    "certificate-expiry": 1,
                    "utxo-pubkey": "02616c56412eb738a9eacfb0550b43a5"
                                   "a2e77e5d5205ea9e2ca8dfac34e50c9754",
                    "txid": "84c88fafe0bb75f507fe3bfb29a93d10"
                            "b2e80c15a63b2943c1a5fecb5a55cba2",
                    "vout": 1,
                    "locktime": 1893456000
                },
                "J54LS6YyJPoseqFS",
                "J55VZ6U6ZyFDNeuv"
            )
        )

        ob = get_ob(self.jmman)

        fidelity_bond_proof1, maker_nick1, taker_nick1 = fidelity_bond_info[0]
        proof = FidelityBondProof(
            maker_nick1, taker_nick1,
            hextobin(fidelity_bond_proof1['certificate-pubkey']),
            fidelity_bond_proof1['certificate-expiry'],
            hextobin(fidelity_bond_proof1['certificate-signature']),
            (hextobin(fidelity_bond_proof1['txid']),
             fidelity_bond_proof1['vout']),
            hextobin(fidelity_bond_proof1['utxo-pubkey']),
            fidelity_bond_proof1['locktime']
        )
        serialized1 = proof._serialize_proof_msg(
            fidelity_bond_proof1['nick-signature'])
        ob.msgchan.nick = taker_nick1

        ob.on_fidelity_bond_seen(
            maker_nick1, fidelity_bond_cmd_list[0], serialized1)
        rows = []
        for by_nick in ob.fb.values():
            rows.append(dict(zip(FIDELITY_BOND_KEYS, by_nick)))
        assert len(rows) == 1

        # show the same fidelity bond message again, check it gets
        # rejected as duplicate
        ob.on_fidelity_bond_seen(
            maker_nick1, fidelity_bond_cmd_list[0], serialized1)
        rows = []
        for by_nick in ob.fb.values():
            rows.append(dict(zip(FIDELITY_BOND_KEYS, by_nick)))
        assert len(rows) == 1

        # show a different fidelity bond and check it does get accepted
        fidelity_bond_proof2, maker_nick2, taker_nick2 = fidelity_bond_info[1]
        proof2 = FidelityBondProof(
            maker_nick1, taker_nick1,
            hextobin(fidelity_bond_proof2['certificate-pubkey']),
            fidelity_bond_proof2['certificate-expiry'],
            hextobin(fidelity_bond_proof2['certificate-signature']),
            (hextobin(fidelity_bond_proof2['txid']),
             fidelity_bond_proof2['vout']),
            hextobin(fidelity_bond_proof2['utxo-pubkey']),
            fidelity_bond_proof2['locktime']
        )
        serialized2 = proof2._serialize_proof_msg(
            fidelity_bond_proof2['nick-signature'])
        ob.msgchan.nick = taker_nick2

        ob.on_fidelity_bond_seen(
            maker_nick2, fidelity_bond_cmd_list[0], serialized2)
        rows = []
        for by_nick in ob.fb.values():
            rows.append(dict(zip(FIDELITY_BOND_KEYS, by_nick)))
        assert len(rows) == 2
