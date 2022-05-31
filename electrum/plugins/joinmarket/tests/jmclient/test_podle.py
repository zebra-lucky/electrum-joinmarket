# -*- coding: utf-8 -*-

'''Tests of Proof of discrete log equivalence commitments.'''

import os
import hashlib
import struct
import pytest

from electrum.logging import get_logger, ShortcutInjectingFilter

from electrum.plugins.joinmarket.jmbase import bintohex
from electrum.plugins.joinmarket import jmbitcoin as bitcoin
from electrum.plugins.joinmarket.jmclient import (
    generate_podle, generate_podle_error_string, PoDLE,
    get_podle_commitments, add_external_commitments, update_commitments)
from electrum.plugins.joinmarket.jmclient.podle import (
    verify_all_NUMS, verify_podle, PoDLEError)

from electrum.plugins.joinmarket.tests import JMTestCase


LOGGING_SHORTCUT = 'J'
log = get_logger(__name__)
log.addFilter(ShortcutInjectingFilter(shortcut=LOGGING_SHORTCUT))


class PoDLETestCase(JMTestCase):

    async def test_commitments_empty(self):
        """Ensure that empty commitments file
        results in {}
        """
        assert get_podle_commitments(self.jmman) == ([], {})

    async def test_commitment_retries(self):
        """Assumes no external commitments available.
        Generate pretend priv/utxo pairs and check that they can be used
        taker_utxo_retries times.
        """
        jmman = self.jmman
        allowed = jmman.jmconf.taker_utxo_retries
        # make some pretend commitments
        dummy_priv_utxo_pairs = [
            (hashlib.sha256(os.urandom(10)).digest(),
             (hashlib.sha256(os.urandom(10)).digest(), 0))
            for _ in range(10)
        ]
        # test a single commitment request of all 10
        for x in dummy_priv_utxo_pairs:
            p = generate_podle(jmman, [x], allowed)
            assert p
        # At this point slot 0 has been taken by all 10.
        for i in range(allowed-1):
            p = generate_podle(jmman, dummy_priv_utxo_pairs[:1], allowed)
            assert p
        p = generate_podle(jmman, dummy_priv_utxo_pairs[:1], allowed)
        assert p is None

    def generate_single_podle_sig(self, priv, i):
        """Make a podle entry for key priv at index i, using a dummy utxo
        value.  This calls the underlying 'raw' code based on the class PoDLE,
        not the library 'generate_podle' which intelligently searches and
        updates commitments.
        """
        dummy_utxo = hashlib.sha256(priv).hexdigest() + ":3"
        podle = PoDLE(dummy_utxo, priv)
        r = podle.generate_podle(i)
        return (r['P'], r['P2'], r['sig'],
                r['e'], r['commit'])

    async def test_rand_commitments(self):
        for i in range(20):
            priv = os.urandom(32)+b"\x01"
            Pser, P2ser, s, e, commitment = self.generate_single_podle_sig(
                priv, 1 + i % 5)
            assert verify_podle(Pser, P2ser, s, e, commitment)
            # tweak commitments to verify failure
            tweaked = [x[::-1] for x in [Pser, P2ser, s, e, commitment]]
            for i in range(5):
                # Check failure on garbling of each parameter
                y = [Pser, P2ser, s, e, commitment]
                y[i] = tweaked[i]
                fail = False
                try:
                    fail = verify_podle(*y)
                except BaseException:
                    pass
                finally:
                    assert not fail

    async def test_nums_verify(self):
        """Check that the NUMS precomputed values are
        valid according to the code; assertion check
        implicit.
        """
        verify_all_NUMS(True)

    async def test_external_commitments(self):
        """Add this generated commitment to the external list
        {txid:N:{'P':pubkey, 'reveal':{1:{'P2':P2,'s':s,'e':e}, 2:{..},..}}}
        Note we do this *after* the sendpayment test so that the external
        commitments will not erroneously used (they are fake).
        """
        # ensure the file exists even if empty
        jmman = self.jmman
        update_commitments(jmman)
        ecs = {}
        tries = jmman.jmconf.taker_utxo_retries
        for i in range(10):
            priv = os.urandom(32)
            dummy_utxo = (hashlib.sha256(priv).digest(), 2)
            ecs[dummy_utxo] = {}
            ecs[dummy_utxo]['reveal'] = {}
            for j in range(tries):
                P, P2, s, e, commit = self.generate_single_podle_sig(priv, j)
                if 'P' not in ecs[dummy_utxo]:
                    ecs[dummy_utxo]['P'] = P
                ecs[dummy_utxo]['reveal'][j] = {'P2': P2, 's': s, 'e': e}
        add_external_commitments(jmman, ecs)
        used, external = get_podle_commitments(jmman)
        for u in external:
            assert external[u]['P'] == ecs[u]['P']
            for i in range(tries):
                for x in ['P2', 's', 'e']:
                    assert (external[u]['reveal'][i][x] ==
                            ecs[u]['reveal'][i][x])

        # add a dummy used commitment, then try again
        update_commitments(jmman, commitment=b"\xab"*32)
        ecs = {}
        known_commits = []
        known_utxos = []
        tries = 3
        for i in range(1, 6):
            u = (struct.pack(b'B', i)*32, i+3)
            known_utxos.append(u)
            priv = struct.pack(b'B', i)*32+b"\x01"
            ecs[u] = {}
            ecs[u]['reveal'] = {}
            for j in range(tries):
                P, P2, s, e, commit = self.generate_single_podle_sig(priv, j)
                known_commits.append(commit)
                if 'P' not in ecs[u]:
                    ecs[u]['P'] = P
                ecs[u]['reveal'][j] = {'P2': P2, 's': s, 'e': e}
        add_external_commitments(jmman, ecs)
        # simulate most of those external being already used
        for c in known_commits[:-1]:
            update_commitments(jmman, commitment=c)
        # this should find the remaining one utxo and return from it
        assert generate_podle(jmman, [], max_tries=tries,
                              allow_external=known_utxos)
        # test commitment removal
        tru = (struct.pack(b"B", 3)*32, 3+3)
        to_remove = {tru: ecs[tru]}
        update_commitments(jmman, external_to_remove=to_remove)

    async def test_podle_constructor(self):
        """Tests rules about construction of PoDLE object
        are conformed to.
        """
        priv = b"\xaa"*32
        # pub and priv together not allowed
        with pytest.raises(PoDLEError):
            p = PoDLE(priv=priv, P="dummypub")
        # no pub or priv is allowed, i forget if this is useful for something
        p = PoDLE()
        # create from priv
        p = PoDLE(priv=priv+b"\x01", u=(struct.pack(b"B", 7)*32, 4))
        pdict = p.generate_podle(2)
        assert all([k in pdict for k in ['used', 'utxo', 'P', 'P2', 'commit',
                                         'sig', 'e']])
        # using the valid data, serialize/deserialize test
        deser = p.deserialize_revelation(p.serialize_revelation())
        assert all([deser[x] == pdict[x]
                    for x in ['utxo', 'P', 'P2', 'sig', 'e']])
        # deserialization must fail for wrong number of items
        with pytest.raises(PoDLEError):
            p.deserialize_revelation(
                ':'.join([str(x) for x in range(4)]), separator=':')
        # reveal() must work without pre-generated commitment
        p.commitment = None
        pdict2 = p.reveal()
        assert pdict2 == pdict
        # corrupt P2, cannot commit:
        p.P2 = "blah"
        with pytest.raises(PoDLEError):
            p.get_commitment()
        # generation fails without a utxo
        p = PoDLE(priv=priv)
        with pytest.raises(PoDLEError):
            p.generate_podle(0)
        # Test construction from pubkey
        pub = bitcoin.privkey_to_pubkey(priv+b"\x01")
        p = PoDLE(P=pub.get_public_key_bytes())
        with pytest.raises(PoDLEError):
            p.get_commitment()
        with pytest.raises(PoDLEError):
            p.verify("dummycommitment", range(3))

    async def test_podle_error_string(self):
        example_utxos = [(b"\x00"*32, i) for i in range(6)]
        priv_utxo_pairs = [('fakepriv1', example_utxos[0]),
                           ('fakepriv2', example_utxos[1])]
        to = example_utxos[2:4]
        ts = example_utxos[4:6]
        cjamt = 100
        tua = "3"
        tuamtper = "20"
        jmman = self.jmman
        errmgsheader, errmsg = generate_podle_error_string(priv_utxo_pairs,
                                                           to,
                                                           ts,
                                                           jmman,
                                                           cjamt,
                                                           tua,
                                                           tuamtper)
        assert errmgsheader == ("Failed to source a commitment; this debugging"
                                " information may help:\n\n")
        y = [bintohex(x[0]) for x in example_utxos]
        assert all([errmsg.find(x) != -1 for x in y])
        # ensure OK with nothing
        errmgsheader, errmsg = generate_podle_error_string(
            [], [], [], jmman, cjamt, tua, tuamtper)
