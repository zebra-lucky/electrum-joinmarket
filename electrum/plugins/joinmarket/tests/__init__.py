# -*- coding: utf-8 -*-

from types import SimpleNamespace
from typing import List
from unittest import mock

from electrum import util, storage, SimpleConfig
from electrum.bitcoin import address_to_scripthash
from electrum.transaction import Transaction
from electrum.wallet import restore_wallet_from_text

from tests import ElectrumTestCase

from electrum.plugins.joinmarket.jm_main import JMManager
from electrum.plugins.joinmarket.tests.jmclient.commontest import DummyJMWallet


__all__ = [
    'JMTestCase',
    'SynchronizerMock',
    'VerifyierMock',
    'NetworkMock',
    'DummyJMWallet',
]

tx1_txid = 'b82763a40e3c701669cb57341a8116d7f6d4cd2dbd0648d839c6b754aac37dd2'
tx1_str = (
    '0200000000010a571806169ce5f06998cc5a66369afbd5a11185ce88d4ca13767ce21de44'
    'ea63f0100000000fdffffff55d47bd60b865662f935d71735a9aae72ef0ffe150218c7356'
    '66c193ac7902470400000000fdffffffce47421089faa366c1febcc5d82c60cd5c291d882'
    'e247a6abf1c788949f837700000000000fdffffffd881f328b274fab128e1aa99bf898a3d'
    'e9e5f19801bcb179a17f24354b2e218a0100000000fdffffff4450e647814dff17739f233'
    'f48af3fa3389f8f2112a2c0a6c7c956f90633ff940100000000fdffffff265df4da6a28bc'
    '4bc8a5b906e41705dee3fb9ec510598d24c1b337a6d2c059a30100000000fdffffffd0432'
    '9933f46eecd48eace7e9ef5aa13d7e425d166dcc5132f83b82d5d5ad1d80100000000fdff'
    'ffffb4c94cdba874a7f9608a424170f834163c39025d25597f68c112fe3ed33cd1df01000'
    '00000fdffffff8be60590ef2c4d51076a2c205bfe89971e0383942a3e841545589b8c5998'
    'bde30000000000fdffffff8cdfc3dc43c8421f7328205fb03e80adb1102020fbb5d31b3c8'
    '6c537836b5fed0000000000fdffffff05c4f7020000000000160014ff22340e4f7d72be67'
    '9db7a1f338e4df5b6e1130a0252600000000001600140cac01dc51b1a082c714c395d35da'
    '4895c02475ca0252600000000001600143809b4dd70ae8534066ccd469d6e5d022253a110'
    'a0252600000000001600143e1563a9c4160c8b44ca553c354b5340b2d64821a0252600000'
    '000001600148462303ddb1815d733861af2fd82d683043d18b00247304402202f3fb38b14'
    '4bbbea89fc7407343f4c82e263ddd23b30e874d777156e2e72710a022006eb49eb44fd5ea'
    '5fe2bbd4d1bb1886702a1711279e66b055a914a511f2d3147012102073223fd736023ea35'
    'd83f0dd7c56ee6e110b4a21033c6a107e9bd05a741d60702473044022039beaf300302530'
    '138c8973dcd3d93000fc1c2c9a65327f3ce0846413680eecb02206e9439c212970dc8744a'
    'df3d0c81b50ac60186f8c8a78f7765d5081f2d7fc2ee0121035b0d6101e61ccc37573705d'
    '432a1371d2d1220e05856496c4b6942e6f4b078e70247304402205d6d94cb1854e2483aeb'
    '7186ef5852dc382fee703cd7b80901092dcbce4611f4022052c897ff678fc9c489a06aa28'
    'e1963b59eb55f190791b053072797b578af25fd0121035b0d6101e61ccc37573705d432a1'
    '371d2d1220e05856496c4b6942e6f4b078e70247304402201cf896d038f7ddfd3b117d835'
    '40834b46a5438a3dfce67c9598601dce7ed339c022022682f7dc48ee49089ae730f38cc12'
    'f1b5c2a8c5d4b5f258ffaa6c1f1e3e89d40121031eee9f3035255dac9433c410ce84ade85'
    '969e08ffe2e4b0b9f4c3937f9ce87b50247304402202c7f077deec637a0e010996fb6059d'
    '1d095a1ecfe87b12244b4d3b72d8e70ea302200b03c456c5bf63ff4dc875fcda04c4db1e7'
    'ad99724d80aff7ed60ac8adf3e3d60121035b0d6101e61ccc37573705d432a1371d2d1220'
    'e05856496c4b6942e6f4b078e7024730440220205c1af36d7153da3a5a4c97199325603ef'
    '73a6f0e891fd48796decaec1a7b99022028e515367cb4ad8782c82a9a17702a8cda080808'
    '766ad08f5fb196c51f87b9c90121035b0d6101e61ccc37573705d432a1371d2d1220e0585'
    '6496c4b6942e6f4b078e702473044022038bcd07b669e809f3e4b29a6f0dc0ed9abe6658b'
    '9b795619688de65563867e1102207258a57694080082234de12b9be12dbdc40bc45e68960'
    'a680271b9c83dcb73390121035b0d6101e61ccc37573705d432a1371d2d1220e05856496c'
    '4b6942e6f4b078e70247304402203154409178ddfe5780e2a8dc7a9906b01704c34fc45c4'
    'b7d73bb2756ea40de3202207bd7d3d162e10c46db6f7f43c0803c562e664402696354b32b'
    '1cb993178df9ac0121035b0d6101e61ccc37573705d432a1371d2d1220e05856496c4b694'
    '2e6f4b078e702473044022067ea4830cc46833da23f5cc40b3451ef93d272c12a0483ac2b'
    'c84f9f96f74e5b02200bac1b3fc813bb6f23620857815c26f36e4c058ac206ab286c36c74'
    'b4deafa560121035b0d6101e61ccc37573705d432a1371d2d1220e05856496c4b6942e6f4'
    'b078e70247304402206a8204210c498f77ef0c582e922ff13e1ce774eb82410775b30a0b6'
    '0160fd9d60220049a17f8ae4833adf70b766b7abec912983a8646f9d764a58f27432e8e0b'
    'b9bc0121035b0d6101e61ccc37573705d432a1371d2d1220e05856496c4b6942e6f4b078e'
    '7a7012b00'
)

BCH_TIP_HEIGHT = 2873814

BCH_HEADER_AT_TIP = {
    'version': 536870912,
    'prev_block_hash':
        '0000000000000002aac61fa2f9b271434ac2a9955bfdd3645d8187e3264064a3',
    'merkle_root':
        'f7cc9dee3edefff5d63a447396b044740c3c9e3793c620aff4fd18beb8eb1b94',
    'timestamp': 1723834285,
    'bits': 486604799,
    'nonce': 728650638,
    'block_height': 2873814
}

BCH_HEADERS = {
    2873813: {
        'version': 541065216,
        'prev_block_hash':
            '000000000000000bbc16f2f2fd82cc6a1b3208d931319bdc3ae5d29efcbf2cc6',
        'merkle_root':
            '53df89562bf12794896e94f55b2a25b84c046e6d0c4a3cbadb586ef2bdf11039',
        'timestamp': 1723833080, 'bits': 420466436, 'nonce': 3534698758,
        'block_height': 2873813},
    2873812: {
        'version': 538968064,
        'prev_block_hash':
            '000000006332e321de6b737849c50817693a2662961c12a4ce393c0c37a7bc89',
        'merkle_root':
            'b86587e98cfed59f966a69edd905a2bbddf65f19f43d713c3267b02fae4ebac6',
        'timestamp': 1723832135, 'bits': 420466436, 'nonce': 1778464843,
        'block_height': 2873812},
    2873811: {
        'version': 536870912,
        'prev_block_hash':
            '0000000000005cf4598545bf49d6324f63131636c91757c8fe4dc03f93632276',
        'merkle_root':
            '15cccf64aad7964309d613f768baf90ce2805dfd0a44a2778eb4f88779432433',
        'timestamp': 1723831765, 'bits': 486604799, 'nonce': 3974262758,
        'block_height': 2873811},
    2873810: {
        'version': 837509120,
        'prev_block_hash':
            '000000004d08d55f58acd4b1009741864d3e35e56a65ff9250f3fdbe956103bb',
        'merkle_root':
            '37987a0c0905cd40123c36d3b10e18ffa7a5d6ac66709713dcdba0e57007bdd6',
        'timestamp': 1723830563, 'bits': 486604799, 'nonce': 2251653492,
        'block_height': 2873810},
    2873809: {
        'version': 536870912,
        'prev_block_hash':
            '000000000000000ab9214d4d96449e2f590d843b9dd0973ad58a7551ba1c6b27',
        'merkle_root':
            '9ea383774b7aff1df28b91bda0efec71e748c51fc120eef1255764b6ca97e122',
        'timestamp': 1723829360, 'bits': 486604799, 'nonce': 1277380237,
        'block_height': 2873809},
    2873808: {
        'version': 608411648,
        'prev_block_hash':
            '000000001e931b36be2b4c3a97444f805280389fdb34f5f0698c764421058f6c',
        'merkle_root':
            '0aa0f410ded0c3ba062155bb49f376cd35f85fb00ee49f6c74f644807e614c7a',
        'timestamp': 1723828153, 'bits': 420466436, 'nonce': 1282440353,
        'block_height': 2873808},
    2873807: {
        'version': 536870912,
        'prev_block_hash':
            '0000000000001f84b4fc16629291b50ca7ee3211a5f7ce58489122779b1c02c8',
        'merkle_root':
            '7a6f30d74ade562194b8224ca3231c47d22b2cfac3e6e36b0a6df4e09701d949',
        'timestamp': 1723827660, 'bits': 486604799, 'nonce': 3972273367,
        'block_height': 2873807},
    2873806: {
        'version': 602759168,
        'prev_block_hash':
            '0000000087a1b519488b864de87f1c13888adeb45261d1d7a0eab579e49f37bb',
        'merkle_root':
            '7398cbb3afc792566c7848284880a062b0dd0d716b50e11f9405bd1034b33b42',
        'timestamp': 1723826459, 'bits': 486604799, 'nonce': 2302593351,
        'block_height': 2873806},
    2873805: {
        'version': 536870912,
        'prev_block_hash':
            '000000000000000927427d10305e2869d01801d938ddcba001ddd5ede79fc669',
        'merkle_root':
            '953642c4f5c5742ed3dcc1c1083ee61a492f09018cd016918e1d991863b648a7',
        'timestamp': 1723825255, 'bits': 486604799, 'nonce': 2050958288,
        'block_height': 2873805},
    2873804: {
        'version': 551550976,
        'prev_block_hash':
            '0000000000000000369c95b405342c45a7156d0258364f5f3c78bfaeb05ba38b',
        'merkle_root':
            '03ace5e888b15d35006992187fc6697de95eb2370c36162491b893701107591a',
        'timestamp': 1723824049, 'bits': 420466436, 'nonce': 4205259273,
        'block_height': 2873804},
}


class BlockchainMock:

    def __init__(self):
        self.no_headers = False

    def is_tip_stale(self):
        if self.no_headers:
            return True
        return False

    def height(self):
        if self.no_headers:
            return 0
        return BCH_TIP_HEIGHT

    def header_at_tip(self):
        if self.no_headers:
            return
        return BCH_HEADER_AT_TIP

    def read_header(self, height):
        if self.no_headers:
            return
        return BCH_HEADERS.get(height, None)


class NetworkMock:

    def __init__(self, loop, config, wallet):
        self.asyncio_loop = loop
        self.config = config
        self.wallet = wallet
        self.proxy = None
        self.params = SimpleNamespace()
        self.params.proxy = None
        self.connected = False
        self.fake_raw_txs = {}

    def add_fake_raw_tx(self, txid, raw_tx):
        self.fake_raw_txs[txid] = raw_tx

    async def try_broadcasting(self, tx, name) -> bool:
        return True

    async def get_transaction(self, txid: str, *, timeout=None) -> str:
        return self.fake_raw_txs.get(txid)

    def blockchain(self):
        return BlockchainMock()

    def has_internet_connection(self):
        return self.connected

    def get_parameters(self):
        return self.params

    def get_server_height(self):
        return int(1e7)

    def get_local_height(self):
        return self.get_server_height()

    def is_connected(self):
        return True

    async def listunspent_for_scripthash(self,  sh: str) -> List[dict]:
        unspent_list = []
        for coin in self.wallet.get_utxos():
            coin_sh = address_to_scripthash(coin.address)
            if coin_sh != sh:
                continue
            unspent = {
                'height': coin.block_height,
                'tx_hash': coin.prevout.txid.hex(),
                'tx_pos': coin.prevout.out_idx,
                'value': coin.value_sats(),
            }
            unspent_list.append(unspent)
        return unspent_list


class SynchronizerMock:

    def __init__(self):
        self.addrs = set()
        self._requests_sent = 0

    def is_up_to_date(self):
        return True

    def add(self, addr):
        self.addrs.add(addr)

    def reset_request_counters(self):
        pass


class VerifyierMock:

    def is_up_to_date(self):
        return True

    def reset_request_counters(self):
        pass


class JMTestCase(ElectrumTestCase):

    TESTNET = True

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.patcher = mock.patch.object(storage.WalletStorage, 'write')
        self.patcher.start()

        self.asyncio_loop = util.get_asyncio_loop()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})
        self.config.FEE_EST_DYNAMIC = False
        self.config.FEE_EST_STATIC_FEERATE = 100000
        self.w = w = restore_wallet_from_text('logic observe arrest marriage '
                                              'crew bounce dismiss audit grunt'
                                              ' identify rate supply',
                                              path='if_this_exists_mocking'
                                              '_failed_648151893',
                                              gap_limit=10,
                                              config=self.config)['wallet']
        self.w.adb.synchronizer = SynchronizerMock()
        self.w.adb.verifier = VerifyierMock()
        self.w._up_to_date = True
        self.w.db.put('stored_height', int(1e7))
        self.network = NetworkMock(self.asyncio_loop, self.config, w)
        self.jmman = jmman = JMManager(self.w)
        self.jmman.on_network_start(self.network)
        await jmman._enable_jm()
        self.jmw = jmw = jmman.jmw
        for addr in w.get_addresses():
            w.adb.add_address(addr)
        jmw.synchronize()
        self.jmconf = jmconf = jmman.jmconf
        jmconf.minimum_makers = 1
        jmconf.taker_utxo_age = 1
        jmconf.tx_fees = 100000
        jmconf.tx_fees_factor = 0
        w.adb.add_transaction(Transaction(tx1_str))
        w.adb.add_verified_tx(tx1_txid, util.TxMinedInfo(
            int(1e6), '', '', '', ''))

    async def asyncTearDown(self):
        self.jmman.stop()
        await self.w.stop()
        self.patcher.stop()
