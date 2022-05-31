# -*- coding: utf-8 -*-

import asyncio
import hashlib
import os
import time
from decimal import Decimal

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QTabWidget, QFrame, QTreeWidgetItem,
    QHeaderView, QLabel)

from electrum import util
from electrum.bitcoin import base_encode
from electrum.gui.qt.util import Buttons, QtEventListener, qt_event_listener

from .jmbitcoin import amount_to_btc, sat_to_unit
from .jmclient.fidelity_bond import FidelityBondProof
from .jmdaemon import (OrderbookWatch, MessageChannelCollection,
                       OnionMessageChannel, IRCMessageChannel)
from .jmdaemon.protocol import (
    JOINMARKET_NICK_HEADER, JM_VERSION, NICK_MAX_ENCODED, NICK_HASH_LENGTH,
    COMMAND_PREFIX, offername_list)
from .jm_qt_support import MyTreeWidget


ORDERTYPES = {
    'sw0absoffer': 'Native SW Absolute Fee',
    'sw0reloffer': 'Native SW Relative Fee',
    'swabsoffer': 'SW Absolute Fee',
    'swreloffer': 'SW Relative Fee'
}


class OBWatchTab(QWidget, QtEventListener):

    def __init__(self, jm_dlg):
        super().__init__()
        self.jm_dlg = jm_dlg
        self.jmman = jm_dlg.jmman
        self.logger = self.jmman.logger
        self.start_fut = None
        self.initUI()

    def initUI(self):
        vbox = QVBoxLayout(self)
        self.ob_watch_info = ob_info = QLabel('')
        self.start_ob_watch_btn = start_btn = QPushButton('Start OB Watch')
        start_btn.clicked.connect(self.on_start_ob_watch)
        self.stop_ob_watch_btn = stop_btn = QPushButton('Stop OB Watch')
        stop_btn.clicked.connect(self.on_stop_ob_watch)
        vbox.addLayout(Buttons(ob_info, start_btn, stop_btn))
        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        frameLayout = QVBoxLayout()
        frame.setLayout(frameLayout)
        vbox.addWidget(frame)

        self.ob_tabs = QTabWidget()
        self.ob_basic = None
        frameLayout.addWidget(self.ob_tabs)
        self.orders_tab = QWidget()
        self.fbonds_tab = QWidget()
        self.ob_tabs.addTab(self.orders_tab, "Orders")
        self.ob_tabs.addTab(self.fbonds_tab, "Fidelity Bonds")
        self.init_orders_tab()
        self.init_fbonds_tab()
        self.register_callbacks()

    @qt_event_listener
    def on_event_obwatch_updated(self):
        fbonds = []
        orders = []
        if self.ob_basic:
            orders_by_nick = self.ob_basic.ob
            for o_by_oid in orders_by_nick.values():
                orders.extend(o_by_oid.values())
            fbonds_by_nick = self.ob_basic.fb
            fbonds = [fbonds_by_nick[nick] for nick in fbonds_by_nick.keys()]
        bond_data = get_fidelity_bond_data(self.jmman, fbonds)
        self.update_orders(orders, bond_data)
        self.update_fbonds(fbonds, bond_data)

    def init_orders_tab(self):
        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)

        headers = self.orders_headers()
        self.otw = t = MyTreeWidget(self.orders_tab, self.create_orders_menu,
                                    headers)
        t.on_update = self.update_orders
        for i in range(len(headers)):
            t.header().setSectionResizeMode(
                i, QHeaderView.ResizeMode.ResizeToContents)

        vbox.addWidget(self.otw)
        self.orders_tab.setLayout(vbox)
        self.update_orders()

    def create_orders_menu(self, position):
        # FIXME add some actions or remove
        _ = self.otw.selectedItems()

    def orders_headers(self):
        '''Function included in case dynamic in future'''
        return ['Type', 'Counterparty', 'Order ID',
                'Fee', 'Miner Fee contribution / BTC',
                'Minimum Size / BTC', 'Maximum Size / BTC', 'Bond Value / BTC']

    def update_orders(self, orders=None, bond_data=None):
        self.otw.clear()

        def show_blank():
            m_item = QTreeWidgetItem(["No data", "", "", "", "", "", "", ""])
            self.otw.addChild(m_item)

        if not orders:
            show_blank()
        else:
            for o in orders:
                counterparty = o[0]
                oid = str(o[1])
                ordertype = ORDERTYPES.get(o[2], 'Unknown')
                minsize = str(amount_to_btc(str(o[3])))
                maxsize = str(amount_to_btc(str(o[4])))
                txfee = "%.8f" % amount_to_btc(str(o[5]))
                if o[2] in ['swabsoffer', 'sw0absoffer']:
                    val = sat_to_unit(o[6], 'BTC')
                    cjfee = "%.8f" % val
                elif o[2] in ['swreloffer', 'sw0reloffer']:
                    cjfee = f'{Decimal(o[6]) * Decimal(100)}%'
                bond_value = ''
                bd = bond_data.get(counterparty) if bond_data else None
                if bd:
                    bond_value = str(
                        amount_to_btc(str(round(bd['bond_value']))))
                m_item = QTreeWidgetItem([ordertype, counterparty, oid,
                                          cjfee, txfee, minsize, maxsize,
                                          bond_value])
                self.otw.addChild(m_item)

    def init_fbonds_tab(self):
        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 5, 0, 5)
        vbox.setSpacing(5)

        headers = self.fbonds_headers()
        self.btw = t = MyTreeWidget(self.orders_tab, self.create_fbonds_menu,
                                    headers)
        t.on_update = self.update_fbonds
        for i in range(len(headers)):
            t.header().setSectionResizeMode(
                i, QHeaderView.ResizeMode.ResizeToContents)

        self.fbonds_top_lb = QLabel('')
        self.fbonds_top_lb.hide()
        self.fbonds_bottom_lb = QLabel(
            'Tip: try running the RPC "decodescript <redeemscript>" as '
            'proof that the fidelity bond address matches the locktime.\n\n'
            'Also run "gettxout <utxo_txid> <utxo_vout>" as proof that the '
            'fidelity bond UTXO is real.')
        self.fbonds_bottom_lb.hide()
        vbox.addWidget(self.fbonds_top_lb)
        vbox.addWidget(self.btw)
        vbox.addWidget(self.fbonds_bottom_lb)
        self.fbonds_tab.setLayout(vbox)
        self.update_fbonds()

    def create_fbonds_menu(self, position):
        _ = self.btw.selectedItems()

    def fbonds_headers(self):
        '''Function included in case dynamic in future'''
        return ['Counterparty', 'UTXO', 'Bond value / BTC',
                'Locktime', 'Locked coins / BTC', 'Confirmation time',
                'Signature expiry height', 'Redeem script']

    def update_fbonds(self, fbonds=None, bond_data=None):
        self.btw.clear()

        def show_blank():
            self.fbonds_top_lb.hide()
            self.fbonds_bottom_lb.hide()
            m_item = QTreeWidgetItem(["No data", "", "", "", "", "", "", ""])
            self.btw.addChild(m_item)

        if not fbonds:
            show_blank()
        else:
            fbonds_cnt = 0
            fbonds_total = 0
            for b in fbonds:
                bd = bond_data.get(b[0]) if bond_data else None
                if not bd:
                    continue
                counterparty = bd['counterparty']
                utxo = bd['utxo']
                bond_value = str(amount_to_btc(str(round(bd['bond_value']))))
                locktime = time.strftime('%Y-%m-%d',
                                         time.localtime(bd['locktime']))
                locked_value = str(amount_to_btc(str(bd['locked_value'])))
                conf_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                          time.localtime(bd['conf_time']))
                expirity_height = str(bd['expirity_height']*2016)  # h*retarget
                redeem_script = bd['redeem_script']
                m_item = QTreeWidgetItem([counterparty, utxo, bond_value,
                                          locktime, locked_value, conf_time,
                                          expirity_height, redeem_script])
                self.btw.addChild(m_item)
                fbonds_cnt += 1
                fbonds_total += bd['locked_value']
            fbonds_total = str(amount_to_btc(str(fbonds_total)))
            self.fbonds_top_lb.setText(f'{fbonds_cnt} fidelity bonds found '
                                       f'with {fbonds_total} BTC total '
                                       f'locked up')
            self.fbonds_top_lb.show()
            self.fbonds_bottom_lb.show()

    def on_start_ob_watch(self, *args, **kwargs):
        if self.ob_basic:
            return

        async def start_ob_watch():
            self.ob_basic = obwatch_main(self.jmman)
            self.ob_watch_info.setText('Connecting...')
            await self.ob_basic.msgchan.run(for_obwatch=True)
            if self.ob_basic.msgchan.available_channels():
                self.ob_watch_info.setText('Connected')
            else:
                self.ob_watch_info.setText('Connection failed')

        self.start_fut = asyncio.run_coroutine_threadsafe(
            start_ob_watch(), self.jmman.loop)

    def on_stop_ob_watch(self, *args, **kwargs):
        if not self.ob_basic:
            return

        if self.start_fut and not self.start_fut.done():
            self.start_fut.cancel()
            self.start_fut = None

        async def stop_ob_watch():
            ob_basic = self.ob_basic
            self.ob_basic = None
            self.ob_watch_info.setText('Stopping...')
            await ob_basic.msgchan.shutdown(shutdown_unavailable=True)
            self.ob_watch_info.setText('')

        asyncio.run_coroutine_threadsafe(stop_ob_watch(), self.jmman.loop)


def get_fidelity_bond_data(jmman, fbonds):
    jmw = jmman.jmw
    jmconf = jmman.jmconf
    bond_data = bd = dict()

    blocks = jmman.wallet.adb.get_local_height()
    blockchain = jmman.network.blockchain()
    mediantime = jmw.get_median_time_past(blockchain)
    if mediantime is None:
        return bond_data
    interest_rate = jmconf.interest_rate

    bond_utxo_set = set()
    fidelity_bond_data = []
    bond_outpoint_conf_times = []
    fidelity_bond_values = []
    for fb in fbonds:
        try:
            parsed_bond = pb = FidelityBondProof.parse_and_verify_proof_msg(
                fb[0], fb[1], fb[2])
        except ValueError:
            continue
        coro = jmw.get_validated_timelocked_fidelity_bond_utxo(
            parsed_bond.utxo, parsed_bond.utxo_pub, parsed_bond.locktime,
            parsed_bond.cert_expiry, blocks)
        fut = asyncio.run_coroutine_threadsafe(coro, jmman.loop)
        bond_utxo_data = ud = fut.result()
        if bond_utxo_data is None:
            continue
        # check for duplicated utxos i.e. two or more makers using the same
        # UTXO which is obviously not allowed, a fidelity bond must only
        # be usable by one maker nick
        utxo_str = (parsed_bond.utxo[0] + b":" +
                    str(parsed_bond.utxo[1]).encode("ascii"))
        if utxo_str in bond_utxo_set:
            continue
        bond_utxo_set.add(utxo_str)

        fidelity_bond_data.append((parsed_bond, bond_utxo_data))

        header = None
        if blocks and bond_utxo_data is not None:
            header = blockchain.read_header(blocks -
                                            bond_utxo_data["confirms"] + 1)
        if header is None:
            continue
        conf_time = header['timestamp']
        bond_outpoint_conf_times.append(conf_time)

        bond_value = jmw.calculate_timelocked_fidelity_bond_value(
            bond_utxo_data['value'],
            conf_time,
            parsed_bond.locktime,
            mediantime,
            interest_rate)
        fidelity_bond_values.append(bond_value)
        nick = pb.maker_nick
        bd[nick] = dict()
        bd[nick]['counterparty'] = nick
        bd[nick]['utxo'] = f'{pb.utxo[0].hex()}:{pb.utxo[1]}'
        bd[nick]['bond_value'] = bond_value
        bd[nick]['locktime'] = pb.locktime
        bd[nick]['locked_value'] = ud["value"]
        bd[nick]['conf_time'] = conf_time
        bd[nick]['expirity_height'] = pb.cert_expiry
        bd[nick]['redeem_script'] = jmw.mk_freeze_script(
            pb.utxo_pub, pb.locktime).hex()
    return bond_data


async def on_privmsg(inst, nick, message, *, pubmsg=False):
    """An override for MessageChannel classes,
    to allow receipt of privmsgs without the
    verification hooks in client-daemon communication."""
    if len(message) < 2:
        return

    if message[0] != COMMAND_PREFIX:
        inst.logger.debug(f'message not a cmd: {message}')
        return
    cmd_string = message[1:].split(' ')[0]
    if cmd_string not in offername_list:
        inst.logger.debug(f'non-offer ignored: {message}')
        return
    # reconstruct original message without cmd pref
    if pubmsg:
        rawmessage = ' '.join(message[1:].split(' '))
    else:
        rawmessage = ' '.join(message[1:].split(' ')[:-2])
    for command in rawmessage.split(COMMAND_PREFIX):
        _chunks = command.split(" ")
        try:
            inst.check_for_orders(nick, _chunks)
            inst.check_for_fidelity_bond(nick, _chunks)
            util.trigger_callback('obwatch_updated')
        except BaseException:
            pass


class ObIRCChannel(IRCMessageChannel):

    async def on_privmsg(self, nick, message, *, pubmsg=False):
        await on_privmsg(self, nick, message)

    async def on_pubmsg(self, nick, message):
        await on_privmsg(self, nick, message, pubmsg=True)


class ObOnionChannel(OnionMessageChannel):

    async def on_privmsg(self, nick, message, *, pubmsg=False):
        await on_privmsg(self, nick, message)

    async def on_pubmsg(self, nick, message):
        await on_privmsg(self, nick, message, pubmsg=True)


class ObChannels(MessageChannelCollection):

    async def on_nick_leave_trigger(self, nick, mc):
        await super().on_nick_leave_trigger(nick, mc)
        util.trigger_callback('obwatch_updated')


class ObBasic(OrderbookWatch):
    """Dummy orderbook watch class
    with hooks for triggering orderbook request"""

    def __init__(self, jmman, msgchan):
        self.set_msgchan(msgchan)
        self.dust_threshold = jmman.jmconf.DUST_THRESHOLD

    async def on_welcome(self):
        await self.request_orderbook()

    async def request_orderbook(self):
        await self.msgchan.request_orderbook()


def get_dummy_nick():
    """In Joinmarket-CS nick creation is negotiated
    between client and server/daemon so as to allow
    client to sign for messages; here we only ever publish
    an orderbook request, so no such need, but for better
    privacy, a conformant nick is created based on a random
    pseudo-pubkey."""
    nick_pkh_raw = hashlib.sha256(os.urandom(10)).digest()[:NICK_HASH_LENGTH]
    nick_pkh = base_encode(nick_pkh_raw, base=58)
    # right pad to maximum possible; b58 is not fixed length.
    # Use 'O' as one of the 4 not included chars in base58.
    nick_pkh += 'O' * (NICK_MAX_ENCODED - len(nick_pkh))
    # The constructed length will be 1 + 1 + NICK_MAX_ENCODED
    nick = JOINMARKET_NICK_HEADER + str(JM_VERSION) + nick_pkh
    return nick


def obwatch_main(jmman):
    jmconf = jmman.jmconf
    global bond_exponent
    # needed to display notional units of FB valuation
    bond_exponent = jmconf.bond_value_exponent
    try:
        float(bond_exponent)
    except ValueError:
        jmman.logger.error(f"Invalid entry for bond_value_exponent,"
                           f" should be decimal number: {bond_exponent}")
        return
    mcs = []
    chan_configs = jmconf.get_msg_channels()  # get_mchannels(mode="PASSIVE")
    for c in list(chan_configs.values()):     # FIXME PASSIVE?
        if not c["enabled"]:
            continue
        if "type" in c and c["type"] == "onion":
            mcs.append(ObOnionChannel(jmman, c))
        else:
            mcs.append(ObIRCChannel(jmman, c))

    mcc = ObChannels(mcs, jmman)
    mcc.set_nick(get_dummy_nick())
    ob_basic = ObBasic(jmman, mcc)
    ob_basic.logger = jmman.logger
    jmman.logger.info("Starting ob-watcher")
    return ob_basic
