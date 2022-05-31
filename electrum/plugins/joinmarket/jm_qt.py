# -*- coding: utf-8 -*-

import os
import datetime
import asyncio
from functools import partial

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (QIcon, QTextCursor, QIntValidator, QFont,
                         QKeySequence, QColor, QBrush, QAction)
from PyQt6.QtWidgets import (QWidget, QGridLayout, QHBoxLayout, QLabel,
                             QVBoxLayout, QDialog, QPushButton, QTabWidget,
                             QCheckBox, QPlainTextEdit, QApplication,
                             QMessageBox, QScrollArea, QFrame, QSizePolicy,
                             QTextEdit, QGroupBox, QLineEdit, QSplitter,
                             QTreeWidgetItem, QHeaderView, QAbstractItemView,
                             QStatusBar, QMenu, QFileDialog,
                             QDoubleSpinBox, QStyle)

from electrum import constants, bitcoin
from electrum.bip32 import xpub_type
from electrum.i18n import _
from electrum.simple_config import FEE_ETA_TARGETS

from electrum.gui.qt.util import (read_QIcon, HelpLabel, MessageBoxMixin,
                                  QtEventListener, qt_event_listener,
                                  MONOSPACE_FONT, WindowModalDialog,
                                  Buttons, OkButton)

from .jm_util import guess_address_script_type, filter_log_line, JMStates
from .jmclient import (JMClientProtocolFactory, Taker, get_max_cj_fee_values,
                       fidelity_bond_weighted_order_choose, get_schedule,
                       ScheduleGenerationErrorNoFunds, schedule_to_text,
                       tumbler_filter_orders_callback, NO_ROUNDING,
                       get_default_max_relative_fee, direct_send,
                       get_default_max_absolute_fee, parse_schedule_line,
                       general_custom_change_warning,
                       nonwallet_custom_change_warning,
                       sweep_custom_change_warning, wallet_display,
                       tumbler_taker_finished_update, restart_wait)
from .jmbitcoin.amount import amount_to_sat, amount_to_str

from .jm_qt_support import (ScheduleWizard, TumbleRestartWizard, config_tips,
                            config_types, MyTreeWidget, JMQtMessageBox,
                            donation_more_message, BitcoinAmountEdit,
                            JMIntValidator, conf_sections, conf_names)
from .jm_qt_obwatch import OBWatchTab


JM_GUI_VERSION = '33'

DATE_FORMAT = "%Y/%m/%d %H:%M:%S"


class GUIConfig:

    def __init__(self):
        self.gaplimit = 6
        self.check_high_fee = 2
        self.max_mix_depth = 5
        self.order_wait_time = 30
        self.checktx = True


GUIconf = GUIConfig()


class FilteredPlainTextEdit(QPlainTextEdit):

    def contextMenuEvent(self, event):
        f_copy = QAction(_('Copy filtered'), self)
        f_copy.triggered.connect(lambda checked: self.copy_filtered())
        f_copy.setEnabled(self.textCursor().hasSelection())

        copy_icon = QIcon.fromTheme('edit-copy')
        if copy_icon:
            f_copy.setIcon(copy_icon)

        menu = self.createStandardContextMenu(event.pos())
        menu.insertAction(menu.actions()[0], f_copy)
        menu.exec(event.globalPos())

    def copy_filtered(self):
        cursor = self.textCursor()
        if not cursor.hasSelection():
            return

        all_lines = self.toPlainText().splitlines()
        sel_beg = cursor.selectionStart()
        sel_end = cursor.selectionEnd()
        l_beg = 0
        result_lines = []
        for i in range(len(all_lines)):
            cur_line = all_lines[i]
            cur_len = len(cur_line)
            l_end = l_beg + cur_len

            if l_end > sel_beg and l_beg < sel_end:
                filtered_line = filter_log_line(cur_line)
                l_sel_start = None if sel_beg <= l_beg else sel_beg - l_beg
                l_sel_end = None if sel_end >= l_end else sel_end - l_beg
                clipped_line = filtered_line[l_sel_start:l_sel_end]
                result_lines.append(clipped_line)

            l_beg += (cur_len + 1)
            if l_beg > sel_end:
                break
        QApplication.clipboard().setText('\n'.join(result_lines))


class WarnExDialog(WindowModalDialog):

    def __init__(self, jmman, parent):
        WindowModalDialog.__init__(self, parent, _('Warning'))
        self.setMinimumWidth(500)
        self.setMaximumWidth(500)
        warn_icon = self.style().standardIcon(
            QStyle.StandardPixmap.SP_MessageBoxWarning)
        self.setWindowIcon(warn_icon)

        self.jm_dlg = parent
        self.jmman = jmman
        jmconf = jmman.jmconf

        self.grid = grid = QGridLayout()
        vbox = QVBoxLayout(self)
        vbox.addLayout(grid)
        grid.setSpacing(8)

        warn_label = QLabel()
        warn_label.setPixmap(warn_icon.pixmap(48))
        grid.addWidget(warn_label, 0, 0)

        warn_text = jmconf.warn_electrumx_data(full_txt=True)
        grid.addWidget(QLabel(warn_text, wordWrap=True), 0, 1)

        is_enabled = jmman.enabled

        self.read_cb = read_cb = QCheckBox(_('I have read the warning.'))
        read_cb.stateChanged.connect(self.on_read_cb_changed)
        self.read_cb.setHidden(is_enabled)
        grid.addWidget(read_cb, 1, 1)

        read_cb_checked = self.read_cb.isChecked()
        self.activate_btn = b = QPushButton(_('Activate JM plugin'))
        b.clicked.connect(self.on_activate_btn_clicked)
        b.setHidden(is_enabled)
        b.setEnabled(read_cb_checked)
        grid.addWidget(b, 2, 1)

        self.active_lb = lb = QLabel(_('JM plugin is activated.'))
        lb.setHidden(not is_enabled)
        grid.addWidget(lb, 3, 1)

        self.hide_cb = hide_cb = QCheckBox(
            _('Do not show this on JoinMarket dialog open.'))
        hide_cb.setChecked(not jmconf.show_warn_electrumx)
        self.hide_cb.setEnabled(False or is_enabled)
        hide_cb.stateChanged.connect(self.on_hide_cb_changed)
        grid.addWidget(hide_cb, 4, 1)

        vbox.addLayout(Buttons(OkButton(self)))
        self.setLayout(vbox)

    def update_ui(self):
        read_cb_checked = self.read_cb.isChecked()
        is_enabled = self.jmman.enabled

        self.read_cb.setHidden(is_enabled)
        self.activate_btn.setEnabled(read_cb_checked)
        self.activate_btn.setHidden(is_enabled)
        self.active_lb.setHidden(not is_enabled)
        self.hide_cb.setEnabled(is_enabled)
        self.jm_dlg.set_tabs_visible()

    def on_read_cb_changed(self, x):
        self.update_ui()

    def on_activate_btn_clicked(self, x):
        if (JMQtMessageBox(self, "Activate JM plugin?", mbtype='question') !=
                QMessageBox.StandardButton.Yes):
            return
        self.jmman.enable_jm()
        if self.jmman.enabled:
            JMQtMessageBox(self, _('JM plugin is activated'), mbtype='info',
                           title=_('Info'))
            self.update_ui()

    def on_hide_cb_changed(self, x):
        self.jmman.jmconf.show_warn_electrumx = (Qt.CheckState(x) !=
                                                 Qt.CheckState.Checked)
        self.update_ui()


class WarnExLabel(HelpLabel):

    def __init__(self, jmman, parent):
        self.parent_win = parent
        self.jmman = jmman
        self.jmconf = jmconf = jmman.jmconf
        text = jmconf.warn_electrumx_data()
        help_text = jmconf.warn_electrumx_data(full_txt=True)
        super(WarnExLabel, self).__init__(text, help_text)

    def mouseReleaseEvent(self, x):
        self.show_warn()

    def show_warn(self):
        WarnExDialog(self.jmman, self.parent_win).exec()


class SpendStateMgr:
    """A primitive class keep track of the mode
    in which the spend tab is being run
    """
    def __init__(self, updatecallback, jmman, update_status_btn_cb):
        self.updatecallback = updatecallback
        self.jmman = jmman
        self.update_status_btn_cb = update_status_btn_cb
        self.reset_vars()

    def jmman_ready(self):
        self.jmman.state = JMStates.Ready
        self.update_status_btn_cb()

    def jmman_mixing(self):
        self.jmman.state = JMStates.Mixing
        self.update_status_btn_cb()

    def updateType(self, t):
        self.typestate = t
        self.updatecallback()

    def updateRun(self, r):
        self.runstate = r
        self.updatecallback()

    def reset_vars(self):
        self.typestate = 'single'
        self.runstate = 'ready'
        self.schedule_name = None
        self.loaded_schedule = None
        self.prev_runstates = []

    def reset(self):
        self.jmman_ready()
        self.reset_vars()
        self.updatecallback()

    @property
    def waiting(self):
        return self.runstate == 'waiting'

    @waiting.setter
    def waiting(self, waiting: bool):
        if waiting:
            self.prev_runstates.append(self.runstate)
            self.runstate = 'waiting'
        elif self.prev_runstates:
            self.runstate = self.prev_runstates.pop()
        else:
            self.runstate = 'ready'
        self.updatecallback()


class JMDlgUnsupportedJM(QDialog, MessageBoxMixin):

    def __init__(self, mwin, plugin):
        QDialog.__init__(self, parent=None)
        flags = self.windowFlags()
        flags = flags & ~Qt.WindowType.Dialog
        flags = flags | Qt.WindowType.Window
        flags = flags | Qt.WindowType.WindowMinimizeButtonHint
        flags = flags | Qt.WindowType.WindowMaximizeButtonHint
        self.setWindowFlags(flags)

        self.setMinimumSize(900, 480)
        self.setWindowIcon(read_QIcon('electrum.png'))
        self.mwin = mwin
        self.plugin = plugin
        self.wallet = mwin.wallet
        self.jmman = jmman = mwin.wallet.jmman
        title = '%s - %s' % (plugin.MSG_TITLE, str(self.wallet))
        self.setWindowTitle(title)

        layout = QGridLayout()
        self.setLayout(layout)

        jm_unsupported_label = QLabel(jmman.unsupported_msg)
        jm_unsupported_label.setWordWrap(True)
        layout.addWidget(jm_unsupported_label, 0, 0, 1, -1)

        self.close_btn = b = QPushButton(_('Close'))
        b.setDefault(True)
        b.clicked.connect(self.close)
        layout.addWidget(b, 2, 1)
        layout.setRowStretch(1, 1)
        layout.setColumnStretch(0, 1)

    def closeEvent(self, event):
        if self.mwin in self.plugin.jm_dialogs:
            del self.plugin.jm_dialogs[self.mwin]
        event.accept()


class JMDlg(QtEventListener, QDialog, MessageBoxMixin):

    def __init__(self, mwin, plugin):
        QDialog.__init__(self, parent=None)
        flags = self.windowFlags()
        flags = flags & ~Qt.WindowType.Dialog
        flags = flags | Qt.WindowType.Window
        flags = flags | Qt.WindowType.WindowMinimizeButtonHint
        flags = flags | Qt.WindowType.WindowMaximizeButtonHint
        self.setWindowFlags(flags)

        self.setMinimumSize(900, 480)
        self.setWindowIcon(read_QIcon('electrum.png'))
        self.mwin = mwin
        self.app = mwin.gui_object.app
        self.plugin = plugin
        self.config = plugin.config
        # self.format_amount = mwin.format_amount
        self.wallet = mwin.wallet
        self.jmman = jmman = mwin.wallet.jmman
        self.logger = jmman.logger
        GUIconf.max_mix_depth = jmman.jmconf.mixdepth + 1
        if constants.net.TESTNET:
            testnet_str = ' ' + constants.net.NET_NAME.capitalize()
        else:
            testnet_str = ''
        self.win_title = '%s%s - %s' % (plugin.MSG_TITLE, testnet_str,
                                        str(self.wallet))
        self.setWindowTitle(self.win_title)

        self.statusBar = QStatusBar()
        layout = QVBoxLayout()
        self.setLayout(layout)

        # setup logging
        self.log_handler = self.jmman.log_handler
        self.logger = self.jmman.logger
        self.log_view = FilteredPlainTextEdit()
        self.log_view.setMaximumBlockCount(1000)
        self.log_view.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.log_view.setReadOnly(True)

        self.tabs = tabs = QTabWidget(self)
        layout.addWidget(tabs)
        layout.addWidget(self.statusBar)

        self.wallet_tab = JMWalletTab(self)
        tabs.addTab(self.wallet_tab, "JM Wallet")
        self.spend_tab = SpendTab(self)
        tabs.addTab(self.spend_tab, "Coinjoins")
        self.ob_watch_tab = OBWatchTab(self)
        tabs.addTab(self.ob_watch_tab, "OB Watch")
        self.coins_tab = CoinsTab(self)
        tabs.addTab(self.coins_tab, "Coins")
        self.history_tab = TxHistoryTab(self)
        tabs.addTab(self.history_tab, "Tx History")
        self.settings_tab = SettingsTab(self)
        tabs.addTab(self.settings_tab, "Settings")
        self.set_tabs_visible()

        self.register_callbacks()
        self.init_log()
        self.on_tabs_changed(0)
        self.tabs.currentChanged.connect(self.on_tabs_changed)

    def set_tabs_visible(self):
        tabs = self.tabs
        for tab in [self.spend_tab, self.ob_watch_tab, self.coins_tab,
                    self.history_tab, self.settings_tab]:
            idx = tabs.indexOf(tab)
            tabs.setTabVisible(idx, self.jmman.enabled)

    def showEvent(self, event):
        super(JMDlg, self).showEvent(event)
        QTimer.singleShot(0, self.on_shown)

    def on_shown(self):
        if self.jmman.jmconf.show_warn_electrumx:
            self.settings_tab.warn_ex_label.show_warn()

    def on_tabs_changed(self, idx):
        if self.tabs.currentWidget() == self.spend_tab:
            self.append_log_tail()
            self.log_handler.notify = True
        elif self.tabs.currentWidget() == self.settings_tab:
            self.settings_tab.constructUI(update=True)
        else:
            self.log_handler.notify = False

    @qt_event_listener
    def on_event_status(self):
        self.wallet_tab.updateWalletInfo()
        self.coins_tab.updateUtxos()

    @qt_event_listener
    def on_event_jm_log_changes(self, *args):
        jmman = args[0]
        if jmman == self.jmman:
            if self.log_handler.head > self.log_head:
                self.clear_log_head()
            if self.log_handler.tail > self.log_tail:
                self.append_log_tail()

    def init_log(self):
        self.log_head = self.log_handler.head
        self.log_tail = self.log_head

    def append_log_tail(self):
        log_handler = self.log_handler
        log_tail = log_handler.tail
        lv = self.log_view
        vert_sb = self.log_view.verticalScrollBar()
        was_at_end = (vert_sb.value() == vert_sb.maximum())
        for i in range(self.log_tail, log_tail):
            log_line = ''
            log_record = log_handler.log.get(i, None)
            if log_record:
                log_line = log_handler.format(log_record)
            lv.appendHtml(log_line)
            if was_at_end:
                cursor = self.log_view.textCursor()
                cursor.movePosition(QTextCursor.End)
                self.log_view.setTextCursor(cursor)
                self.log_view.ensureCursorVisible()
        self.log_tail = log_tail

    def clear_log_head(self):
        self.log_head = self.log_handler.head

    def resizeEvent(self, event):
        self.log_view.ensureCursorVisible()
        return super(JMDlg, self).resizeEvent(event)

    def shutdown(self):
        self.logger.info('Shutting down JMDlg')
        try:
            spend_tab = self.spend_tab
            jmman = self.jmman
            jmman.jmconf.reset_mincjamount()
            self.ob_watch_tab.on_stop_ob_watch()

            async def shutdown_mixing():
                if spend_tab.spendstate.runstate == 'ready':
                    if jmman.state == JMStates.Mixing:
                        jmman.state = JMStates.Ready
                    return

                self.logger.info('Shutting down mixing')
                try:
                    while not spend_tab.clientfactory:
                        await asyncio.sleep(0.2)

                    spend_tab.abortTransactions()
                    proto_daemon = spend_tab.clientfactory.proto_daemon
                    spend_tab.clientfactory = None
                    spend_tab.taker = None

                    while not proto_daemon.mcc:
                        await asyncio.sleep(0.2)

                    await proto_daemon.mc_shutdown(
                        shutdown_unavailable=True)
                    if jmman.state == JMStates.Mixing:
                        jmman.state = JMStates.Ready
                    self.logger.info('Shutting down finished')
                except Exception as e:
                    self.logger.info(f'Error shutting down mixing: '
                                     f'{repr(e)}')

            asyncio.run_coroutine_threadsafe(shutdown_mixing(), jmman.loop)
        except Exception as e:
            self.logger.error(f'Error shutting down JMDlg: {repr(e)}')

    def closeEvent(self, event):
        if not self.plugin.unconditional_close_jm_dlg:
            quit_msg = "Are you sure you want to quit?"
            reply = JMQtMessageBox(self, quit_msg, mbtype='question')
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        self.shutdown()
        self.unregister_callbacks()
        if self.mwin in self.plugin.jm_dialogs:
            del self.plugin.jm_dialogs[self.mwin]
        event.accept()

    def done(self, r):
        pass  # do nothing on reject/accept especially reject from Esc key

    def show_error(self, msg, title=None):
        if title is None:
            title = "Error"
        JMQtMessageBox(self, msg, mbtype='crit', title=title)

    @classmethod
    def autofreeze_warning_cb(cls, parent_win, outpoint, utxo):
        """ Handles coins sent to reused addresses,
        preventing forced address reuse, according to value of
        POLICY setting `max_sats_freeze_reuse` (see
        WalletService.check_for_reuse()).
        """
        utxostr = (f'outpoint:\n{outpoint}\n\n'
                   f'address:\n{utxo.address}\n\n'
                   f'value:\n{utxo.value}')
        msg = (f"New utxo has been automatically frozen to prevent forced "
               f"address reuse:\n\n{utxostr}\n\n You can unfreeze this utxo "
               f"via the Coins tab.")
        JMQtMessageBox(parent_win, msg, mbtype='info',
                       title="New utxo frozen")


class JMWalletTab(QWidget):

    def __init__(self, jm_dlg):
        super().__init__()
        self.jm_dlg = jm_dlg
        self.jmman = jm_dlg.jmman
        self.logger = self.jmman.logger
        self.wallet_name = jm_dlg.win_title
        self.initUI()

    def initUI(self):
        self.label1 = QLabel(
            'No wallet loaded. Use "Wallet > Load" to load existing wallet ' +
            'or "Wallet > Generate" to create a new wallet.',
            self)
        self.label1.setAlignment(
                Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        v = MyTreeWidget(self, self.create_menu, self.getHeaders())
        v.header().resizeSection(0, 400)    # size of "Address" column
        v.header().resizeSection(1, 130)    # size of "Index" column
        v.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection)
        v.on_update = self.updateWalletInfo
        v.hide()
        self.walletTree = v
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        vbox.addWidget(self.label1)
        vbox.addWidget(v)
        buttons = QWidget()
        vbox.addWidget(buttons)
        self.updateWalletInfo()
        self.show()

    def getHeaders(self):
        '''Function included in case dynamic in future'''
        return ['Address', 'Index', 'Balance', 'Status', 'Label']

    def create_menu(self, position):
        item = self.walletTree.currentItem()
        address_valid = False
        xpub_exists = False
        if item:
            txt = str(item.text(0))
            if bitcoin.is_address(txt):
                address_valid = True

            parsed = txt.split()
            if len(parsed) > 1:
                try:
                    if xpub_type(parsed[-1]) in ['standard', 'p2wpkh-p2sh',
                                                 'p2wsh-p2sh', 'p2wpkh',
                                                 'p2wsh']:
                        xpub = parsed[-1]
                        xpub_exists = True
                except BaseException:
                    pass

        menu = QMenu()
        if address_valid:
            copy_addr_act = QAction("Copy address to clipboard", menu)
            copy_addr_act.triggered.connect(
                lambda: QApplication.clipboard().setText(txt))
            copy_addr_act.setShortcut(
                QKeySequence(QKeySequence.StandardKey.Copy))
            menu.addAction(copy_addr_act)
            if item.text(4):
                menu.addAction(
                    "Copy label to clipboard",
                    lambda: QApplication.clipboard().setText(item.text(4)))
            # Show QR code option only for new addresses to avoid address reuse
            if item.text(3) == "new":
                menu.addAction("Show QR code",
                               lambda: self.openAddressQRCodePopup(txt))
        if xpub_exists:
            copy_xpub_act = QAction("Copy extended public key to clipboard",
                                    menu)
            copy_xpub_act.triggered.connect(
                lambda: QApplication.clipboard().setText(txt))
            copy_xpub_act.setShortcut(
                QKeySequence(QKeySequence.StandardKey.Copy))
            menu.addAction(copy_xpub_act)
            menu.addAction("Show QR code",
                           lambda: self.openQRCodePopup(xpub, xpub))

        # TODO add more items to context menu
        menu.exec(self.walletTree.viewport().mapToGlobal(position))

    def openQRCodePopup(self, title, data):
        self.jm_dlg.mwin.show_qrcode(data, 'Address', parent=self)

    def openAddressQRCodePopup(self, address):
        self.openQRCodePopup(address, address)

    def updateWalletInfo(self):
        max_mixdepth_count = GUIconf.max_mix_depth

        previous_expand_states = []
        # before deleting, note whether items were expanded
        for i in range(self.walletTree.topLevelItemCount()):
            tli = self.walletTree.invisibleRootItem().child(i)
            # expandedness is a list beginning with the top level expand state,
            # followed by the expand state of its children
            expandedness = [tli.isExpanded()]
            for j in range(tli.childCount()):
                expandedness.append(tli.child(j).isExpanded())
            previous_expand_states.append(expandedness)
        self.walletTree.clear()

        walletinfo = get_wallet_printout(self.jmman)

        rows, mbalances, xpubs, total_bal = walletinfo
        self.label1.setText("CURRENT WALLET: " + self.wallet_name +
                            ', total balance: ' + total_bal)
        self.walletTree.show()

        for mixdepth in range(max_mixdepth_count):
            mdbalance = mbalances[mixdepth]
            account_xpub = xpubs[mixdepth][-1]

            m_item = QTreeWidgetItem(["Mixdepth " + str(mixdepth) +
                                      " , balance: " + mdbalance + ", " +
                                      account_xpub, '', '', '', ''])
            self.walletTree.addChild(m_item)

            # if expansion states existed, reinstate them:
            if len(previous_expand_states) == max_mixdepth_count:
                m_item.setExpanded(previous_expand_states[mixdepth][0])
            # we expand at the mixdepth level by default
            else:
                m_item.setExpanded(True)

            for address_type in [0, 1]:
                if address_type == 0:
                    heading = "EXTERNAL " + xpubs[mixdepth][address_type]
                elif address_type == 0:
                    heading = "INTERNAL"
                else:
                    heading = ""

                seq_item = QTreeWidgetItem([heading, '', '', '', ''])
                m_item.addChild(seq_item)

                # by default, the external addresses of mixdepth 0 is expanded
                should_expand = mixdepth == 0 and address_type == 0
                for address_index in range(len(rows[mixdepth][address_type])):
                    item = QTreeWidgetItem(
                        rows[mixdepth][address_type][address_index])
                    item.setFont(0, QFont(MONOSPACE_FONT))
                    if rows[mixdepth][address_type][address_index][3] != "new":
                        item.setForeground(3, QBrush(QColor('red')))
                    # by default, if the balance is non zero, it is
                    #  also expanded
                    balance = float(
                        rows[mixdepth][address_type][address_index][2])
                    if balance > 0:
                        should_expand = True
                    seq_item.addChild(item)
                # Remember user choice, if expansion states existed,
                # reinstate them:
                if len(previous_expand_states) == max_mixdepth_count:
                    should_expand = \
                        previous_expand_states[mixdepth][address_type+1]
                seq_item.setExpanded(should_expand)


class SpendTab(QWidget):

    info_callback_signal = pyqtSignal(tuple)
    error_callback_signal = pyqtSignal(tuple)
    check_offers_signal = pyqtSignal(tuple)
    check_direct_send_signal = pyqtSignal(tuple)
    taker_info_signal = pyqtSignal(tuple)
    taker_finished_signal = pyqtSignal(tuple)
    start_single_signal = pyqtSignal()
    start_join_signal = pyqtSignal()

    def __init__(self, jm_dlg):
        super().__init__()
        self.jm_dlg = jm_dlg
        self.jmman = jmman = jm_dlg.jmman
        self.logger = jmman.logger
        self.initUI()
        self.taker = None
        self.filter_offers_response = None
        self.clientfactory = None
        self.tumbler_options = None
        # timer for waiting for confirmation on restart
        self.restartTimer = QTimer()
        # timer for wait for next transaction
        self.nextTxTimer = None
        # tracks which mode the spend tab is run in
        update_jm_status_btn = partial(self.jm_dlg.plugin.update_jm_status_btn,
                                       jmman.wallet)
        self.spendstate = SpendStateMgr(self.toggleButtons, jmman,
                                        update_jm_status_btn)
        self.spendstate.reset()  # trigger callback to 'ready' state

        # connect callback signals
        self.info_callback_signal.connect(self._infoDirectSend)
        self.error_callback_signal.connect(self._errorDirectSend)
        self.check_offers_signal.connect(self._checkOffers)
        self.check_direct_send_signal.connect(self._checkDirectSend)
        self.taker_info_signal.connect(self._takerInfo)
        self.taker_finished_signal.connect(self._takerFinished)
        self.start_single_signal.connect(self.startSingle)
        self.start_join_signal.connect(self.startJoin)

    def switchToJoinmarket(self):
        self.numCPLabel.setVisible(True)
        self.numCPInput.setVisible(True)

    def clearFields(self, ignored):
        self.switchToJoinmarket()
        self.addressInput.setText('')
        self.amountInput.setText('')
        self.changeInput.setText('')
        self.addressInput.setEnabled(True)
        self.mixdepthInput.setEnabled(True)
        self.amountInput.setEnabled(True)
        self.changeInput.setEnabled(True)
        self.startButton.setEnabled(True)
        self.abortButton.setEnabled(False)

    def checkAddress(self, addr):
        valid = bitcoin.is_address(str(addr))
        if not valid and len(addr) > 0:
            JMQtMessageBox(self, "Bitcoin address not valid.",
                           mbtype='warn',
                           title="Error")

    def parseURIAndValidateAddress(self, addr):
        addr = addr.strip()
        self.checkAddress(addr)

    def checkAmount(self, amount_str):
        if not amount_str:
            return False
        try:
            amount_sat = amount_to_sat(amount_str)
        except ValueError as e:
            JMQtMessageBox(self, f'{repr(e)}', title="Error", mbtype="warn")
            return False
        jmman = self.jmman
        if amount_sat < jmman.jmconf.DUST_THRESHOLD:
            JMQtMessageBox(self,
                           "Amount " + amount_to_str(amount_sat) +
                           " is below dust threshold " +
                           amount_to_str(jmman.jmconf.DUST_THRESHOLD) + ".",
                           mbtype='warn',
                           title="Error")
            return False
        return True

    def cache_keypairs(self, callback, *, tx_cnt=None):
        jmman = self.jmman
        if jmman.jmw.check_need_new_keypairs():
            password = None
            jm_dlg = self.jm_dlg
            while jmman.wallet.has_keystore_encryption():
                password = jm_dlg.mwin.password_dialog(parent=jm_dlg)
                if password is None:
                    # User cancelled password input
                    return True, None
                try:
                    jmman.wallet.check_password(password)
                    break
                except Exception as e:
                    jm_dlg.show_error(str(e))
                    continue
            coro = jmman.jmw.make_keypairs_cache(password, callback,
                                                 tx_cnt=tx_cnt)
            asyncio.run_coroutine_threadsafe(coro, jmman.loop)
            return True, callback
        else:
            return False, None

    def generateTumbleSchedule(self):
        global GUIconf
        # needs a set of tumbler options and destination addresses, so needs
        # a wizard
        jmman = self.jmman
        wizard = ScheduleWizard(jmman)
        wizard_return = wizard.exec()
        if wizard_return == QDialog.DialogCode.Rejected:
            return
        try:
            self.spendstate.loaded_schedule = wizard.get_schedule(
                jmman.jmw.get_balance_by_mixdepth(), jmman.jmconf.mixdepth)
        except ScheduleGenerationErrorNoFunds:
            JMQtMessageBox(self,
                           "Failed to start tumbler; no funds available.",
                           title="Tumbler start failed.")
            return
        self.spendstate.schedule_name = 'generated'
        self.updateSchedView()
        self.tumbler_options = wizard.opts
        self.tumbler_destaddrs = wizard.get_destaddrs()
        self.sch_startButton.setEnabled(True)

    def selectSchedule(self):
        firstarg = QFileDialog.getOpenFileName(
            self, 'Choose Schedule File',
            options=QFileDialog.Option.DontUseNativeDialog)[0]
        if not firstarg:
            return
        # TODO validate the schedule
        self.logger.debug('Looking for schedule in: ' + str(firstarg))

        res, schedule = get_schedule(firstarg)
        if not res:
            JMQtMessageBox(self, "Not a valid JM schedule file", mbtype='crit',
                           title='Error')
        else:
            self.jm_dlg.statusBar.showMessage("Schedule loaded OK.")
            self.spendstate.loaded_schedule = schedule
            self.spendstate.schedule_name = os.path.basename(str(firstarg))
            self.updateSchedView()
            reply = JMQtMessageBox(self, "An incomplete tumble run"
                                         " detected.\nDo you want to"
                                         " restart?",
                                   title="Restart detected",
                                   mbtype='question')
            if reply != QMessageBox.StandardButton.Yes:
                return
            self.tumbler_options = True

    def updateSchedView(self):
        if self.spendstate.schedule_name:
            self.sch_label2.setText(self.spendstate.schedule_name)
            self.sched_view.setText(
                schedule_to_text(self.spendstate.loaded_schedule))
        else:
            self.sch_label2.setText("None")
            self.sched_view.setText("")

    def getDonateLayout(self):
        donateLayout = QHBoxLayout()
        self.donateCheckBox = QCheckBox()
        self.donateCheckBox.setChecked(False)
        # Temporarily disabled
        self.donateCheckBox.setEnabled(False)
        self.donateCheckBox.setMaximumWidth(30)
        self.donateLimitBox = QDoubleSpinBox()
        self.donateLimitBox.setMinimum(0.001)
        self.donateLimitBox.setMaximum(0.100)
        self.donateLimitBox.setSingleStep(0.001)
        self.donateLimitBox.setDecimals(3)
        self.donateLimitBox.setValue(0.010)
        self.donateLimitBox.setMaximumWidth(100)
        self.donateLimitBox.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        donateLayout.addWidget(self.donateCheckBox)
        label1 = QLabel("Check to send change lower than: ")
        label1.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        donateLayout.addWidget(label1)
        donateLayout.setAlignment(
            label1, Qt.AlignmentFlag.AlignLeft)
        donateLayout.addWidget(self.donateLimitBox)
        donateLayout.setAlignment(
            self.donateLimitBox, Qt.AlignmentFlag.AlignLeft)
        label2 = QLabel(" BTC as a donation.")
        donateLayout.addWidget(label2)
        label2.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        donateLayout.setAlignment(
            label2, Qt.AlignmentFlag.AlignLeft)
        label3 = HelpLabel('More', donation_more_message,
                           'About the donation feature')
        label3.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        donateLayout.setAlignment(
            label3, Qt.AlignmentFlag.AlignLeft)
        donateLayout.addWidget(label3)
        donateLayout.addStretch(1)
        return donateLayout

    def initUI(self):
        jmman = self.jm_dlg.jmman
        vbox = QVBoxLayout(self)
        top = QFrame()
        top.setFrameShape(QFrame.Shape.StyledPanel)
        topLayout = QGridLayout()
        top.setLayout(topLayout)
        sA = QScrollArea()
        sA.setWidgetResizable(True)
        topLayout.addWidget(sA)
        self.qtw = QTabWidget()
        sA.setWidget(self.qtw)
        self.single_join_tab = QWidget()
        self.schedule_tab = QWidget()
        self.qtw.addTab(self.single_join_tab, "Single Join")
        self.qtw.addTab(self.schedule_tab, "Multiple Join")

        # construct layout for scheduler
        sch_layout = QGridLayout()
        sch_layout.setSpacing(4)
        self.schedule_tab.setLayout(sch_layout)
        current_schedule_layout = QVBoxLayout()
        sch_label1 = QLabel("Current schedule: ")
        sch_label1.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.sch_label2 = QLabel("None")
        current_schedule_layout.addWidget(sch_label1)
        current_schedule_layout.addWidget(self.sch_label2)
        self.sched_view = QTextEdit()
        self.sched_view.setReadOnly(True)
        self.sched_view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        current_schedule_layout.addWidget(self.sched_view)
        sch_layout.addLayout(current_schedule_layout, 0, 0, 1, 1)
        self.schedule_set_button = QPushButton('Choose schedule file')
        self.schedule_set_button.clicked.connect(self.selectSchedule)
        self.wallet_schedule_button = QPushButton('Schedule from wallet')
        self.wallet_schedule_button.clicked.connect(self.load_wallet_schedule)
        self.schedule_generate_button = QPushButton('Generate tumble schedule')
        self.schedule_generate_button.clicked.connect(
            self.generateTumbleSchedule)
        self.sch_startButton = QPushButton('Run schedule')
        # not runnable until schedule chosen
        self.sch_startButton.setEnabled(False)
        self.sch_startButton.clicked.connect(self.startMultiple)
        self.sch_abortButton = QPushButton('Abort')
        self.sch_abortButton.setEnabled(False)
        self.sch_abortButton.clicked.connect(self.abortTransactions)

        sch_buttons_box = QGroupBox("Actions")
        sch_buttons_layout = QVBoxLayout()
        sch_buttons_layout.addWidget(self.schedule_set_button)
        sch_buttons_layout.addWidget(self.wallet_schedule_button)
        sch_buttons_layout.addWidget(self.schedule_generate_button)
        sch_buttons_layout.addWidget(self.sch_startButton)
        sch_buttons_layout.addWidget(self.sch_abortButton)
        sch_buttons_box.setLayout(sch_buttons_layout)
        sch_layout.addWidget(sch_buttons_box, 0, 1, 1, 1)

        # construct layout for single joins
        innerTopLayout = QGridLayout()
        innerTopLayout.setSpacing(4)
        self.single_join_tab.setLayout(innerTopLayout)

        # Temporarily disabled
        # donateLayout = self.getDonateLayout()
        # innerTopLayout.addLayout(donateLayout, 0, 0, 1, 2)

        recipientLabel = QLabel('Recipient address / URI')
        recipientLabel.setToolTip(
            'The address or bitcoin: URI you want to send the payment to')
        self.addressInput = QLineEdit('')
        self.addressInput.editingFinished.connect(
            lambda: self.parseURIAndValidateAddress(self.addressInput.text()))
        innerTopLayout.addWidget(recipientLabel, 1, 0)
        innerTopLayout.addWidget(self.addressInput, 1, 1, 1, 2)

        self.numCPLabel = QLabel('Number of counterparties')
        self.numCPLabel.setToolTip(
            'How many other parties to send to; if you enter 4\n' +
            ', there will be 5 participants, including you.\n' +
            'Enter 0 to send direct without coinjoin.')
        self.numCPInput = QLineEdit('9')
        self.numCPInput.setValidator(QIntValidator(0, 20))
        innerTopLayout.addWidget(self.numCPLabel, 2, 0)
        innerTopLayout.addWidget(self.numCPInput, 2, 1, 1, 2)

        mixdepthLabel = QLabel('Mixdepth')
        mixdepthLabel.setToolTip(
            'The mixdepth of the wallet to send the payment from')
        self.mixdepthInput = QLineEdit('0')

        self.mixdepthInput.setValidator(
            QIntValidator(0, jmman.jmconf.mixdepth - 1))
        innerTopLayout.addWidget(mixdepthLabel, 3, 0)
        innerTopLayout.addWidget(self.mixdepthInput, 3, 1, 1, 2)

        amountLabel = QLabel('Amount')
        amountLabel.setToolTip(
            'The amount to send.\n' +
            'If you enter 0, a SWEEP transaction\nwill be performed,' +
            ' spending all the coins \nin the given mixdepth.')
        self.amountInput = BitcoinAmountEdit('')
        innerTopLayout.addWidget(amountLabel, 4, 0)
        innerTopLayout.addWidget(self.amountInput, 4, 1, 1, 2)

        changeLabel = QLabel('Custom change address')
        changeLabel.setToolTip(
            'Specify an address to receive change, rather ' +
            'than sending it to the internal wallet.')
        self.changeInput = QLineEdit()
        self.changeInput.editingFinished.connect(
            lambda: self.checkAddress(self.changeInput.text().strip()))
        self.changeInput.setPlaceholderText("(optional)")
        innerTopLayout.addWidget(changeLabel, 5, 0)
        innerTopLayout.addWidget(self.changeInput, 5, 1, 1, 2)

        self.startButton = QPushButton('Start')
        self.startButton.setToolTip(
            'If "checktx" is selected in the Settings, you will be \n'
            'prompted to decide whether to accept\n'
            'the transaction after connecting, and shown the\n'
            'fees to pay; you can cancel at that point, or by \n'
            'pressing "Abort".')
        self.startButton.clicked.connect(self.startSingle)
        self.abortButton = QPushButton('Abort')
        self.abortButton.setEnabled(False)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.startButton)
        buttons.addWidget(self.abortButton)
        self.abortButton.clicked.connect(self.abortTransactions)
        innerTopLayout.addLayout(buttons, 6, 0, 1, 2)
        splitter1 = QSplitter(Qt.Orientation.Vertical)
        splitter1.addWidget(top)
        splitter1.addWidget(self.jm_dlg.log_view)
        splitter1.setSizes([400, 200])
        self.setLayout(vbox)
        vbox.addWidget(splitter1)
        self.show()

    def load_wallet_schedule(self):
        schedule_txt = self.jmman.jmconf.get_schedule().encode('utf-8')
        schedule = []
        schedule_lines = schedule_txt.splitlines()
        for sl in schedule_lines:
            parsed, res = parse_schedule_line(schedule, sl)
            if not parsed:
                JMQtMessageBox(self, "Not a valid JM schedule saved"
                                     " in the wallet",
                               mbtype='crit', title='Error')
                self.logger.warning(f"Wrong schedule loaded from wallet: "
                                    f"error: {res}, data: {schedule_txt}."
                                    f" Clearning wrong schedule")
                self.jmman.jmconf.set_schedule('')
                return
            elif res is not None:
                schedule = res

        self.jm_dlg.statusBar.showMessage("Schedule loaded OK.")
        self.spendstate.loaded_schedule = schedule
        self.spendstate.schedule_name = 'saved in wallet'
        self.updateSchedView()
        reply = JMQtMessageBox(self, "An incomplete tumble run"
                                     " detected.\nDo you want to"
                                     " restart?",
                               title="Restart detected",
                               mbtype='question')
        if reply != QMessageBox.StandardButton.Yes:
            return
        self.tumbler_options = True

    def restartWaitWrap(self):
        if restart_wait(self.jmman, self.waitingtxid):
            self.restartTimer.stop()
            self.waitingtxid = None
            self.jm_dlg.statusBar.showMessage("Transaction in a block,"
                                              " now continuing.")
            self.startJoin()

    def startJoin_callback(self):
        self.spendstate.waiting = False
        self.start_join_signal.emit()

    def startMultiple(self):
        jmman = self.jmman
        if not self.spendstate.runstate == 'ready':
            self.logger.info("Cannot start join, already running.")
            return
        if not self.spendstate.loaded_schedule:
            self.logger.info("Cannot start, no schedule loaded.")
            return

        self.spendstate.jmman_mixing()
        self.spendstate.updateType('multiple')
        self.spendstate.updateRun('running')

        if self.tumbler_options:
            # Uses the flag 'True' value from selectSchedule to recognize a
            # restart, which needs new dynamic option values. The rationale
            # for using input is in case the user can increase success
            # probability by changing them.
            if self.tumbler_options is True:
                wizard = TumbleRestartWizard(jmman)
                wizard_return = wizard.exec()
                if wizard_return == QDialog.DialogCode.Rejected:
                    self.spendstate.reset()
                    return
                self.tumbler_options = wizard.getOptions()
            # check for a partially-complete schedule; if so,
            # follow restart logic
            # 1. filter out complete:
            self.spendstate.loaded_schedule = [
                s for s in self.spendstate.loaded_schedule if s[-1] != 1]
            # reload destination addresses
            self.tumbler_destaddrs = [x[3] for x
                                      in self.spendstate.loaded_schedule
                                      if x not in ["INTERNAL", "addrask"]]
            # 2 Check for unconfirmed
            if (isinstance(self.spendstate.loaded_schedule[0][-1], str)
                    and len(self.spendstate.loaded_schedule[0][-1]) == 64):
                # ensure last transaction is confirmed before restart
                jmman.tumble_log.info("WAITING TO RESTART...")
                self.jm_dlg.statusBar.showMessage("Waiting for confirmation"
                                                  " to restart..")
                txid = self.spendstate.loaded_schedule[0][-1]
                # remove the already-done entry (this connects to the other
                # TODO, probably better *not* to truncate the done-already
                # txs from file, but simplest for now.
                self.spendstate.loaded_schedule = \
                    self.spendstate.loaded_schedule[1:]
                # defers startJoin() call until tx seen on network. Note that
                # since we already updated state to running, user cannot
                # start another transactions while waiting. Also, use :0
                # because it always exists
                self.waitingtxid = txid
                self.restartTimer.timeout.connect(self.restartWaitWrap)
                self.restartTimer.start(5000)
                self.updateSchedView()
                return
            self.updateSchedView()
        self.startJoin()

    def checkDirectSend(self, dtx, destaddr, amount, fee, custom_change_addr):
        res_fut = self.jmman.loop.create_future()
        self.check_direct_send_signal.emit((
            res_fut, dtx, destaddr, amount, fee, custom_change_addr))
        return res_fut

    def _checkDirectSend(self, args):
        """Give user info to decide whether to accept a direct send;
        note the callback includes the full prettified transaction,
        but currently not printing it for space reasons.
        """
        try:
            res_fut, dtx, destaddr, amount, fee, custom_change_addr = args
            mbinfo = ["Sending " + amount_to_str(amount) + ",",
                      "to: " + destaddr + ","]

            if custom_change_addr:
                mbinfo.append("change to: " + custom_change_addr + ",")

            mbinfo += ["fee: " + amount_to_str(fee) + ".",
                       "Accept?"]
            reply = JMQtMessageBox(self,
                                   '\n'.join([m + '<p>' for m in mbinfo]),
                                   mbtype='question', title="Direct send")
            if reply == QMessageBox.StandardButton.Yes:
                self.direct_send_amount = amount
                res_fut.set_result(True)
            else:
                res_fut.set_result(False)
        except Exception as e:
            res_fut.set_result(False)
            self.logger.info(f"Error in _checkDirectSend: {repr(e)}")

    def infoDirectSend(self, msg, txinfo):
        self.info_callback_signal.emit((msg, txinfo))

    def _infoDirectSend(self, args):
        msg, txinfo = args
        destaddr = str(self.addressInput.text().strip())
        if txinfo:
            if isinstance(txinfo, str):
                w = self.jmman.wallet
                txid = txinfo
                tx = w.adb.get_transaction(txid)
            else:
                tx = txinfo
                txid = tx.txid()
        self.clearFields(None)
        if not txinfo:
            self.giveUp()
        else:
            # since direct_send() assumes a one-shot processing, it does
            # not add a callback for confirmation, so that event could
            # get lost; we do that here to ensure that the confirmation
            # event is noticed:
            def qt_directsend_callback(rtxd, rtxid, confs):
                if rtxid == txid:
                    return True
                return False
            jmman = self.jmman
            jmman.jmw.active_txs[txid] = tx
            jmman.jmw.wallet_service_register_callbacks(
                [qt_directsend_callback], txid, cb_type="confirmed")
            self.persistTxToHistory(destaddr, self.direct_send_amount,
                                    txid)
            self.cleanUp()
        JMQtMessageBox(self, msg, title="Success")

    def errorDirectSend(self, msg):
        self.error_callback_signal.emit((msg,))

    def _errorDirectSend(self, args):
        msg = args[0]
        JMQtMessageBox(self, msg, mbtype="warn", title="Error")

    def startSingle_callback(self):
        self.spendstate.waiting = False
        self.start_single_signal.emit()

    def startSingle(self):
        jmman = self.jmman
        if not self.spendstate.runstate == 'ready':
            self.logger.info("Cannot start join, already running.")
        if not self.validateSingleSend():
            return

        destaddr = str(self.addressInput.text().strip())
        try:
            amount = amount_to_sat(self.amountInput.text())
        except ValueError as e:
            JMQtMessageBox(self, f'{repr(e)}', title="Error", mbtype="warn")
            return
        makercount = int(self.numCPInput.text())
        mixdepth = int(self.mixdepthInput.text())

        if makercount == 0:
            need_cache, callback = self.cache_keypairs(
                self.startSingle_callback, tx_cnt=0)
            if need_cache:
                if callback:
                    self.spendstate.waiting = True
                    self.jm_dlg.statusBar.showMessage(
                        "Caching keypairs to sign ...")
                else:
                    self.logger.info('Need password to cache keypairs to sign')
                    self.spendstate.waiting = False
                return
            custom_change = None
            if len(self.changeInput.text().strip()) > 0:
                custom_change = str(self.changeInput.text().strip())
            coro = direct_send(jmman, mixdepth,
                               [(destaddr, amount)],
                               accept_callback=self.checkDirectSend,
                               info_callback=self.infoDirectSend,
                               error_callback=self.errorDirectSend,
                               custom_change_addr=custom_change,
                               return_transaction=True)
            asyncio.run_coroutine_threadsafe(coro, jmman.loop)
            return

        # for coinjoin sends no point to send below dust threshold, likely
        # there will be no makers for such amount.
        if amount != 0 and makercount > 0 and not self.checkAmount(amount):
            return

        if makercount < jmman.jmconf.minimum_makers:
            JMQtMessageBox(self, "Number of counterparties (" + str(
                makercount) + ") below minimum_makers (" + str(
                jmman.jmconf.minimum_makers) +
                ") in configuration.",
                title="Error", mbtype="warn")
            return

        # note 'amount' is integer, so not interpreted as fraction
        # see notes in sample testnet schedule for format
        self.spendstate.loaded_schedule = [[mixdepth, amount, makercount,
                                            destaddr, 0, NO_ROUNDING, 0]]
        self.spendstate.jmman_mixing()
        self.spendstate.updateType('single')
        self.spendstate.updateRun('running')
        self.startJoin()

    def getMaxCJFees(self, relfee, absfee):
        """ Used as a callback to decide relative and absolute
        maximum fees for coinjoins, in cases where the user has not
        set these values in the config (which is the default)."""
        if relfee is None:
            relfee = get_default_max_relative_fee()
        if absfee is None:
            absfee = get_default_max_absolute_fee()
        msg = (f'Your maximum absolute fee from one counterparty has been '
               f'set to: {absfee} satoshis.\nYour maximum relative fee from '
               f'one counterparty has been set to: {relfee}.\nTo change '
               f'these, please change the settings:\nmax_cj_fee_abs = '
               f'your-value-in-satoshis\nmax_cj_fee_rel = '
               f'your-value-as-decimal\nmax_cj_fee_confirmed to confirm '
               f'values\nin the [OTHER] section.\nNote: If you don\'t do '
               f'this, this dialog will interrupt the tumbler.')
        JMQtMessageBox(self, msg, mbtype="info", title="Setting fee limits.")
        return relfee, absfee

    def startJoin(self):
        schedule_len = len(list(
            filter(lambda x: x[-1] == 0, self.spendstate.loaded_schedule)))
        need_cache, callback = self.cache_keypairs(self.startJoin_callback,
                                                   tx_cnt=schedule_len)
        if need_cache:
            if callback:
                self.spendstate.waiting = True
                self.jm_dlg.statusBar.showMessage(
                    "Caching keypairs to sign ...")
            else:
                self.logger.info('Need password to cache keypairs to sign')
                self.spendstate.waiting = False
            return

        self.logger.debug('starting coinjoin ..')
        # Decide whether to interrupt processing to sanity check the fees
        jmman = self.jmman
        if self.tumbler_options:
            check_offers_callback = self.checkOffersTumbler
        elif GUIconf.checktx:
            check_offers_callback = self.checkOffers
        else:
            check_offers_callback = None

        destaddrs = self.tumbler_destaddrs if self.tumbler_options else []
        custom_change = None
        if len(self.changeInput.text().strip()) > 0:
            custom_change = str(self.changeInput.text().strip())
        jmman = self.jmman
        maxcjfee = get_max_cj_fee_values(jmman,
                                         user_callback=self.getMaxCJFees)
        self.logger.info("Using maximum coinjoin fee limits"
                         " per maker of {:.4%}, {} ".format(
                             maxcjfee[0], amount_to_str(maxcjfee[1])))
        self.taker = Taker(jmman,
                           self.spendstate.loaded_schedule,
                           maxcjfee,
                           order_chooser=fidelity_bond_weighted_order_choose,
                           callbacks=[check_offers_callback,
                                      self.takerInfo,
                                      self.takerFinished],
                           tdestaddrs=destaddrs,
                           custom_change_address=custom_change,
                           ignored_makers=jmman.jmw.ignored_makers)
        self.clientfactory = JMClientProtocolFactory(self.taker)
        jmman.set_client_factory(self.clientfactory)
        coro = self.clientfactory.getClient().clientStart()
        asyncio.run_coroutine_threadsafe(coro, self.jmman.loop)
        self.jm_dlg.statusBar.showMessage("Connecting to message channels ...")

    def takerInfo(self, infotype, infomsg):
        if not self.taker:
            return
        self.taker_info_signal.emit((infotype, infomsg))

    def _takerInfo(self, args):
        infotype, infomsg = args
        if infotype == "INFO":
            # use of a dialog interrupts processing?, investigate.
            if len(infomsg) > 200:
                self.logger.info("INFO: " + infomsg)
            else:
                self.jm_dlg.statusBar.showMessage(infomsg)
        elif infotype == "ABORT":
            JMQtMessageBox(self, infomsg,
                           mbtype='warn')
            # Abort signal explicitly means this transaction will not continue.
            self.abortTransactions()
        else:
            raise NotImplementedError

    def checkOffersTumbler(self, offers_fees, cjamount):
        return tumbler_filter_orders_callback(
            self.jmman, offers_fees, cjamount, self.taker)

    def checkOffers(self, offers_fee, cjamount):
        if not self.taker:
            return
        res_fut = self.jmman.loop.create_future()
        self.check_offers_signal.emit((res_fut, offers_fee, cjamount))
        return res_fut

    def _checkOffers(self, args):
        """Parse offers and total fee from client protocol,
        allow the user to agree or decide.
        """
        try:
            res_fut, offers_fee, cjamount = args
            if self.taker.aborted:
                self.logger.debug("Not processing offers, user has aborted.")
                res_fut.set_result(False)
                return

            if not offers_fee:
                JMQtMessageBox(self,
                               "Not enough matching offers found.",
                               mbtype='warn',
                               title="Error")
                self.giveUp()
                res_fut.set_result(False)
                return
            offers, total_cj_fee = offers_fee
            total_fee_pc = 1.0 * total_cj_fee / self.taker.cjamount

            mbinfo = []
            mbinfo.append("Sending amount: " +
                          amount_to_str(self.taker.cjamount))
            mbinfo.append("to address: " + self.taker.my_cj_addr)
            mbinfo.append(" ")
            mbinfo.append("Counterparties chosen:")
            mbinfo.append('Name,     Order id, Coinjoin fee (sat.)')
            for k, o in offers.items():
                if o['ordertype'] in ['sw0reloffer', 'swreloffer', 'reloffer']:
                    display_fee = int(self.taker.cjamount *
                                      float(o['cjfee'])) - int(o['txfee'])
                elif o['ordertype'] in ['sw0absoffer', 'swabsoffer',
                                        'absoffer']:
                    display_fee = int(o['cjfee']) - int(o['txfee'])
                else:
                    self.logger.debug("Unsupported order type: " +
                                      str(o['ordertype']) + ", aborting.")
                    self.giveUp()
                    res_fut.set_result(False)
                    return
                mbinfo.append(k + ', ' + str(o['oid']) + ',         ' + str(
                    display_fee))
            mbinfo.append('Total coinjoin fee = ' +
                          amount_to_str(total_cj_fee) +
                          ', or ' +
                          str(float('%.3g' % (100.0 * total_fee_pc))) + '%')
            title = 'Check Transaction'
            if total_fee_pc * 100 > GUIconf.check_high_fee:
                title += ': WARNING: Fee is HIGH!!'
            reply = JMQtMessageBox(self,
                                   '\n'.join([m + '<p>' for m in mbinfo]),
                                   mbtype='question',
                                   title=title)
            if reply == QMessageBox.StandardButton.Yes:
                # amount is now accepted;
                # The user is now committed to the transaction
                self.abortButton.setEnabled(False)
                res_fut.set_result(True)
                return
            else:
                self.filter_offers_response = "REJECT"
                self.giveUp()
                res_fut.set_result(False)
                return
        except Exception as e:
            res_fut.set_result(False)
            self.logger.info(f"Error in _checkOffers: {repr(e)}")

    def startNextTransaction(self):
        coro = self.clientfactory.getClient().clientStart()
        asyncio.run_coroutine_threadsafe(coro, self.jmman.loop)

    def takerFinished(self, res, fromtx=False, waittime=0.0, txdetails=None):
        if not self.taker:
            return
        self.taker_finished_signal.emit((res, fromtx, waittime, txdetails))

    def _takerFinished(self, args):
        """Callback (after pass-through signal) for jmclient.Taker
        on completion of each join transaction.
        """
        res, fromtx, waittime, txdetails = args
        # non-GUI-specific state updates first:
        if self.tumbler_options:
            jmman = self.jmman
            tumble_log = jmman.tumble_log
            tumbler_taker_finished_update(self.taker, tumble_log,
                                          self.tumbler_options, res,
                                          fromtx,
                                          waittime,
                                          txdetails)

        self.spendstate.loaded_schedule = self.taker.schedule
        # Shows the schedule updates in the GUI; TODO make this more visual
        if self.spendstate.typestate == 'multiple':
            self.updateSchedView()

        # GUI-specific updates; QTimer.singleShot serves the role
        # of reactor.callLater
        if fromtx == "unconfirmed":
            self.jm_dlg.statusBar.showMessage(
                "Transaction seen on network: " + self.taker.txid)
            if self.spendstate.typestate == 'single':
                self.clearFields(None)
                JMQtMessageBox(self, "Transaction broadcast OK. You can"
                                     " safely \nshut down if you don't want"
                                     " to wait.",
                               title="Success")
            # TODO: theoretically possible to miss this if confirmed event
            # seen before unconfirmed.
            self.persistTxToHistory(self.taker.my_cj_addr, self.taker.cjamount,
                                    self.taker.txid)

            # TODO prob best to completely fold multiple and tumble to reduce
            # complexity/duplication
            if (self.spendstate.typestate == 'multiple'
                    and not self.tumbler_options):
                self.taker.jmman.wallet.save_db()  # FIXME?
            return
        if fromtx:
            if res:
                self.jm_dlg.statusBar.showMessage("Transaction confirmed: " +
                                                  self.taker.txid)
                # singleShot argument is in milliseconds
                if self.nextTxTimer:
                    self.nextTxTimer.stop()
                self.nextTxTimer = QTimer()
                self.nextTxTimer.setSingleShot(True)
                self.nextTxTimer.timeout.connect(self.startNextTransaction)
                self.nextTxTimer.start(int(waittime*60*1000))
                # QTimer.singleShot(int(self.taker_finished_waittime*60*1000),
                #                         self.startNextTransaction)
            else:
                if self.tumbler_options:
                    self.jm_dlg.statusBar.showMessage("Transaction failed,"
                                                      " trying again...")
                    QTimer.singleShot(0, self.startNextTransaction)
                else:
                    # currently does not continue for non-tumble schedules
                    self.giveUp()
        else:
            if res:
                self.jm_dlg.statusBar.showMessage("All transaction(s)"
                                                  " completed successfully.")
                if len(self.taker.schedule) == 1:
                    msg = "Transaction has been confirmed.\n" + "Txid: " + \
                                           str(self.taker.txid)
                else:
                    msg = "All transactions have been confirmed."
                JMQtMessageBox(self, msg, title="Success")
                self.cleanUp()
            else:
                self.giveUp()

    def persistTxToHistory(self, addr, amt, txid):
        # persist the transaction to history
        now = round(datetime.datetime.now().timestamp())
        self.jmman.jmw.add_jm_tx(txid, addr, amt, now)
        # update the TxHistory tab
        self.jm_dlg.history_tab.updateTxInfo()

    def toggleButtons(self):
        """Refreshes accessibility of buttons in the (single, multiple) join
        tabs based on the current state as defined by the SpendStateMgr
        instance. Thus, should always be called on any update to that instance.
        """
        # The first two buttons are for the single join tab; the remaining 4
        # are for the multijoin tab.
        btns = (self.startButton, self.abortButton,
                self.schedule_set_button, self.wallet_schedule_button,
                self.schedule_generate_button, self.sch_startButton,
                self.sch_abortButton)
        if self.spendstate.runstate == 'ready':
            btnsettings = (True, False, True, True, True, True, False)
        elif self.spendstate.runstate == 'waiting':
            btnsettings = (False, False, False, False, False, False, False)
        elif self.spendstate.runstate == 'running':
            if self.spendstate.typestate == 'single':
                # can only abort current run, nothing else
                btnsettings = (False, True, False, False, False, False, False)
            elif self.spendstate.typestate == 'multiple':
                btnsettings = (False, False, False, False, False, False, True)
            else:
                assert False
        else:
            assert False

        for b, s in zip(btns, btnsettings):
            b.setEnabled(s)

    def abortTransactions(self):
        jmman = self.jmman
        coro = jmman.jmw.cleanup_keypairs()
        asyncio.run_coroutine_threadsafe(coro, jmman.loop)
        self.taker.aborted = True
        self.giveUp()

    def giveUp(self):
        """Inform the user that the transaction failed, then reset state.
        """
        self.logger.debug("Transaction aborted.")
        self.jm_dlg.statusBar.showMessage("Transaction aborted.")
        if self.taker and len(self.taker.ignored_makers) > 0:
            JMQtMessageBox(self, "These Makers did not respond, and will be \n"
                           "ignored in future: \n" + str(
                            ','.join(self.taker.ignored_makers)),
                           title="Transaction aborted")
            self.jmman.jmw.ignored_makers.extend(self.taker.ignored_makers)
        self.cleanUp()

    def cleanUp(self):
        """Reset state to 'ready'
        """
        # Qt specific: because schedules can restart in same app instance,
        # we must clean up any existing delayed actions via singleShot.
        # Currently this should only happen via self.abortTransactions.
        if self.nextTxTimer:
            self.nextTxTimer.stop()
        self.spendstate.reset()
        self.tumbler_options = None
        self.tumbler_destaddrs = None

    def validateSingleSend(self):
        if len(self.addressInput.text()) == 0:
            JMQtMessageBox(
                self,
                "Recipient address must be provided.",
                mbtype='warn', title="Error")
            return False

        valid = bitcoin.is_address(str(self.addressInput.text().strip()))
        if not valid:
            JMQtMessageBox(self, 'Invalid address',
                           mbtype='warn', title="Error")
            return False
        if len(self.numCPInput.text()) == 0:
            JMQtMessageBox(
                self,
                "Number of counterparties must be provided. Enter '0'"
                " to do a direct send instead of a CoinJoin.",
                mbtype='warn', title="Error")
            return False
        if len(self.mixdepthInput.text()) == 0:
            JMQtMessageBox(
                self,
                "Mixdepth must be chosen.",
                mbtype='warn', title="Error")
            return False
        if len(self.amountInput.text()) == 0:
            JMQtMessageBox(
                self,
                "Amount, in bitcoins, must be provided.",
                mbtype='warn', title="Error")
            return False
        jmman = self.jmman
        if len(self.changeInput.text().strip()) != 0:
            dest_addr = str(self.addressInput.text().strip())
            change_addr = str(self.changeInput.text().strip())
            makercount = int(self.numCPInput.text())
            try:
                amount = amount_to_sat(self.amountInput.text())
            except ValueError as e:
                JMQtMessageBox(self, f'{repr(e)}', title="Error",
                               mbtype="warn")
                return False
            valid = bitcoin.is_address(change_addr)
            if not valid:
                JMQtMessageBox(self, "Custom change address is invalid.",
                               mbtype='warn', title="Error")
                return False

            if change_addr == dest_addr:
                msg = ''.join(["Custom change address cannot be the ",
                               "same as the recipient address."])
                JMQtMessageBox(self,
                               msg,
                               mbtype='warn', title="Error")
                return False
            if amount == 0:
                JMQtMessageBox(self, sweep_custom_change_warning,
                               mbtype='warn', title="Error")
                return False
            if makercount > 0:
                reply = JMQtMessageBox(self, general_custom_change_warning,
                                       mbtype='question', title="Warning")
                if reply == QMessageBox.StandardButton.No:
                    return False

            if makercount > 0:
                change_addr_type = guess_address_script_type(change_addr)
                wallet_type = jmman.wallet.get_txin_type()
                if change_addr_type != wallet_type:
                    reply = JMQtMessageBox(
                        self, nonwallet_custom_change_warning,
                        mbtype='question',
                        title="Warning"
                    )
                    if reply == QMessageBox.StandardButton.No:
                        return False

        return True


class CoinsTab(QWidget):

    def __init__(self, jm_dlg):
        super().__init__()
        self.jm_dlg = jm_dlg
        self.jmman = jm_dlg.jmman
        self.logger = self.jmman.logger
        self.initUI()

    def initUI(self):
        self.cTW = v = MyTreeWidget(self, self.create_menu, self.getHeaders())
        self.cTW.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection)
        self.cTW.header().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive)
        self.cTW.header().setStretchLastSection(False)
        self.cTW.on_update = self.updateUtxos
        v.header().resizeSection(0, 400)
        v.header().resizeSection(1, 130)
        v.header().resizeSection(2, 400)

        vbox = QVBoxLayout()
        self.setLayout(vbox)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        vbox.addWidget(self.cTW)
        self.updateUtxos()
        self.show()

    def getHeaders(self):
        '''Function included in case dynamic in future'''
        return ['Txid:n', 'Amount in BTC', 'Address', 'Label']

    def updateUtxos(self):
        """ Note that this refresh of the display only accesses in-process
        utxo database (no sync e.g.) so can be immediate.
        """
        jmman = self.jmman
        self.cTW.clear()

        def show_blank():
            m_item = QTreeWidgetItem(["No coins", "", "", ""])
            self.cTW.addChild(m_item)
            self.cTW.show()

        utxos_enabled = {}
        utxos_disabled = {}
        for i in range(GUIconf.max_mix_depth):
            utxos_e, utxos_d = jmman.jmw.get_utxos_enabled_disabled(i)
            if utxos_e != {}:
                utxos_enabled[i] = utxos_e
            if utxos_d != {}:
                utxos_disabled[i] = utxos_d
        if utxos_enabled == {} and utxos_disabled == {}:
            show_blank()
            return

        for i in range(GUIconf.max_mix_depth):
            uem = utxos_enabled.get(i)
            udm = utxos_disabled.get(i)
            m_item = QTreeWidgetItem(["Mixdepth " + str(i), '', '', ''])
            self.cTW.addChild(m_item)
            for heading in ["NOT FROZEN", "FROZEN"]:
                um = uem if heading == "NOT FROZEN" else udm
                seq_item = QTreeWidgetItem([heading, '', '', ''])
                m_item.addChild(seq_item)
                seq_item.setExpanded(True)
                if um is None:
                    item = QTreeWidgetItem(['None', '', '', ''])
                    seq_item.addChild(item)
                else:
                    for k, v in um.items():
                        # txid:index, btc, address
                        s = "{0:.08f}".format(v['value']/1e8)
                        a = v['address']
                        item = QTreeWidgetItem([k, s, a, v["label"]])
                        item.setFont(0, QFont(MONOSPACE_FONT))
                        seq_item.addChild(item)
                    m_item.setExpanded(True)

    def toggle_utxo_disable(self, txids, idxs):
        w = self.jmman.wallet
        for i in range(0, len(txids)):
            prevout_txid = txids[i]
            prevout_idx = idxs[i]
            prevout_str = f'{prevout_txid}:{prevout_idx}'
            tx = w.adb.get_transaction(prevout_txid)
            if not tx:
                continue
            tx_output = tx.outputs()[prevout_idx]
            addr = tx_output.address
            coins = w.adb.get_utxos(domain=[addr])
            coin = None
            for c in coins:
                if c.prevout.to_str() == prevout_str:
                    coin = c
                break
            if not coin:
                continue
            is_frozen = w.is_frozen_coin(coin)
            self.jm_dlg.mwin.set_frozen_state_of_coins([coin], not is_frozen)
        self.updateUtxos()

    def create_menu(self, position):
        # all selected items
        selected_items = self.cTW.selectedItems()
        txids = []
        idxs = []
        if len(selected_items) == 0:
            return
        try:
            for item in selected_items:
                if ':' not in item.text(0):
                    continue
                txid, idx = item.text(0).split(":")
                assert len(txid) == 64
                idx = int(idx)
                assert idx >= 0
                txids.append(txid)
                idxs.append(idx)
        except Exception as e:
            self.logger.error("Error retrieving txids in Coins tab: " +
                              repr(e))
            return
        # current item
        item = self.cTW.currentItem()
        if ':' not in item.text(0):
            return
        txid, idx = item.text(0).split(":")

        menu = QMenu()
        menu.addAction("Freeze/un-freeze utxo(s) (toggle)",
                       lambda: self.toggle_utxo_disable(txids, idxs))
        menu.addAction("Copy transaction id to clipboard",
                       lambda: QApplication.clipboard().setText(txid))
        menu.exec(self.cTW.viewport().mapToGlobal(position))


class TxHistoryTab(QWidget):

    def __init__(self, jm_dlg):
        super().__init__()
        self.jm_dlg = jm_dlg
        self.jmman = jm_dlg.jmman
        self.logger = self.jmman.logger
        self.initUI()

    def initUI(self):
        self.tHTW = MyTreeWidget(self, self.create_menu, self.getHeaders())
        self.tHTW.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tHTW.header().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive)
        self.tHTW.header().setStretchLastSection(False)
        self.tHTW.on_update = self.updateTxInfo
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        vbox.addWidget(self.tHTW)
        self.updateTxInfo()
        self.show()

    def getHeaders(self):
        '''Function included in case dynamic in future'''
        return ['Receiving address', 'Amount in BTC', 'Transaction id', 'Date']

    def updateTxInfo(self, txinfo=None):
        self.tHTW.clear()
        if not txinfo:
            txinfo = self.getTxInfoFromHistory()
        for t in txinfo:
            t_item = QTreeWidgetItem(t)
            self.tHTW.addChild(t_item)
        for i in range(4):
            self.tHTW.resizeColumnToContents(i)

    def getTxInfoFromHistory(self):
        txhist = []
        jm_txs = self.jmman.jmw.get_jm_txs()
        for txid, (address, amount, date) in jm_txs.items():
            txhist.append((address, amount, txid, date))
        txhist.sort(key=lambda x: x[3])
        return [(address, str(amount), txid,
                 datetime.datetime.fromtimestamp(date).strftime(DATE_FORMAT))
                for address, amount, txid, date in txhist]

    def create_menu(self, position):
        item = self.tHTW.currentItem()
        if not item:
            return
        address_valid = False
        if item:
            address = str(item.text(0))
            address_valid = bitcoin.is_address(address)

        menu = QMenu()
        if address_valid:
            menu.addAction("Copy address to clipboard",
                           lambda: QApplication.clipboard().setText(address))
        menu.addAction("Copy transaction id to clipboard",
                       lambda: QApplication.clipboard().setText(
                           str(item.text(2))))
        menu.addAction("Copy full transaction info to clipboard",
                       lambda: QApplication.clipboard().setText(
                           ','.join([str(item.text(_)) for _ in range(4)])))
        menu.exec(self.tHTW.viewport().mapToGlobal(position))


class SettingsTab(QWidget):

    def __init__(self, jm_dlg):
        super().__init__()
        self.jm_dlg = jm_dlg
        self.jmman = jm_dlg.jmman
        self.logger = self.jmman.logger
        self.msg_channels = self.jmman.jmconf.get_msg_channels()
        self.settings_grid = None
        self.constructUI()

    def constructUI(self, *, update=False):
        jmman = self.jmman
        jmconf = jmman.jmconf
        if update and self.settings_grid is not None:
            for i in reversed(range(self.settings_grid.count())):
                self.settings_grid.itemAt(i).widget().setParent(None)
        else:
            self.outerGrid = QGridLayout()
            self.warn_ex_label = WarnExLabel(jmman, self.jm_dlg)
            self.outerGrid.addWidget(self.warn_ex_label, 0, 0, 1, -1)

            # subscribe_spent
            sub_spent_cb = QCheckBox(jmconf.subscribe_spent_data())
            sub_spent_cb.setChecked(jmconf.subscribe_spent)

            def on_sub_spent_state_changed(x):
                jmconf.subscribe_spent = (Qt.CheckState(x) ==
                                          Qt.CheckState.Checked)

            sub_spent_cb.stateChanged.connect(on_sub_spent_state_changed)
            self.outerGrid.addWidget(sub_spent_cb, 1, 0, 1, -1)

            b = QPushButton(_('Reset to defaults'))
            b.clicked.connect(self.reset_to_defaults)
            self.outerGrid.addLayout(Buttons(b), 2, 0)

        sA = QScrollArea()
        sA.setWidgetResizable(True)
        frame = QFrame()
        self.settings_grid = grid = QGridLayout()

        self.settingsFields = []
        j = 0
        for i, section in enumerate(conf_sections):
            if section == 'MESSAGING':
                index_map = {v: i for i, v in
                             enumerate(['onion', 'irc1', 'irc2'])}
                sorted_sections = sorted(
                    self.msg_channels.items(),
                    key=lambda pair: index_map.get(pair[0], 1e5))
                for subsection, msg_channel in sorted_sections:
                    if subsection == 'onion':
                        opts_names = ['enabled', 'type', 'socks5_host',
                                      'socks5_port', 'directory_nodes']
                    else:
                        opts_names = ['enabled', 'type', 'channel', 'host',
                                      'port', 'usessl', 'socks5',
                                      'socks5_host', 'socks5_port']
                    index_map = {v: i for i, v in
                                 enumerate(opts_names)}
                    names = list(msg_channel.keys())
                    subsection_name = f'{section}:{subsection}'
                    newSettingsFields = self.getSettingsFields(subsection_name,
                                                               names)
                    newSettingsFields = sorted(
                        newSettingsFields,
                        key=lambda pair: index_map.get(pair[0].text(), 1e5))
                    self.settingsFields.extend(newSettingsFields)
                    sL = QLabel(subsection_name)
                    sL.setStyleSheet("QLabel {color: green;}")
                    grid.addWidget(sL)
                    j += 1
                    for k, ns in enumerate(newSettingsFields):
                        grid.addWidget(ns[0], j, 0)
                        # try to find the tooltip for this label
                        # it might not be there
                        if str(ns[0].text()) in config_tips:
                            ttS = config_tips[str(ns[0].text())]
                            ns[0].setToolTip(ttS)
                        grid.addWidget(ns[1], j, 1)
                        sfindex = (len(self.settingsFields) -
                                   len(newSettingsFields) + k)
                        if isinstance(ns[1], QCheckBox):
                            ns[1].toggled.connect(
                                lambda checked, s=subsection_name, q=sfindex:
                                    self.handleEdit(s, self.settingsFields[q],
                                                    checked))
                        else:
                            ns[1].editingFinished.connect(
                                lambda q=sfindex, s=subsection_name:
                                    self.handleEdit(s, self.settingsFields[q]))
                        j += 1
            else:
                names = conf_names[section]
                newSettingsFields = self.getSettingsFields(section, names)
                self.settingsFields.extend(newSettingsFields)
                sL = QLabel(section)
                sL.setStyleSheet("QLabel {color: green;}")
                grid.addWidget(sL)
                j += 1
                for k, ns in enumerate(newSettingsFields):
                    grid.addWidget(ns[0], j, 0)
                    # try to find the tooltip for this label from config tips;
                    # it might not be there
                    if str(ns[0].text()) in config_tips:
                        ttS = config_tips[str(ns[0].text())]
                        ns[0].setToolTip(ttS)
                    grid.addWidget(ns[1], j, 1)
                    sfindex = (len(self.settingsFields) -
                               len(newSettingsFields) + k)
                    if isinstance(ns[1], QCheckBox):
                        ns[1].toggled.connect(
                            lambda checked, s=section, q=sfindex:
                                self.handleEdit(s, self.settingsFields[q],
                                                checked))
                    else:
                        ns[1].editingFinished.connect(
                            lambda q=sfindex, s=section:
                                self.handleEdit(s, self.settingsFields[q]))
                    j += 1
        self.outerGrid.addWidget(sA, 3, 0)

        sA.setWidget(frame)
        frame.setLayout(grid)
        frame.adjustSize()
        if not update:
            self.setLayout(self.outerGrid)
        self.show()

    def reset_to_defaults(self):
        reply = JMQtMessageBox(self,
                               "Do you want to reset all settings"
                               " to default values?",
                               title="Confirm reset settings",
                               mbtype='question')
        if reply != QMessageBox.StandardButton.Yes:
            return
        conf_keys = set()
        for section, keys in conf_names.items():
            conf_keys |= set(keys)
        jmconf = self.jmman.jmconf
        jmconf.reset_to_defaults(conf_keys)
        jmconf.reset_mincjamount()
        self.constructUI(update=True)

    def handleEdit(self, section, t, checked=None):
        global GUIconf
        jmman = self.jmman
        sBar = self.jm_dlg.statusBar
        if section.startswith('MESSAGING'):
            subsection = section.split(':')[-1]
            oname = str(t[0].text())
            config_types.get(oname)
            if isinstance(t[1], QCheckBox):
                oval = checked
            else:
                oval = t[1].text()
            if oname in ["port", 'socks5_port']:
                oval = int(oval)
            self.msg_channels[subsection][oname] = oval
            self.jmman.jmconf.set_msg_channels(self.msg_channels)
        else:
            oname = str(t[0].text())
            if isinstance(t[1], QCheckBox):
                setattr(jmman.jmconf, oname, bool(checked))
                oval = str(getattr(jmman.jmconf, oname))
            else:
                config_types.get(oname)
                otype = config_types.get(oname) or int
                oval = t[1].text()
                try:
                    if section == 'GUI':
                        setattr(GUIconf, oname, otype(oval))
                        val = str(getattr(GUIconf, oname))
                    else:
                        setattr(jmman.jmconf, oname, otype(oval))
                        val = str(getattr(jmman.jmconf, oname))
                    if val != oval:
                        t[1].setText(val)
                        if oname == 'tx_fees':
                            targets = sorted(FEE_ETA_TARGETS)
                            msg = (f'tx_fees is set to closest high value'
                                   f' {val} from electrum'
                                   f' FEE_ETA_TARGETS {targets}')
                            sBar.showMessage(msg)
                except Exception as e:
                    sBar.showMessage(f'{oname} can not be persisted: {e}')
            if oname == 'mixdepth':
                self.jm_dlg.wallet_tab.updateWalletInfo()
                self.jm_dlg.coins_tab.updateUtxos()
        self.logger.debug(f'setting section: {section}, name: {oname}'
                          f' to: {oval}')

    def getSettingsFields(self, section, names):
        results = []
        jmman = self.jmman
        if section.startswith('MESSAGING:'):
            subsection = section.split(':')[-1]
            for name, val in self.msg_channels[subsection].items():
                if name == 'type':
                    continue
                t = config_types.get(name, type(None))
                if t == int:
                    sf = QLineEdit(str(val))
                    if name in ["port", 'socks5_port']:
                        sf.setValidator(JMIntValidator(1, 65535))
                elif t == bool:
                    sf = QCheckBox()
                    sf.setChecked(val)
                else:
                    sf = QLineEdit(str(val))
                results.append((QLabel(name), sf))
            return results
        for name in names:
            val = None
            for n in conf_names[section]:
                if n == name:
                    if section == 'GUI':
                        val = str(getattr(GUIconf, name))
                    else:
                        val = str(getattr(jmman.jmconf, name))
                    break
            if name in config_types:
                t = config_types[name]
                if t == bool:
                    sf = QCheckBox()
                    checked = True if val == 'True' else False
                    sf.setChecked(checked)
                elif t == 'amount':
                    sf = BitcoinAmountEdit(val)
                elif t:
                    sf = QLineEdit(val)
                    if t == int:
                        if name == "tx_fees":
                            # must account for both tx_fees settings type,
                            # and we set upper limit well above default absurd
                            # check just in case a high value is needed:
                            sf.setValidator(JMIntValidator(1, 1000000))
                else:
                    continue
            else:
                sf = QLineEdit(val)
            results.append((QLabel(name), sf))
        return results


def get_wallet_printout(jmman):
    """Given a WalletService object, retrieve the list of
    addresses and corresponding balances to be displayed.
    We retrieve a WalletView abstraction, and iterate over
    sub-objects to arrange the per-mixdepth and per-address lists.
    The format of the returned data is:
    rows: is of format [[[addr,index,bal,status,label],[addr,...]]*5,
    [[addr, index,..], [addr, index..]]*5]
    mbalances: is a simple array of 5 mixdepth balances
    xpubs: [[xpubext, xpubint], ...]
    Bitcoin amounts returned are in btc, not satoshis
    """
    walletview = wallet_display(jmman, False, serialized=False)
    rows = []
    mbalances = []
    xpubs = []
    for j, acct in enumerate(walletview.children):
        mbalances.append(acct.get_fmt_balance())
        rows.append([])
        xpubs.append([])
        for i, branch in enumerate(acct.children):
            xpubs[j].append(branch.xpub)
            rows[j].append([])
            for entry in branch.children:
                rows[-1][i].append([entry.serialize_address(),
                                    entry.serialize_wallet_position(),
                                    entry.serialize_amounts(),
                                    entry.serialize_status(),
                                    entry.serialize_label()])
        # Append the account xpub to the end of the list
        account_xpub = acct.xpub
        xpubs[j].append(account_xpub)
    total_bal = walletview.get_fmt_balance()
    return (rows, mbalances, xpubs, total_bal)
