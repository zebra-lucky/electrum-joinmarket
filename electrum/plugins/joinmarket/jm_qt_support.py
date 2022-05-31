# -*- coding: utf-8 -*-

'''
Qt files for the wizard for initiating a tumbler run.


    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''
import string

from PyQt6.QtCore import Qt, QLocale, pyqtSignal, QSize
from PyQt6.QtGui import (QIntValidator, QDoubleValidator, QValidator,
                         QBrush, QColor)
from PyQt6.QtWidgets import (QWidget, QGridLayout, QHBoxLayout, QLabel,
                             QVBoxLayout, QMessageBox,
                             QSizePolicy, QTextEdit, QLineEdit, QLayout,
                             QComboBox, QTreeWidget, QHeaderView, QButtonGroup,
                             QWizardPage, QWizard, QStyledItemDelegate,
                             QRadioButton)

from electrum.bitcoin import is_address

from .jmbitcoin.amount import amount_to_sat, btc_to_sat, sat_to_btc
from .jmclient import get_tumble_schedule


# configuration types
conf_sections = [
    'OTHER',
    'TIMEOUT',
    'POLICY',
    'MESSAGING',
    'GUI',
]

conf_names = {
    'TIMEOUT': [
        'maker_timeout_sec',
        'unconfirm_timeout_sec',
        'confirm_timeout_hours',
    ],
    'POLICY': [
        'merge_algorithm',
        'tx_fees',
        'tx_fees_factor',
        'absurd_fee_per_kb',
        'max_sweep_fee_change',
        'tx_broadcast',
        'minimum_makers',
        'max_sats_freeze_reuse',
        'interest_rate',
        'bondless_makers_allowance',
        'bond_value_exponent',
        'taker_utxo_retries',
        'taker_utxo_age',
        'taker_utxo_amtpercent',
    ],
    'GUI': [
        'check_high_fee',
        'max_mix_depth',
        'order_wait_time',
        'checktx',
    ],
    'OTHER': [
        'max_cj_fee_abs',
        'max_cj_fee_rel',
        'max_cj_fee_confirmed',
        'mincjamount',
    ],
}

config_types = {
    # TIMEOUT section
    'maker_timeout_sec': int,
    'unconfirm_timeout_sec': int,
    'confirm_timeout_hours': int,
    # POLICY section
    'merge_algorithm': str,
    'gaplimit': int,
    'tx_fees': int,
    'tx_fees_factor': float,
    'absurd_fee_per_kb': 'amount',
    'max_sweep_fee_change': float,
    'tx_broadcast': str,
    'minimum_makers': int,
    'max_sats_freeze_reuse': int,
    'interest_rate': float,
    'bondless_makers_allowance': float,
    'bond_value_exponent': float,
    'taker_utxo_retries': int,
    'taker_utxo_age': int,
    'taker_utxo_amtpercent': int,
    'max_cj_fee_abs': int,
    'max_cj_fee_rel': float,
    'max_cj_fee_confirmed': bool,
    'mincjamount': int,
    # MESSAGING section
    'enabled': bool,
    'port': int,
    'socks5_port': int,
    'socks5': bool,
    'usessl': bool,
    # GUI section
    'check_high_fee': int,
    'max_mix_depth': int,
    'order_wait_time': int,
    'checktx': bool,
}

config_tips = {
    'max_cj_fee_abs': 'Maximum absolute coinjoin fee in satoshi to pay\nto a '
    'single market maker for a transaction.\nBoth the limits given '
    'in max-cj-fee-abs and max-cj-fee-rel\nmust be exceeded in order to not '
    'consider a certain offer.',
    'max_cj_fee_rel': 'Maximum relative coinjoin fee, in fractions of the\n'
    'coinjoin value, to pay to a single market maker for a transaction.\nBoth '
    'the limits given in max-cj-fee-abs and max-cj-fee-rel\nmust be exceeded '
    'in order to not consider a certain offer.\nExample: 0.001 for a maximum '
    'fee of 0.1% of the cj amount',
    'max_cj_fee_confirmed': 'Confirm use of '
    'values max_cj_fee_abs, max_cj_fee_rel\nto not show info dialog with '
    'default values\non each coinjoin transaction.',
    'checktx': 'whether to check fees before completing transaction',
    'host': 'hostname for IRC server',
    'channel': 'channel name on IRC server',
    'port': 'port for connecting to IRC server',
    'usessl': "'true'/'false' to use SSL for each connection to IRC\n",
    'socks5': "'true'/'false' to use a SOCKS5 proxy for each connection",
    'socks5_host': 'host for SOCKS5 proxy',
    'socks5_port': 'port for SOCKS5 proxy',
    'maker_timeout_sec': 'timeout for waiting for replies from makers',
    'merge_algorithm': 'for dust sweeping, try merge_algorithm = gradual, \n'
    'for more rapid dust sweeping, try merge_algorithm = greedy, \n'
    'for most rapid dust sweeping, try merge_algorithm = greediest \n',
    'tx_fees':
    'the fee estimate is based on a projection of how many satoshis \n'
    'per kB are needed to get in one of the next N blocks, N set here \n'
    'as the value of "tx_fees". This estimate is high if you set N=1, \n'
    'so we choose N=5 for a more reasonable figure as our default.\n'
    'For values less than 1001 value approximated to one from '
    '[1, 2, 5, 10, 25] list.\n'
    'Alternative: Any value higher than 1000 will be interpreted as \n'
    'fee value in satoshi per KB. This overrides the dynamic estimation.',
    'gaplimit': 'How far forward to search for used addresses'
    ' in the HD wallet',
    'check_high_fee': 'Percent fee considered dangerously high, default 2%',
    'max_mix_depth': 'Total number of mixdepths in the wallet, default 5',
    'order_wait_time': 'How long to wait for orders to arrive on entering\n' +
    'the message channel, default is 30s',
    "absurd_fee_per_kb": "maximum amount per kilobyte you are willing"
    " to pay,\nwhatever the fee estimate currently says.",
    "tx_broadcast": "Options: self, random-peer, not-self"
    " (note: random-maker\nis not currently supported).\n"
    "self = broadcast transaction with your own ip\n"
    "random-peer = everyone who took part in the coinjoin has\n" +
    "a chance of broadcasting.\n" +
    "not-self = never broadcast with your own ip.",
    "taker_utxo_retries": "Global consensus parameter, do NOT change.\n" +
    "See documentation of use of 'commitments'.",
    "taker_utxo_age": "Global consensus parameter, do NOT change.\n" +
    "See documentation of use of 'commitments'.",
    "taker_utxo_amtpercent": "Global consensus parameter, do not change.\n" +
    "See documentation of use of 'commitments'.",
    "minimum_makers": "The minimum number of counterparties"
    " for the transaction\nto complete (default 2). If set to a high value"
    " it can cause transactions\nto fail much more frequently.",
    "max_sats_freeze_reuse": "Threshold number of satoshis below which an\n" +
    "incoming utxo to a reused address in the wallet will\n" +
    "be AUTOMATICALLY frozen. -1 means always freeze reuse.",
    "mincjamount": "minimum coinjoin amount in transaction in satoshi, "
    "default 100k",
}

# Temporarily disabled
donation_more_message = "Currently disabled"
"""
donation_more_message = '\n'.join(
            ['If the calculated change for your transaction',
             'is smaller than the value you choose (default 0.01 btc)',
             'then that change is sent as a donation. If your change',
             'is larger than that, there will be no donation.', '',
             'As well as helping the developers, this feature can,',
             'in certain circumstances, improve privacy, because there',
             'is no change output that can be linked with your inputs later.'])
"""


def JMQtMessageBox(obj, msg, mbtype='info', title='', detailed_text=None):
    mbtypes = {'info': QMessageBox.information,
               'crit': QMessageBox.critical,
               'warn': QMessageBox.warning,
               'question': QMessageBox.question}
    title = "JoinmarketQt - " + title
    if mbtype == 'question':
        return QMessageBox.question(
            obj, title, msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    else:
        if detailed_text:
            assert mbtype == 'info'

            class JMQtDMessageBox(QMessageBox):
                def __init__(self):
                    QMessageBox.__init__(self)
                    self.setSizeGripEnabled(True)
                    self.setSizePolicy(QSizePolicy.Policy.Expanding,
                                       QSizePolicy.Policy.Expanding)
                    self.layout().setSizeConstraint(
                        QLayout.SizeConstraint.SetMaximumSize)

                def resizeEvent(self, event):
                    self.setMinimumHeight(0)
                    self.setMaximumHeight(16777215)
                    self.setMinimumWidth(0)
                    self.setMaximumWidth(16777215)
                    result = super().resizeEvent(event)
                    details_box = self.findChild(QTextEdit)
                    if details_box is not None:
                        details_box.setMinimumHeight(0)
                        details_box.setMaximumHeight(16777215)
                        details_box.setMinimumWidth(0)
                        details_box.setMaximumWidth(16777215)
                        details_box.setSizePolicy(QSizePolicy.Policy.Expanding,
                                                  QSizePolicy.Policy.Expanding)
                    return result

            b = JMQtDMessageBox()
            b.setIcon(QMessageBox.Information)
            b.setWindowTitle(title)
            b.setText(msg)
            b.setDetailedText(detailed_text)
            b.setStandardButtons(QMessageBox.Ok)
            b.exec()
        else:
            mbtypes[mbtype](obj, title, msg)


class MyTreeWidget(QTreeWidget):

    def __init__(self,
                 parent,
                 create_menu,
                 headers,
                 stretch_column=None,
                 editable_columns=None):
        QTreeWidget.__init__(self, parent)
        self.parent = parent
        self.stretch_column = stretch_column
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(create_menu)
        self.setUniformRowHeights(True)
        # extend the syntax for consistency
        self.addChild = self.addTopLevelItem
        self.insertChild = self.insertTopLevelItem
        self.editor = None
        self.pending_update = False
        if editable_columns is None:
            editable_columns = [stretch_column]
        self.editable_columns = editable_columns
        self.itemActivated.connect(self.on_activated)
        self.update_headers(headers)

    def update_headers(self, headers):
        self.setColumnCount(len(headers))
        self.setHeaderLabels(headers)
        self.header().setStretchLastSection(False)
        for col in range(len(headers)):
            # note, a single stretch column is currently not used.
            self.header().setSectionResizeMode(
                col, QHeaderView.ResizeMode.Interactive)

    def editItem(self, item, column):
        if column in self.editable_columns:
            self.editing_itemcol = (item, column, item.text(column))
            # Calling setFlags causes on_changed events for some reason
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEditable)
            QTreeWidget.editItem(self, item, column)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_F2:
            self.on_activated(self.currentItem(), self.currentColumn())
        else:
            QTreeWidget.keyPressEvent(self, event)

    def permit_edit(self, item, column):
        return (column in self.editable_columns and
                self.on_permit_edit(item, column))

    def on_permit_edit(self, item, column):
        return True

    def on_activated(self, item, column):
        if self.permit_edit(item, column):
            self.editItem(item, column)
        else:
            pt = self.visualItemRect(item).bottomLeft()
            pt.setX(50)
            self.customContextMenuRequested.emit(pt)

    def createEditor(self, parent, option, index):
        self.editor = QStyledItemDelegate.createEditor(self.itemDelegate(),
                                                       parent, option, index)
        self.editor.connect(self.editor, pyqtSignal("editingFinished()"),
                            self.editing_finished)
        return self.editor

    def editing_finished(self):
        # Long-time QT bug - pressing Enter to finish editing signals
        # editingFinished twice.  If the item changed the sequence is
        # Enter key:  editingFinished, on_change, editingFinished
        # Mouse: on_change, editingFinished
        # This mess is the cleanest way to ensure we make the
        # on_edited callback with the updated item
        if self.editor:
            (item, column, prior_text) = self.editing_itemcol
            if self.editor.text() == prior_text:
                self.editor = None  # Unchanged - ignore any 2nd call
            elif item.text(column) == prior_text:
                pass  # Buggy first call on Enter key, item not yet updated
            else:
                # What we want - the updated item
                self.on_edited(*self.editing_itemcol)
                self.editor = None

            # Now do any pending updates
            if self.editor is None and self.pending_update:
                self.pending_update = False
                self.on_update()

    def on_edited(self, item, column, prior):
        '''Called only when the text actually changes'''
        key = str(item.data(0, Qt.ItemDataRole.UserRole))
        text = item.text(column)
        self.parent.wallet.set_label(key, text)
        if text:
            item.setForeground(column, QBrush(QColor('black')))
        else:
            text = self.parent.wallet.get_default_label(key)
            item.setText(column, text)
            item.setForeground(column, QBrush(QColor('gray')))
        self.parent.history_list.update()
        self.parent.update_completions()

    def update(self):
        # Defer updates if editing
        if self.editor:
            self.pending_update = True
        else:
            self.on_update()

    def on_update(self):
        pass

    def get_leaves(self, root):
        child_count = root.childCount()
        if child_count == 0:
            yield root
        for i in range(child_count):
            item = root.child(i)
            for x in self.get_leaves(item):
                yield x

    def filter(self, p, columns):
        p = p.lower()
        for item in self.get_leaves(self.invisibleRootItem()):
            item.setHidden(all([item.text(column).lower().find(p) == -1
                                for column in columns]))


class JMIntValidator(QIntValidator):

    def __init__(self, minval, maxval):
        super().__init__(minval, maxval)
        self.minval = minval
        self.maxval = maxval
        self.allowed = set(string.digits)

    def validate(self, arg__1, arg__2):
        if not arg__1:
            return (QValidator.State.Intermediate, arg__1, arg__2)
        if not set(arg__1) <= self.allowed:
            return QValidator.State.Invalid
        # above guarantees integer
        if not (int(arg__1) <= self.maxval and int(arg__1) >= self.minval):
            return (QValidator.State.Invalid, arg__1, arg__2)
        return super().validate(arg__1, arg__2)


class QDoubleValidatorC(QDoubleValidator):
    '''Set locale to C, to support dot as decimal_point separator'''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setLocale(QLocale.c())


class BitcoinAmountBTCValidator(QDoubleValidator):

    def __init__(self):
        super().__init__(0.00000000, 20999999.9769, 8)
        self.setLocale(QLocale.c())
        # Only numbers and "." as a decimal separator must be allowed,
        # no thousands separators, as per BIP21
        self.allowed = set(string.digits + ".")

    def validate(self, arg__1, arg__2):
        if not arg__1:
            return (QValidator.State.Intermediate, arg__1, arg__2)
        if not set(arg__1) <= self.allowed:
            return (QValidator.State.Invalid, arg__1, arg__2)
        return super().validate(arg__1, arg__2)


class BitcoinAmountSatValidator(JMIntValidator):

    def __init__(self):
        super().__init__(0, 2147483647)


class BitcoinAmountEdit(QWidget):

    def __init__(self, default_value):
        super().__init__()
        layout = QHBoxLayout()
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMaximumSize)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(1)
        self.valueInputBox = QLineEdit()
        self.editingFinished = self.valueInputBox.editingFinished
        layout.addWidget(self.valueInputBox)
        self.unitChooser = QComboBox()
        self.unitChooser.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.unitChooser.setIconSize(QSize(0, 0))
        self.unitChooser.addItems(["BTC", "sat"])
        self.unitChooser.currentIndexChanged.connect(self.onUnitChanged)
        self.BTCValidator = BitcoinAmountBTCValidator()
        self.SatValidator = BitcoinAmountSatValidator()
        self.setModeBTC()
        layout.addWidget(self.unitChooser)
        if default_value:
            self.valueInputBox.setText(str(sat_to_btc(amount_to_sat(
                default_value))))
        self.setLayout(layout)

    def setModeBTC(self):
        self.valueInputBox.setPlaceholderText("0.00000000")
        self.valueInputBox.setMaxLength(17)
        self.valueInputBox.setValidator(self.BTCValidator)

    def setModeSat(self):
        self.valueInputBox.setPlaceholderText("0")
        self.valueInputBox.setMaxLength(16)
        self.valueInputBox.setValidator(self.SatValidator)

    # index: 0 - BTC, 1 - sat
    def onUnitChanged(self, index):
        if index == 0:
            # switch from sat to BTC
            sat_amount = self.valueInputBox.text()
            self.setModeBTC()
            if sat_amount:
                self.valueInputBox.setText('%.8f' % sat_to_btc(sat_amount))
        else:
            # switch from BTC to sat
            btc_amount = self.valueInputBox.text()
            self.setModeSat()
            if btc_amount:
                self.valueInputBox.setText(str(btc_to_sat(btc_amount)))

    def setText(self, text):
        if text:
            if self.unitChooser.currentIndex() == 0:
                self.valueInputBox.setText(str(sat_to_btc(text)))
            else:
                self.valueInputBox.setText(str(text))
        else:
            self.valueInputBox.setText('')

    def setEnabled(self, enabled):
        self.valueInputBox.setEnabled(enabled)
        self.unitChooser.setEnabled(enabled)

    def text(self):
        if len(self.valueInputBox.text()) == 0:
            return ''
        elif self.unitChooser.currentIndex() == 0:
            return str(btc_to_sat(self.valueInputBox.text()))
        else:
            return self.valueInputBox.text()


class SchDynamicPage1(QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
        self.setTitle("Tumble schedule generation")
        self.setSubTitle("Set parameters for the sequence of transactions"
                         " in the tumble.")
        results = []
        sN = ['Average number of counterparties',
              'How many mixdepths to tumble through',
              'Average wait time between transactions, in minutes',
              'Average number of transactions per mixdepth']
        # Tooltips
        sH = ["How many other participants are in each coinjoin, on average;"
              " but\neach individual coinjoin will have a number that's varied"
              " according to\nsettings on the next page",
              "For example, if you start at mixdepth 1 and enter 4 here, the"
              " tumble\nwill move coins from mixdepth 1 to mixdepth 5",
              "This is the time waited *after* 1 confirmation has occurred,"
              " and is\nvaried randomly.",
              "Will be varied randomly, see advanced settings next page"]
        # types
        sT = [int, int, float, int]
        # constraints
        sMM = [(3, 20), (2, 7), (0.00000001, 100.0, 8), (2, 10)]
        sD = ['9', '4', '60.0', '2']
        for x in zip(sN, sH, sT, sD, sMM):
            ql = QLabel(x[0])
            ql.setToolTip(x[1])
            qle = QLineEdit(x[3])
            if x[2] == int:
                qle.setValidator(QIntValidator(*x[4]))
            if x[2] == float:
                qle.setValidator(QDoubleValidatorC(*x[4]))
            results.append((ql, qle))
        layout = QGridLayout()
        layout.setSpacing(4)
        for i, x in enumerate(results):
            layout.addWidget(x[0], i + 1, 0)
            layout.addWidget(x[1], i + 1, 1, 1, 2)
        self.setLayout(layout)
        self.registerField("makercount", results[0][1])
        self.registerField("mixdepthcount", results[1][1])
        self.registerField("timelambda", results[2][1])
        self.registerField("txcountparams", results[3][1])


class SchDynamicPage2(QWizardPage):

    def initializePage(self):
        addrLEs = []
        requested_mixdepths = int(self.field("mixdepthcount"))
        testaddrs = ["", "", ""]
        # less than 3 is unacceptable for privacy effect, more is optional
        self.required_addresses = max(3, requested_mixdepths - 1)
        for i in range(self.required_addresses):
            if i >= self.addrfieldsused:
                self.layout.addWidget(QLabel("Destination address: " +
                                             str(i)), i, 0)
                if i < len(testaddrs):
                    addrLEs.append(QLineEdit(testaddrs[i]))
                else:
                    addrLEs.append(QLineEdit(""))
                self.layout.addWidget(addrLEs[-1], i, 1, 1, 2)
                # addrLEs[-1].editingFinished.connect(
                #     lambda: checkAddress(self, addrLEs[-1].text()))
                self.registerField("destaddr"+str(i), addrLEs[-1])
        self.addrfieldsused = self.required_addresses
        self.setLayout(self.layout)

    def __init__(self, parent):
        super().__init__(parent)
        self.setTitle("Destination addresses")
        self.setSubTitle("Enter destination addresses for coins; "
                         "minimum 3 for privacy. You may leave later"
                         " ones blank.")
        self.layout = QGridLayout()
        self.layout.setSpacing(4)
        self.addrfieldsused = 0


class SchFinishPage(QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
        self.setTitle("Advanced options")
        self.setSubTitle("(the default values are usually sufficient)")
        layout = QGridLayout()
        layout.setSpacing(4)

        results = []
        sN = ['Makercount sdev',
              'Tx count sdev',
              'Minimum maker count',
              'Minimum transaction count',
              'Min coinjoin amount',
              'Response wait time',
              'Stage 1 transaction wait time increase',
              'Rounding Chance']
        for w in ["One", "Two", "Three", "Four", "Five"]:
            sN += [w + " significant figures rounding weight"]
        # Tooltips
        sH = ["Standard deviation of the number of makers to use in each"
              " transaction.",
              "Standard deviation of the number of transactions to use in"
              " each mixdepth",
              "The lowest allowed number of maker counterparties.",
              "The lowest allowed number of transactions in one mixdepth.",
              "The lowest allowed size of any coinjoin, in satoshis.",
              "The time in seconds to wait for response from counterparties.",
              "The factor increase in wait time for stage 1 sweep coinjoins",
              "The probability of non-sweep coinjoin amounts being rounded"]
        for w in ["one", "two", "three", "four", "five"]:
            sH += ["If rounding happens (determined by Rounding Chance) then"
                   " this is the relative probability of rounding to " + w +
                   " significant figures"]
        # types
        sT = [float, float, int, int, int, float, float, float] + [int]*5
        # constraints
        sMM = [(0.0, 10.0, 2), (0.0, 10.0, 2), (2, 20),
               (1, 10), (100000, 100000000), (10.0, 500.0, 2), (0, 100, 1),
               (0.0, 1.0, 3)] + [(0, 10000)]*5
        sD = ['1.0', '1.0', '2', '2', '1000000', '20', '3', '0.25',
              '55', '15', '25', '65', '40']
        for x in zip(sN, sH, sT, sD, sMM):
            ql = QLabel(x[0])
            ql.setToolTip(x[1])
            qle = QLineEdit(x[3])
            if x[2] == int:
                qle.setValidator(QIntValidator(*x[4]))
            if x[2] == float:
                qle.setValidator(QDoubleValidatorC(*x[4]))
            results.append((ql, qle))
        layout = QGridLayout()
        layout.setSpacing(4)
        for i, x in enumerate(results):
            layout.addWidget(x[0], i + 1, 0)
            layout.addWidget(x[1], i + 1, 1, 1, 2)
        self.setLayout(layout)
        # fields not considered 'mandatory' as defaults are accepted
        self.registerField("makercountsdev", results[0][1])
        self.registerField("txcountsdev", results[1][1])
        self.registerField("minmakercount", results[2][1])
        self.registerField("mintxcount", results[3][1])
        self.registerField("mincjamount", results[4][1])
        self.registerField("waittime", results[5][1])
        self.registerField("stage1_timelambda_increase", results[6][1])
        self.registerField("rounding_chance", results[7][1])
        for i in range(5):
            self.registerField("rounding_sigfig_weight_" + str(i+1),
                               results[8+i][1])


class SchIntroPage(QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)
        self.setTitle("Generate a join transaction schedule")
        self.rbgroup = QButtonGroup(self)
        self.r0 = QRadioButton("Define schedule manually "
                               "(not yet implemented)")
        self.r0.setEnabled(False)
        self.r1 = QRadioButton("Generate a tumble schedule automatically")
        self.rbgroup.addButton(self.r0)
        self.rbgroup.addButton(self.r1)
        self.r1.setChecked(True)
        layout = QVBoxLayout()
        layout.addWidget(self.r0)
        layout.addWidget(self.r1)
        self.setLayout(layout)


class ScheduleWizard(QWizard):

    def __init__(self, jmman):
        super().__init__()
        self.setWindowTitle("Joinmarket schedule generator")
        self.jmman = jmman
        self.setPage(0, SchIntroPage(self))
        self.setPage(1, SchDynamicPage1(self))
        self.setPage(2, SchDynamicPage2(self))
        self.setPage(3, SchFinishPage(self))

    def get_destaddrs(self):
        return self.destaddrs

    def get_schedule(self, wallet_balance_by_mixdepth, max_mixdepth_in_wallet):
        self.destaddrs = []
        for i in range(self.page(2).required_addresses):
            daddrstring = str(self.field("destaddr"+str(i)))
            if is_address(daddrstring):
                self.destaddrs.append(daddrstring)
            elif daddrstring != "":
                JMQtMessageBox(self, "Error, invalid address", mbtype='crit',
                               title='Error')
                return None
        self.opts = {}
        self.opts['mixdepthcount'] = int(self.field("mixdepthcount"))
        self.opts['txfee'] = -1
        self.opts['addrcount'] = len(self.destaddrs)
        self.opts['makercountrange'] = (int(self.field("makercount")),
                                        float(self.field("makercountsdev")))
        self.opts['minmakercount'] = int(self.field("minmakercount"))
        self.opts['txcountparams'] = (int(self.field("txcountparams")),
                                      float(self.field("txcountsdev")))
        self.opts['mintxcount'] = int(self.field("mintxcount"))
        self.opts['timelambda'] = float(self.field("timelambda"))
        self.opts['waittime'] = float(self.field("waittime"))
        self.opts["stage1_timelambda_increase"] = float(
            self.field("stage1_timelambda_increase"))
        self.opts['mincjamount'] = int(self.field("mincjamount"))
        # needed for Taker to check:
        self.opts['rounding_chance'] = float(self.field("rounding_chance"))
        self.opts['rounding_sigfig_weights'] = tuple(
            [int(self.field("rounding_sigfig_weight_" + str(i+1)))
             for i in range(5)])
        self.jmman.jmconf.mincjamount = self.opts['mincjamount']
        return get_tumble_schedule(self.opts, self.destaddrs,
                                   wallet_balance_by_mixdepth,
                                   max_mixdepth_in_wallet)


class TumbleRestartWizard(QWizard):

    def __init__(self, jmman):
        super().__init__()
        self.jmman = jmman
        self.setWindowTitle("Restart tumbler schedule")
        self.setPage(0, RestartSettingsPage(self))

    def getOptions(self):
        self.opts = {}
        self.opts['mincjamount'] = int(self.field("mincjamount"))
        relfeeval = float(self.field("maxrelfee"))
        absfeeval = int(self.field("maxabsfee"))
        self.opts['maxcjfee'] = (relfeeval, absfeeval)
        # needed for Taker to check:
        self.jmman.jmconf.mincjamount = self.opts['mincjamount']
        return self.opts


class RestartSettingsPage(QWizardPage):

    def __init__(self, parent):
        super().__init__(parent)
        self.setTitle("Tumbler options")
        self.setSubTitle("Options settings that can be varied on restart")
        layout = QGridLayout()
        layout.setSpacing(4)

        results = []
        sN = ['Min coinjoin amount',
              'Max relative fee per counterparty (e.g. 0.005)',
              'Max fee per counterparty, satoshis (e.g. 10000)']
        # Tooltips
        sH = ["The lowest allowed size of any coinjoin, in satoshis.",
              "A decimal fraction (e.g. 0.001 = 0.1%) (this AND next"
              " must be violated to reject",
              "Integer number of satoshis (this AND previous must be"
              " violated to reject)"]
        # types
        sT = [int, float, int]
        # constraints
        sMM = [(100000, 100000000), (0.000001, 0.25, 6),
               (0, 10000000)]
        sD = ['1000000', '0.0005', '10000']
        for x in zip(sN, sH, sT, sD, sMM):
            ql = QLabel(x[0])
            ql.setToolTip(x[1])
            qle = QLineEdit(x[3])
            if x[2] == int:
                qle.setValidator(QIntValidator(*x[4]))
            if x[2] == float:
                qle.setValidator(QDoubleValidatorC(*x[4]))
            results.append((ql, qle))
        layout = QGridLayout()
        layout.setSpacing(4)
        for i, x in enumerate(results):
            layout.addWidget(x[0], i + 1, 0)
            layout.addWidget(x[1], i + 1, 1, 1, 2)
        self.setLayout(layout)
        # fields not considered 'mandatory' as defaults are accepted
        self.registerField("mincjamount", results[0][1])
        self.registerField("maxrelfee", results[1][1])
        self.registerField("maxabsfee", results[2][1])
