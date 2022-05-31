# -*- coding: utf-8 -*-

from functools import partial

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QPixmap, QIcon
from PyQt6.QtWidgets import QGridLayout, QHBoxLayout

from electrum.i18n import _
from electrum.network import Network
from electrum.plugin import hook

from electrum.gui.qt.main_window import StatusBarButton
from electrum.gui.qt.util import (EnterButton, WindowModalDialog, WWLabel,
                                  CloseButton)


# FIXME changed due to changes in external plugins code, need to check later.
# Currently external plugins does not work as need.
#
# def get_zipfile_module_path():
#    import inspect
#    from . import qt
#
#    module_path = inspect.getfile(qt)
#    if module_path.endswith('.electrum/plugins/joinmarket.zip/'
#                            'joinmarket/qt.py'):
#        return module_path
#
#
# def load_plugin_modules_from_zip(qt_module_path):
#    import importlib.util
#    import sys
#    import os
#    import zipimport
#
#    from electrum.logging import get_logger
#    _logger = get_logger(__name__)
#
#    plugin_name = os.path.basename(os.path.dirname(qt_module_path))
#    zip_filename = os.path.dirname(os.path.dirname(qt_module_path))
#    try:
#        zipfile = zipimport.zipimporter(zip_filename)
#    except zipimport.ZipImportError:
#        _logger.error(f"unable to load zip plugin '{zip_filename}'")
#        return
#    try:
#        module = zipfile.load_module(plugin_name)
#    except zipimport.ZipImportError:
#        _logger.error(f"unable to load zip plugin '{zip_filename}' "
#                      f"package '{plugin_name}'")
#        return
#    sys.modules['electrum_external_plugins.' + plugin_name] = module
#
#    for name in ['jm_util', 'jm_qt',
#                 'icon_data.jm_png', 'icon_data.jm_active_png']:
#        full_name = f'electrum_external_plugins.{plugin_name}.{name}'
#        spec = importlib.util.find_spec(full_name)
#        if spec is None:
#            raise RuntimeError(f"{full_name} module not found")
#        module = importlib.util.module_from_spec(spec)
#        sys.modules[spec.name] = module
#        if sys.version_info >= (3, 10):
#            spec.loader.exec_module(module)
#        else:
#            try:
#                module = spec.loader.load_module(full_name)
#            except Exception:
#                _logger.error(f'Can not import {plugin_name}.{name}')
#                return
#
#
# zipfile_module_path = get_zipfile_module_path()
# if zipfile_module_path:
#    load_plugin_modules_from_zip(zipfile_module_path)


from . import version as JM_PLUGIN_VERSION  # noqa: E402
from .plugin import JoinMarketPlugin  # noqa: E402
from .jm_qt import JMDlgUnsupportedJM, JMDlg, JM_GUI_VERSION  # noqa: E402
from .jmbase import JM_CORE_VERSION  # noqa: E402
from .jmdaemon import JM_VERSION  # noqa: E402


class JMAboutDlg(WindowModalDialog):

    def __init__(self, window, plugin):
        WindowModalDialog.__init__(self, window, plugin.MSG_TITLE)
        self.setMinimumWidth(600)

        self.wallet = window.parent().wallet
        self.plugin = plugin
        self.config = plugin.config
        self.network = Network.get_instance()

        g = QGridLayout(self)
        msg = '\n\n'.join([
            _('JoinMarket plugin allow creation of CoinJoin transactions'
              ' to enhance privacy of Bitcoin use.'),
            _('To start mixing open JoinMarket dialog using button'
              ' placed at the status bar.'),
            'Based on https://github.com/JoinMarket-Org/'
            'joinmarket-clientserver/\n\n'
            f'JM_VERSION={JM_VERSION}\n'
            f'JM_CORE_VERSION={JM_CORE_VERSION}\n'
            f'JM_GUI_VERSION={JM_GUI_VERSION}\n'
            f'JM_PLUGIN_VERSION={JM_PLUGIN_VERSION}\n'
        ])
        g.addWidget(WWLabel(msg), 0, 0, 1, -1)

        g.setRowStretch(10, 1)
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(CloseButton(self))
        g.addLayout(hbox, 11, 0, 1, -1)


class Plugin(JoinMarketPlugin, QObject):

    autofreeze_warning_signal = pyqtSignal(tuple)

    def __init__(self, parent, config, name):
        QObject.__init__(self)
        JoinMarketPlugin.__init__(self, parent, config, name)
        self.qt_gui = None
        self.mwins = {}
        self.jm_status_btns = {}
        self.jm_dialogs = {}
        self.unconditional_close_jm_dlg = False
        self.autofreeze_warning_signal.connect(self.autofreeze_warning_cb)

    def requires_settings(self) -> bool:
        return True

    def settings_widget(self, window):
        about_dlg_partial = partial(self.about_dlg, window)
        return EnterButton(_('About Plugin'), about_dlg_partial)

    def about_dlg(self, window):
        d = JMAboutDlg(window, self)
        d.exec()

    @hook
    def init_qt(self, qt_gui):
        self.qt_gui = qt_gui
        for mwin in qt_gui.windows:
            w = mwin.wallet
            if w and w not in self._wallets:
                self.load_wallet(w, mwin)

    def on_close(self):
        for w in list(self._wallets):
            self.close_wallet(w)

    @hook
    def load_wallet(self, wallet, mwin):
        super(Plugin, self).load_wallet(wallet)
        self.qt_register(wallet, mwin)
        if not wallet.jmman.enabled:
            return
        wallet.jmman.jmw.load_and_cleanup()

    @hook
    def close_wallet(self, wallet):
        self.unconditional_close_jm_dlg = True
        for mwin in self.qt_gui.windows:
            if mwin.wallet == wallet:
                self.qt_unregister(wallet, mwin)
        self.unconditional_close_jm_dlg = False
        super(Plugin, self).close_wallet(wallet)

    def load_icons(self):
        from .icon_data.jm_png import PNG_BYTES as jm_png_bytes
        from .icon_data.jm_active_png import PNG_BYTES as jm_active_png_bytes
        pxmp = QPixmap()
        pxmp.loadFromData(jm_png_bytes)
        self.jm_icon = QIcon(pxmp)
        pxmp = QPixmap()
        pxmp.loadFromData(jm_active_png_bytes)
        self.jm_active_icon = QIcon(pxmp)
        pxmp = QPixmap()

    def autofreeze_warning_cb(self, args):
        mwin, outpoint, utxo = args
        JMDlg.autofreeze_warning_cb(mwin, outpoint, utxo)

    def qt_register(self, wallet, mwin):

        def _autofreeze_warning_cb(outpoint, utxo):
            self.autofreeze_warning_signal.emit((mwin, outpoint, utxo))

        wallet.jmman.jmw.set_autofreeze_warning_cb(_autofreeze_warning_cb)

        self.load_icons()
        self.mwins[wallet] = mwin
        # add status bar button
        sb = mwin.statusBar()
        jmb = StatusBarButton(self.jm_icon, _("JoinMarket"),
                              partial(self.show_jm_dialog, mwin), sb.height())
        self.jm_status_btns[mwin] = jmb
        sb.insertPermanentWidget(1, jmb)
        self.update_jm_status_btn(wallet)

    def qt_unregister(self, wallet, mwin):
        mwin = self.mwins.pop(wallet, None)
        if not mwin:
            return
        self.hide_jm_dialog(mwin)
        # remove status bar button
        jmb = self.jm_status_btns.pop(mwin, None)
        if jmb:
            sb = mwin.statusBar()
            sb.removeWidget(jmb)
        wallet.jmman.jmw.set_autofreeze_warning_cb(None)

    def find_jm_dialog(self, mwin):
        return self.jm_dialogs.get(mwin, None)

    def show_jm_dialog(self, mwin, d=None):
        if not d:
            d = self.find_jm_dialog(mwin)
        if d:
            d.raise_()
            d.activateWindow()
        else:
            if mwin.wallet.jmman.unsupported:
                d = JMDlgUnsupportedJM(mwin, self)
            else:
                d = JMDlg(mwin, self)
            self.jm_dialogs[mwin] = d
            d.show()

    def hide_jm_dialog(self, mwin):
        d = self.find_jm_dialog(mwin)
        if d:
            d.close()

    def update_jm_status_btn(self, wallet):
        mwin = self.mwins.get(wallet, None)
        if not mwin:
            return
        jmb = self.jm_status_btns.get(mwin, None)
        if not jmb:
            return
        if wallet.jmman.is_mixing:
            icon = self.jm_active_icon
            status = _('Is Mixing')
        else:
            icon = self.jm_icon
            status = _('Is Idle')
        tooltip = f'{self.MSG_TITLE} {status}'
        jmb.setIcon(icon)
        jmb.setToolTip(tooltip)
