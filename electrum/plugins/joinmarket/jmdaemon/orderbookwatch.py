# -*- coding: utf-8 -*-

import sys
from collections import defaultdict
from decimal import InvalidOperation, Decimal
from numbers import Integral

from .protocol import JM_VERSION
from .fidelity_bond_sanity_check import fidelity_bond_sanity_check


class OrderbookWatch(object):

    def set_msgchan(self, msgchan):
        self.msgchan = msgchan
        self.msgchan.register_orderbookwatch_callbacks(
            self.on_order_seen, self.on_order_cancel,
            self.on_fidelity_bond_seen)
        self.msgchan.register_channel_callbacks(
            self.on_welcome, self.on_set_topic, None, self.on_disconnect,
            self.on_nick_leave, None)

        self.ob = defaultdict(dict)     # nick -> oid -> JMOffer
        self.fb = dict()                # nick -> fidelity bond

    @staticmethod
    def on_set_topic(newtopic, logger):
        chunks = newtopic.split('|')
        for msg in chunks[1:]:
            try:
                msg = msg.strip()
                params = msg.split(' ')
                min_version = int(params[0])
                max_version = int(params[1])
                alert = msg[msg.index(params[1]) + len(params[1]):].strip()
            except (ValueError, IndexError):
                continue
            if min_version < JM_VERSION < max_version:
                logger.warning('=' * 60)
                logger.warning('JOINMARKET ALERT')
                logger.warning(alert)
                logger.warning('=' * 60)

    def on_order_seen(self, counterparty, oid, ordertype, minsize, maxsize,
                      txfee, cjfee):
        try:
            if int(oid) < 0 or int(oid) > sys.maxsize:
                self.logger.debug("Got invalid order ID: " + oid + " from " +
                                  counterparty)
                return
            # delete orders eagerly, so in case a buggy maker sends an
            # invalid offer, we won't accidentally !fill based on the ghost
            # of its previous message.
            if counterparty in self.ob and oid in self.ob[counterparty]:
                del self.ob[counterparty][oid]
            # now validate the remaining fields
            if int(minsize) < 0 or int(minsize) > 21 * 10**14:
                self.logger.debug("Got invalid minsize: {} from {}".format(
                    minsize, counterparty))
                return
            if int(minsize) < self.dust_threshold:
                minsize = self.dust_threshold
                self.logger.debug("{} has dusty minsize, capping at {}".format(
                    counterparty, minsize))
                # do not pass return, go not drop this otherwise fine offer
            if int(maxsize) < 0 or int(maxsize) > 21 * 10**14:
                self.logger.debug("Got invalid maxsize: " + maxsize +
                                  " from " + counterparty)
                return
            if int(txfee) < 0:
                self.logger.debug("Got invalid txfee: {} from {}".format(
                    txfee, counterparty))
                return
            if int(minsize) > int(maxsize):

                fmt = ("Got minsize bigger than maxsize: {} - {} "
                       "from {}").format
                self.logger.debug(fmt(minsize, maxsize, counterparty))
                return
            if ordertype in ['sw0absoffer', 'swabsoffer', 'absoffer']\
                    and not isinstance(cjfee, Integral):
                try:
                    cjfee = int(cjfee)
                except ValueError:
                    self.logger.debug("Got non integer coinjoin fee: " +
                                      str(cjfee) + " for an absoffer from " +
                                      counterparty)
                    return
            self.ob[counterparty][oid] = (
                str(counterparty),
                int(oid),
                str(ordertype),
                int(minsize),
                int(maxsize),
                int(txfee),
                str(Decimal(cjfee))
            )
        except InvalidOperation:
            self.logger.debug("Got invalid cjfee: " + str(cjfee) + " from " +
                              counterparty)
        except Exception as e:
            self.logger.debug("Error parsing order " + str(oid) + " from " +
                              counterparty)
            self.logger.debug("Exception was: " + repr(e))

    def on_order_cancel(self, counterparty, oid):
        if counterparty in self.ob and oid in self.ob[counterparty]:
            del self.ob[counterparty][oid]

    def on_fidelity_bond_seen(self, nick, bond_type, fidelity_bond_proof_msg):
        taker_nick = self.msgchan.nick
        maker_nick = nick
        if not fidelity_bond_sanity_check(fidelity_bond_proof_msg):
            self.logger.debug("Failed to verify fidelity bond for"
                              " {}, skipping.".format(maker_nick))
            return
        self.fb[nick] = (
            str(nick), str(taker_nick), str(fidelity_bond_proof_msg)
        )

    def on_nick_leave(self, nick):
        if nick in self.ob:
            del self.ob[nick]
        if nick in self.fb:
            del self.fb[nick]

    async def on_disconnect(self):
        self.ob = defaultdict(dict)
        self.fb = dict()
