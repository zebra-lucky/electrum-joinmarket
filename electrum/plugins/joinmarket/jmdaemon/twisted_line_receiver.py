# -*- coding: utf-8 -*-

# modified LineReceiver from twisted.words.protocols.basic
# https://github.com/twisted/twisted

# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.
# https://github.com/twisted/twisted/blob/trunk/LICENSE

import asyncio


class LineReceiver(asyncio.Protocol):

    _buffer = b""
    _busyReceiving = False
    delimiter = b"\r\n"
    MAX_LENGTH = 16384

    def data_received(self, data):
        if self._busyReceiving:
            self._buffer += data
            return

        try:
            self._busyReceiving = True
            self._buffer += data
            while self._buffer:
                try:
                    line, self._buffer = self._buffer.split(self.delimiter, 1)
                except ValueError:
                    if len(self._buffer) >= (self.MAX_LENGTH +
                                             len(self.delimiter)):
                        line, self._buffer = self._buffer, b""
                        return self.line_length_exceeded(line)
                    return
                else:
                    lineLength = len(line)
                    if lineLength > self.MAX_LENGTH:
                        exceeded = line + self.delimiter + self._buffer
                        self._buffer = b""
                        return self.line_length_exceeded(exceeded)
                    why = self.line_received(line)
                    if why or self.transport and self.transport.is_closing():
                        return why
        finally:
            self._busyReceiving = False

    def line_received(self, line):
        raise NotImplementedError

    def send_line(self, line):
        return self.transport.write(line + self.delimiter)

    def line_length_exceeded(self, line):
        return self.transport.close()
