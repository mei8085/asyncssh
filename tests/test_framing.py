# Copyright (c) 2024 by Ron Frederick <ronf@timeheart.net> and others.
#
# This program and the accompanying materials are made available under
# the terms of the Eclipse Public License v2.0 which accompanies this
# distribution and is available at:
#
#     http://www.eclipse.org/legal/epl-2.0/
#
# This program may also be made available under the following secondary
# licenses when the conditions for such availability set forth in the
# Eclipse Public License v2.0 are satisfied:
#
#    GNU General Public License, Version 2.0, or any later versions of
#    this license
#
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
#
# Contributors:
#     Ron Frederick - initial implementation, API, and documentation

"""Integration tests for SSH packet framing (length, padding, and cursor)"""

import asyncio
import socket

import asyncssh
from asyncssh.constants import MSG_IGNORE, MSG_UNIMPLEMENTED
from asyncssh.misc import ConnectionLost, ProtocolError
from asyncssh.packet import Byte, String, UInt32

from .util import AsyncTestCase, asynctest


# An SSH transport message type which is not assigned by the SSH protocol.
# A peer which decodes it must answer with MSG_UNIMPLEMENTED, making frame
# boundaries observable without completing a key exchange.
_UNASSIGNED_PKTTYPE = 19

# Chunk size used to drive the asynchronous (split) read entry point
_CHUNK_SIZE = 3


def _make_frame(payload, padlen=None):
    """Build an unencrypted SSH binary packet frame for the given payload"""

    blocksize = 8

    if padlen is None:
        padlen = -(5 + len(payload)) % blocksize
        if padlen < 4:
            padlen += blocksize

    packet = Byte(padlen) + payload + b'P' * padlen
    return UInt32(len(packet)) + packet


def _parse_frames(data):
    """Decode the unencrypted frames contained in a byte string"""

    frames = []

    while len(data) >= 4:
        pktlen = int.from_bytes(data[:4], 'big')
        if len(data) < 4 + pktlen:
            break

        packet = data[4:4+pktlen]
        padlen = packet[0]
        frames.append(packet[1:-padlen])
        data = data[4+pktlen:]

    return frames


class _TestFraming(AsyncTestCase):
    """Integration tests for the SSH packet frame reader

       A minimal SSH peer is driven over a raw TCP socket. Frames are
       delivered in two ways: all at once ("sync", a single ``data_received``
       call) and split into small chunks ("async", repeated
       ``data_received`` calls while the reader is waiting for more data).
       Both read entry points must produce the same deterministic result.

       Assertions are split into three groups so that frame length and
       padding failures, packet tail/cursor failures, and the connection
       state after a bad frame are reported separately in a single run:

       1. Frame length and padding.
       2. Packet tail and cursor.
       3. Connection state after a bad frame.
    """

    async def _start_fake_server(self, response_blobs):
        """Start a fake SSH server which sends the given raw frame data

           Any frames the client sends back are collected so that
           MSG_UNIMPLEMENTED replies can be counted. Reads are bounded so
           a test never blocks waiting for a peer which has already
           produced the behavior under test. The server always closes
           itself once the bounded read completes.
        """

        received = []

        async def handle_client(reader, writer):
            # Consume and answer the SSH version exchange
            await reader.readline()
            writer.write(b'SSH-2.0-TestFakeServer\r\n')
            await asyncio.sleep(0.05)

            for blob in response_blobs:
                if self._delivery == 'sync':
                    # Synchronous read entry: feed everything in one write
                    writer.write(blob)
                else:
                    # Asynchronous read entry: force the reader across many
                    # data_received calls, each providing only a few bytes
                    for offset in range(0, len(blob), _CHUNK_SIZE):
                        writer.write(blob[offset:offset+_CHUNK_SIZE])
                        await writer.drain()

            # Collect client replies, but stop as soon as the client goes
            # quiet so well-behaved frames do not pay for a full timeout.
            try:
                while True:
                    data = await asyncio.wait_for(
                        reader.read(4096), timeout=0.3)
                    if not data:
                        break
                    received.append(data)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                pass

            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

        server = await asyncio.start_server(
            handle_client, '127.0.0.1', 0, family=socket.AF_INET)

        port = server.sockets[0].getsockname()[1]
        return server, port, received

    async def _run_client(self, port):
        """Connect an SSH client to the fake server and return its error"""

        try:
            conn = await asyncio.wait_for(
                asyncssh.connect('127.0.0.1', port, known_hosts=(),
                                 kex_algs=['ecdh-sha2-nistp256'],
                                 login_timeout=5),
                timeout=8)
        except Exception as exc:
            return exc, None
        else:
            return None, conn

    async def _check_bad_frame(self, blobs, expected_exc, expected_reason):
        """Assert that malformed framing raises a deterministic client error

           This runs under both read delivery modes. Each mode is reported
           as its own subtest so the failing entry point is identifiable in
           a single test report.
        """

        for self._delivery in ('sync', 'async'):
            with self.subTest(mode=self._delivery):
                server, port, _ = await self._start_fake_server(blobs)

                try:
                    exc, conn = await self._run_client(port)
                finally:
                    server.close()
                    await server.wait_closed()

                # Group 3: the connection must be closed with a definite
                # error rather than left open or torn down silently
                self.assertIsInstance(exc, expected_exc)
                self.assertIn(expected_reason, str(exc))

                if conn is not None:
                    self.assertTrue(conn.is_closed())
                    conn.abort()

    async def _check_unimplemented_replies(self, blobs, expected_count):
        """Count MSG_UNIMPLEMENTED replies produced for decoded frames"""

        for self._delivery in ('sync', 'async'):
            with self.subTest(mode=self._delivery):
                server, port, received = await self._start_fake_server(blobs)

                try:
                    _exc, conn = await self._run_client(port)
                    if conn is not None:
                        # Framing was accepted; the connect only stays open
                        # because the fake server never performs a key
                        # exchange. Close the client once replies are sent.
                        await asyncio.sleep(0.1)
                        conn.abort()
                        await conn.wait_closed()
                finally:
                    server.close()
                    await server.wait_closed()

                replies = _parse_frames(b''.join(received))
                count = sum(1 for payload in replies
                            if payload and payload[0] == MSG_UNIMPLEMENTED)
                self.assertEqual(count, expected_count)

    #
    # Group 1: frame length and padding
    #

    @asynctest
    async def test_frame_length_over_limit(self):
        """A frame length above the implementation limit is rejected

           Distinct failure message: 'Max packet size exceeded'.
        """

        # Header alone claims more than the 256 KiB receive limit
        over_limit = UInt32(256*1024 + 1) + b'\x04' + b'X'*4

        await self._check_bad_frame(
            [over_limit], ProtocolError, 'Max packet size exceeded')

    @asynctest
    async def test_frame_padding_below_minimum(self):
        """A complete frame whose padlen is below four is rejected

           Distinct failure message: 'Invalid packet padding length'.
        """

        # Block-aligned 16-byte frame, but padlen 3 violates the SSH
        # requirement of at least four padding bytes
        payload_len = 8
        packet = Byte(3) + b'Q'*payload_len + b'ZZZ'
        bad_padding = UInt32(len(packet)) + packet

        self.assertEqual(len(bad_padding) % 8, 0)
        await self._check_bad_frame(
            [bad_padding], ProtocolError, 'Invalid packet padding length')

    @asynctest
    async def test_frame_padding_overruns_packet(self):
        """A frame whose padlen runs past the packet tail is rejected

           Distinct failure message: 'Invalid packet padding length'. This
           must not slice past the end of the packet buffer.
        """

        # 16-byte block-aligned frame claiming 250 padding bytes while the
        # packet only holds 11 bytes after the padlen field
        packet = Byte(250) + b'Q'*11
        bad_padding = UInt32(len(packet)) + packet

        self.assertEqual(len(bad_padding) % 8, 0)
        await self._check_bad_frame(
            [bad_padding], ProtocolError, 'Invalid packet padding length')

    @asynctest
    async def test_legal_min_and_max_padding(self):
        """Frames carrying the minimum and maximum legal padding decode

           For an 8-byte block size, payloads of seven and eight bytes
           require padlen of four and eleven respectively. Both frames
           must be decoded by the original protocol without error, which
           is observed through the reply to a trailing unassigned-type
           frame: exactly one MSG_UNIMPLEMENTED means both legal frames
           were consumed and the cursor advanced correctly.
        """

        min_padding = _make_frame(Byte(MSG_IGNORE) + String(b'ab'))
        max_padding = _make_frame(Byte(MSG_IGNORE) + String(b'abc'))
        probe = _make_frame(Byte(_UNASSIGNED_PKTTYPE) + UInt32(0))

        self.assertEqual(min_padding[4], 4)
        self.assertEqual(max_padding[4], 11)

        await self._check_unimplemented_replies(
            [min_padding + max_padding + probe], 1)

    #
    # Group 2: packet tail and cursor
    #

    @asynctest
    async def test_truncated_packet_body(self):
        """A frame header followed by too few body bytes fails at EOF

           The reader must keep waiting for the declared tail instead of
           reading beyond it, and report a definite ConnectionLost when
           the peer closes with the frame incomplete.
        """

        truncated = UInt32(12) + b'\x04' + b'XYZ'

        await self._check_bad_frame(
            [truncated], ConnectionLost, 'Connection lost')

    @asynctest
    async def test_truncated_packet_header(self):
        """A partial four-byte length header fails deterministically at EOF"""

        await self._check_bad_frame(
            [b'\x00\x00'], ConnectionLost, 'Connection lost')

    @asynctest
    async def test_residual_bytes_not_treated_as_next_frame(self):
        """Residual bytes after a complete frame stay buffered as a frame

           A complete legal frame followed by only part of the next header
           must not be misparsed. The residual bytes remain a partial
           frame until EOF, at which point a definite ConnectionLost is
           reported.
        """

        legal = _make_frame(Byte(MSG_IGNORE) + String(b'ab'))

        await self._check_bad_frame(
            [legal + b'\x00\x00'], ConnectionLost, 'Connection lost')

    @asynctest
    async def test_no_overread_across_frame_boundary(self):
        """The reader stops exactly at each frame tail

           Two complete legal frames followed by an unassigned-type probe
           must yield exactly one MSG_UNIMPLEMENTED. Any read past a frame
           tail would desynchronize the cursor and the probe would not be
           decoded as its own frame.
        """

        first = _make_frame(Byte(MSG_IGNORE) + String(b'ab'))
        second = _make_frame(Byte(MSG_IGNORE) + String(b'abc'))
        probe = _make_frame(Byte(_UNASSIGNED_PKTTYPE) + UInt32(0))

        await self._check_unimplemented_replies(
            [first + second + probe], 1)

    #
    # Group 3: connection state after a bad frame
    #

    @asynctest
    async def test_consecutive_bad_frames(self):
        """Multiple consecutive bad frames produce one deterministic error

           The first bad frame must terminate processing immediately: the
           client raises the length/padding ProtocolError and never reaches
           the trailing probe frame (no MSG_UNIMPLEMENTED reply). The
           residual bad frames must not be treated as new frames.
        """

        for self._delivery in ('sync', 'async'):
            with self.subTest(mode=self._delivery):
                first_bad = UInt32(256*1024 + 1) + b'\x04' + b'X'*4
                second_bad = UInt32(12) + Byte(250) + b'Q'*11
                probe = _make_frame(Byte(_UNASSIGNED_PKTTYPE) + UInt32(0))

                server, port, received = await self._start_fake_server(
                    [first_bad + second_bad + probe])

                try:
                    exc, conn = await self._run_client(port)
                finally:
                    server.close()
                    await server.wait_closed()

                # Deterministic error from the first frame, not the second
                self.assertIsInstance(exc, ProtocolError)
                self.assertEqual(str(exc), 'Max packet size exceeded')

                # The connection must be closed and the probe never decoded
                replies = _parse_frames(b''.join(received))
                self.assertFalse(
                    any(payload and payload[0] == MSG_UNIMPLEMENTED
                        for payload in replies))

                if conn is not None:
                    self.assertTrue(conn.is_closed())
                    conn.abort()
