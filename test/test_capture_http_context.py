"""Regression tests for capture_http request attribution.

These tests verify that recorded requests are attributed to the
innermost capture context active when the request is *started* --
not to the context that was active when the connection was created --
and that interleaved transactions on multiple connections of the same
thread never share buffers.

All tests run against a local HTTP server, no external network needed.
"""

import base64
import hashlib
import http.client
import http.server
import threading

from io import BytesIO

# must be imported before 'requests'
from warcio.capture_http import capture_http, RecordingStream

import pytest
import requests

from warcio.archiveiterator import ArchiveIterator


def _urllib3_uses_patched_connection():
    """capture_http patches http.client.HTTPConnection at import time.
    urllib3 creates its connection subclasses from that class, so it
    must be imported *after* capture_http. Some pytest plugins import
    urllib3 early; in that case requests-based capture cannot work."""
    try:
        import urllib3.connection
    except ImportError:  # pragma: no cover
        return False
    from warcio.capture_http import RecordingHTTPConnection
    return issubclass(urllib3.connection.HTTPConnection,
                      RecordingHTTPConnection)


requires_patched_urllib3 = pytest.mark.skipif(
    not _urllib3_uses_patched_connection(),
    reason='urllib3 imported before warcio.capture_http: requests-based '
           'capture not available (known import-order limitation)')


# ==================================================================
BODY_A = b'alpha-body:' + bytes(range(256)) * 40
BODY_B = b'beta-body!' + bytes(range(255, -1, -1)) * 40
BODY_BIG = b'big:' + bytes(range(256)) * 400
ECHO_PREFIX = b'echo:'


# ==================================================================
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _send(self, body):
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        bodies = {'/a': BODY_A, '/b': BODY_B, '/big': BODY_BIG}
        body = bodies.get(self.path)
        if body is None:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self._send(body)

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        self._send(ECHO_PREFIX + self.rfile.read(length))

    def log_message(self, *args):
        pass


class Server(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # early-closed client connections are expected in these tests
        pass


# ==================================================================
class TestCaptureHttpContext(object):
    @classmethod
    def setup_class(cls):
        cls.server = Server(('127.0.0.1', 0), Handler)
        cls.port = cls.server.server_address[1]

        thread = threading.Thread(target=cls.server.serve_forever)
        thread.daemon = True
        thread.start()

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def url(self, path):
        return 'http://127.0.0.1:{0}{1}'.format(self.port, path)

    # --------------------------------------------------------------
    # WARC parsing helpers
    # --------------------------------------------------------------
    @staticmethod
    def load_transactions(writer):
        """Parse the WARC and group records into
        ((response, body), (request, body)) pairs, matched via
        WARC-Concurrent-To. Bodies are read while iterating (the
        ArchiveIterator is streaming). Asserts that every transaction
        was written exactly once and that every request is paired.
        """
        responses = []
        requests_ = {}

        for record in ArchiveIterator(writer.get_stream()):
            body = record.content_stream().read()
            if record.rec_type == 'response':
                responses.append((record, body))
            else:
                assert record.rec_type == 'request'
                concurrent = record.rec_headers['WARC-Concurrent-To']
                assert concurrent not in requests_
                requests_[concurrent] = (record, body)

        pairs = []
        for response, resp_body in responses:
            resp_id = response.rec_headers['WARC-Record-ID']
            assert resp_id in requests_
            request, req_body = requests_.pop(resp_id)
            assert (request.rec_headers['WARC-Target-URI'] ==
                    response.rec_headers['WARC-Target-URI'])
            pairs.append(((response, resp_body), (request, req_body)))

        # no unpaired requests
        assert not requests_
        return pairs

    @staticmethod
    def digest(content):
        return 'sha1:' + base64.b32encode(
            hashlib.sha1(content).digest()).decode('ascii')

    def assert_pair(self, pair, url, resp_body, req_body=b''):
        (response, actual_resp_body), (request, actual_req_body) = pair
        assert response.rec_headers['WARC-Target-URI'] == url
        assert request.rec_headers['WARC-Target-URI'] == url
        assert response.rec_headers['WARC-IP-Address'] == '127.0.0.1'
        assert request.rec_headers['WARC-IP-Address'] == '127.0.0.1'

        assert actual_resp_body == resp_body
        assert (response.rec_headers['WARC-Payload-Digest'] ==
                self.digest(resp_body))
        assert 'WARC-Block-Digest' in response.rec_headers

        assert actual_req_body == req_body
        assert (request.rec_headers['WARC-Payload-Digest'] ==
                self.digest(req_body))
        assert 'WARC-Block-Digest' in request.rec_headers

    def get(self, conn, path):
        conn.request('GET', path)
        resp = conn.getresponse()
        body = resp.read()
        resp.close()
        return body

    # --------------------------------------------------------------
    # nesting
    # --------------------------------------------------------------
    def test_nested_contexts(self):
        # connection created outside of any context, reused throughout
        conn = http.client.HTTPConnection('127.0.0.1', self.port)

        with capture_http() as outer_writer:
            assert self.get(conn, '/a') == BODY_A

            with capture_http(gzip=True) as inner_writer:
                assert self.get(conn, '/b') == BODY_B

            # inner exited: outer is active again
            assert self.get(conn, '/big') == BODY_BIG

        outer_pairs = self.load_transactions(outer_writer)
        inner_pairs = self.load_transactions(inner_writer)

        assert len(outer_pairs) == 2
        assert len(inner_pairs) == 1

        by_url = {p[0][0].rec_headers['WARC-Target-URI']: p
                  for p in outer_pairs}
        self.assert_pair(by_url[self.url('/a')], self.url('/a'), BODY_A)
        self.assert_pair(by_url[self.url('/big')], self.url('/big'), BODY_BIG)

        self.assert_pair(inner_pairs[0], self.url('/b'), BODY_B)

    def test_inner_context_exception_restores_outer(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.port)

        with capture_http() as outer_writer:
            assert self.get(conn, '/a') == BODY_A

            with pytest.raises(ValueError):
                with capture_http() as inner_writer:
                    assert self.get(conn, '/b') == BODY_B
                    raise ValueError('boom')

            # outer context restored even though inner raised
            assert self.get(conn, '/big') == BODY_BIG

        outer_urls = {resp.rec_headers['WARC-Target-URI']
                      for (resp, _), _ in
                      self.load_transactions(outer_writer)}
        inner_urls = {resp.rec_headers['WARC-Target-URI']
                      for (resp, _), _ in
                      self.load_transactions(inner_writer)}

        assert outer_urls == {self.url('/a'), self.url('/big')}
        assert inner_urls == {self.url('/b')}

    # --------------------------------------------------------------
    # connection reuse in and out of contexts
    # --------------------------------------------------------------
    def test_connection_reuse_across_contexts(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.port)

        # outside any context: not recorded
        assert self.get(conn, '/a') == BODY_A

        # reused inside a context: recorded
        with capture_http() as writer:
            assert self.get(conn, '/b') == BODY_B

        # outside again: not recorded
        assert self.get(conn, '/big') == BODY_BIG

        pairs = self.load_transactions(writer)
        assert len(pairs) == 1
        self.assert_pair(pairs[0], self.url('/b'), BODY_B)

    @requires_patched_urllib3
    def test_requests_session_reuse(self):
        sesh = requests.Session()
        sesh.trust_env = False

        with capture_http() as writer:
            res = sesh.get(self.url('/a'))
            assert res.content == BODY_A

        # same pooled connection, but outside any context: not recorded
        res = sesh.get(self.url('/b'))
        assert res.content == BODY_B

        # back inside a context on the reused connection: recorded
        with capture_http(writer):
            res = sesh.post(self.url('/echo'), data=b'ping')
            assert res.content == ECHO_PREFIX + b'ping'

        records = list(ArchiveIterator(writer.get_stream()))

        # original sequential order is preserved:
        # response, request, response, request
        assert [r.rec_type for r in records] == \
            ['response', 'request', 'response', 'request']
        assert [r.rec_headers['WARC-Target-URI'] for r in records] == \
            [self.url('/a'), self.url('/a'),
             self.url('/echo'), self.url('/echo')]

        pairs = self.load_transactions(writer)
        by_url = {p[0][0].rec_headers['WARC-Target-URI']: p for p in pairs}
        self.assert_pair(by_url[self.url('/a')], self.url('/a'), BODY_A)
        self.assert_pair(by_url[self.url('/echo')], self.url('/echo'),
                         ECHO_PREFIX + b'ping', req_body=b'ping')

    # --------------------------------------------------------------
    # interleaved transactions on multiple connections, same thread
    # --------------------------------------------------------------
    def test_interleaved_responses(self):
        conn_a = http.client.HTTPConnection('127.0.0.1', self.port)
        conn_b = http.client.HTTPConnection('127.0.0.1', self.port)

        with capture_http() as writer:
            conn_a.request('GET', '/a')
            conn_b.request('GET', '/b')

            resp_a = conn_a.getresponse()
            resp_b = conn_b.getresponse()

            # read both responses interleaved, in small chunks
            chunks_a = []
            chunks_b = []
            while True:
                chunk_a = resp_a.read(997)
                chunk_b = resp_b.read(733)
                chunks_a.append(chunk_a)
                chunks_b.append(chunk_b)
                if not chunk_a and not chunk_b:
                    break

            resp_a.close()
            resp_b.close()

        assert b''.join(chunks_a) == BODY_A
        assert b''.join(chunks_b) == BODY_B

        pairs = self.load_transactions(writer)
        assert len(pairs) == 2

        by_url = {p[0][0].rec_headers['WARC-Target-URI']: p for p in pairs}
        self.assert_pair(by_url[self.url('/a')], self.url('/a'), BODY_A)
        self.assert_pair(by_url[self.url('/b')], self.url('/b'), BODY_B)

    def test_outer_response_read_during_inner_context(self):
        conn_a = http.client.HTTPConnection('127.0.0.1', self.port)
        conn_b = http.client.HTTPConnection('127.0.0.1', self.port)

        with capture_http() as outer_writer:
            conn_a.request('GET', '/a')
            resp_a = conn_a.getresponse()

            with capture_http() as inner_writer:
                # inner request, fully read inside the inner context
                assert self.get(conn_b, '/b') == BODY_B

                # outer response, fully read while the inner context
                # is active: still attributed to the outer context
                assert resp_a.read() == BODY_A
                resp_a.close()

        outer_pairs = self.load_transactions(outer_writer)
        inner_pairs = self.load_transactions(inner_writer)

        assert len(outer_pairs) == 1
        assert len(inner_pairs) == 1
        self.assert_pair(outer_pairs[0], self.url('/a'), BODY_A)
        self.assert_pair(inner_pairs[0], self.url('/b'), BODY_B)

    # --------------------------------------------------------------
    # short reads, early close, filter errors
    # --------------------------------------------------------------
    def test_early_close_records_only_bytes_read(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.port)

        with capture_http() as writer:
            conn.request('GET', '/big')
            resp = conn.getresponse()
            chunk = resp.read(1000)
            assert len(chunk) == 1000
            assert chunk == BODY_BIG[:1000]

            # closing early: transaction is written once, with only
            # the bytes actually read
            resp.close()
            # repeated closes must not write the transaction again
            resp.close()

            # other transactions are unaffected
            assert self.get(
                http.client.HTTPConnection('127.0.0.1', self.port),
                '/a') == BODY_A

        pairs = self.load_transactions(writer)
        assert len(pairs) == 2

        by_url = {p[0][0].rec_headers['WARC-Target-URI']: p for p in pairs}
        self.assert_pair(by_url[self.url('/big')], self.url('/big'),
                         BODY_BIG[:1000])
        self.assert_pair(by_url[self.url('/a')], self.url('/a'), BODY_A)

    def test_filter_exception_releases_transaction(self):
        failed = []

        def flaky_filter(request, response, recorder):
            if not failed:
                failed.append(True)
                raise ValueError('filter boom')
            return request, response

        conn = http.client.HTTPConnection('127.0.0.1', self.port)

        with capture_http(filter_func=flaky_filter) as writer:
            conn.request('GET', '/a')
            resp = conn.getresponse()
            with pytest.raises(ValueError):
                resp.read()

            # the failed transaction released its buffers and did not
            # corrupt the next one
            assert self.get(conn, '/b') == BODY_B

        pairs = self.load_transactions(writer)
        assert len(pairs) == 1
        self.assert_pair(pairs[0], self.url('/b'), BODY_B)

    def test_readinto_short_read_records_actual_bytes(self):
        class FakeTransaction(object):
            def __init__(self):
                self.writes = []

            def set_remote_ip(self, ip):
                pass

            def write_response(self, buff):
                self.writes.append(bytes(buff))

            def done(self):
                pass

        tx = FakeTransaction()
        stream = RecordingStream(BytesIO(b'12345'), tx)

        # buffer is larger than the data available: only the bytes
        # actually read may be recorded
        buff = bytearray(64)
        assert stream.readinto(buff) == 5
        assert b''.join(tx.writes) == b'12345'
