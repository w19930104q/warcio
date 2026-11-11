import threading

from io import BytesIO

from six.moves import http_client as httplib

from contextlib import contextmanager

from array import array

from warcio.utils import to_native_str, BUFF_SIZE, open
from warcio.warcwriter import WARCWriter, BufferWARCWriter

from tempfile import SpooledTemporaryFile


# ============================================================================
orig_connection = httplib.HTTPConnection


# ============================================================================
class RecordingStream(object):
    """Wraps the response socket file of a single recorded transaction.

    All bytes read from the socket are routed to the transaction that
    owns this stream -- no matter which capture context happens to be
    active at read time -- so responses read interleaved on different
    connections of the same thread never get mixed up.
    """

    def __init__(self, fp, transaction):
        self.fp = fp
        self.transaction = transaction

        self.transaction.set_remote_ip(self._get_remote_ip())

    def _get_remote_ip(self):
        try:
            fp = self.fp
            # for python 3, need to get 'raw' fp
            if hasattr(fp, 'raw'):  #pragma: no cover
                fp = fp.raw

            socket = fp._sock

            # wrapped ssl socket
            if hasattr(socket, 'socket'):
                socket = socket.socket

            return socket.getpeername()[0]

        except Exception:  #pragma: no cover
            return None

    def read(self, amt=None):
        buff = self.fp.read(amt)
        self.transaction.write_response(buff)
        return buff

    def readinto(self, buff):
        res = self.fp.readinto(buff)
        if res:
            # record only the bytes actually read on a short read,
            # not the entire (partially unfilled) buffer
            self.transaction.write_response(buff[:res])
        return res

    def readline(self, maxlen=-1):
        line = self.fp.readline(maxlen)
        self.transaction.write_response(line)
        return line

    def close(self):
        try:
            self.transaction.done()
        finally:
            # close the socket file even if the transaction (e.g. a
            # filter function) raised
            if self.fp is not None:
                self.fp.close()

    def flush(self):
        return self.fp.flush()


# ============================================================================
class RecordingHTTPResponse(httplib.HTTPResponse):
    def __init__(self, transaction, *args, **kwargs):
        httplib.HTTPResponse.__init__(self, *args, **kwargs)
        self.fp = RecordingStream(self.fp, transaction)


# ============================================================================
class RecordingHTTPConnection(httplib.HTTPConnection):
    local = threading.local()

    def __init__(self, *args, **kwargs):
        orig_connection.__init__(self, *args, **kwargs)

        # transaction currently recorded on this connection, if any
        self._capture_tx = None

        # CONNECT tunnel target, tracked per connection: the CONNECT
        # exchange happens before (and independently of) any recorded
        # transaction on this connection
        self._connect_host = None
        self._connect_port = None
        self._connect_checked = False

        # whether response_class was patched by us on this connection
        self._recording_response_class = False

    @staticmethod
    def current_recorder():
        """The recorder of the innermost capture context currently
        active on this thread, or None if no context is active."""
        stack = getattr(RecordingHTTPConnection.local, 'recorder_stack', None)
        if stack:
            return stack[-1]
        return None

    def putrequest(self, *args, **kwargs):
        # Attribute the new request to the innermost capture context
        # active *right now* -- not to whatever context (if any) was
        # active when this connection was created. This makes reused
        # connections work: requests started inside a context are
        # recorded, requests started outside any context are not.
        result = orig_connection.putrequest(self, *args, **kwargs)

        recorder = self.current_recorder()
        if recorder is not None:
            tx = recorder.start_transaction()
            tx.connect_host = self._connect_host
            tx.connect_port = self._connect_port
            if self._connect_host:
                tx.warc_headers['WARC-Proxy-Host'] = \
                    'https://{0}:{1}'.format(self.host, self.port)

            self._capture_tx = tx

            def make_recording_response(*args, **kwargs):
                return RecordingHTTPResponse(tx, *args, **kwargs)

            self.response_class = make_recording_response
            self._recording_response_class = True
        else:
            self._capture_tx = None
            if self._recording_response_class:
                del self.response_class
                self._recording_response_class = False

        return result

    def send(self, data):
        self._track_connect(data)

        tx = self._capture_tx
        if tx is None:
            orig_connection.send(self, data)
            return

        def send_request(buff):
            tx.extract_url(buff, self.host, self.port, self.default_port)

            orig_connection.send(self, buff)
            tx.write_request(buff)

        # if sending request body as stream
        # (supported via httplib but seems unused via higher-level apis)
        if hasattr(data, 'read') and not isinstance(data, array):  #pragma: no cover
            while True:
                buff = data.read(BUFF_SIZE)
                if not buff:
                    break

                send_request(buff)
        else:
            send_request(data)

    def _track_connect(self, data):
        # Track the tunnel target of a CONNECT request on the connection
        # itself, so that transactions started later (after the tunnel
        # is established) can compute the correct target url.
        if self._connect_checked:
            return

        self._connect_checked = True

        try:
            line = to_native_str(BytesIO(data).readline(), 'latin-1')
            parts = line.split(' ', 2)
            if parts[0] != 'CONNECT':
                return

            target = parts[1].split(':', 1)
            self._connect_host = target[0]
            self._connect_port = int(target[1]) if len(target) > 1 \
                else self.default_port
        except Exception:
            pass

    def _tunnel(self, *args, **kwargs):
        if self._capture_tx is not None:
            self._capture_tx.start_tunnel()

        return orig_connection._tunnel(self, *args, **kwargs)


# ============================================================================
class RecordingTransaction(object):
    """Recording state of a single request/response pair.

    Each transaction owns its private buffers, url and WARC headers,
    so interleaved transactions on different connections of the same
    thread never share state. A transaction is written to the WARC at
    most once, by the recorder (capture context) that started it.
    """

    def __init__(self, recorder):
        self.recorder = recorder
        self.request_out = recorder._create_buffer()
        self.response_out = recorder._create_buffer()
        self.url = None
        self.connect_host = self.connect_port = None
        self.started_req = True
        self.first_line_read = False
        self.warc_headers = {}
        self.done_called = False

    def start_tunnel(self):
        self.started_req = False
        self.first_line_read = False

    def set_remote_ip(self, remote_ip):
        if self.recorder.record_ip and remote_ip:
            self.warc_headers['WARC-IP-Address'] = remote_ip

    def write_request(self, buff):
        if self.started_req:
            self.request_out.write(buff)

    def write_response(self, buff):
        if self.started_req:
            self.response_out.write(buff)

    def _create_record(self, out, record_type):
        length = out.tell()
        out.seek(0)
        return self.recorder.writer.create_warc_record(
                warc_headers_dict=self.warc_headers,
                uri=self.url,
                record_type=record_type,
                payload=out,
                length=length)

    def done(self):
        # each transaction is written to the WARC at most once
        if self.done_called:
            return

        self.done_called = True

        try:
            if not self.started_req:
                return

            recorder = self.recorder
            if not recorder.active:
                # the owning capture context has already exited:
                # release the buffers without writing anything
                return

            request = self._create_record(self.request_out, 'request')
            response = self._create_record(self.response_out, 'response')

            if recorder.filter_func:
                request, response = recorder.filter_func(request, response,
                                                         recorder)
                if not request or not response:
                    return

            with recorder.lock:
                recorder.writer.write_request_response_pair(request, response)
        finally:
            # always release this transaction's buffers, even if the
            # filter or the writer raised -- other in-flight
            # transactions are not affected
            self.started_req = False
            self.request_out.close()
            self.response_out.close()

    def extract_url(self, data, host, port, default_port):
        if self.first_line_read:
            return

        self.first_line_read = True
        buff = BytesIO(data)
        line = to_native_str(buff.readline(), 'latin-1')

        parts = line.split(' ', 2)
        verb = parts[0]
        path = parts[1]

        if verb == "CONNECT":
            parts = path.split(":", 1)
            self.connect_host = parts[0]
            self.connect_port = int(parts[1]) if len(parts) > 1 else default_port
            self.warc_headers['WARC-Proxy-Host'] = "https://{0}:{1}".format(host, port)
            return

        if self.connect_host:
            host = self.connect_host

        if self.connect_port:
            port = self.connect_port

        if path.startswith(('http:', 'https:')):
            self.warc_headers['WARC-Proxy-Host'] = "http://{0}:{1}".format(host, port)
            self.url = path
            return

        scheme = 'https' if default_port == 443 else 'http'
        self.url = scheme + '://' + host
        if port != default_port:
            self.url += ':' + str(port)

        self.url += path


# ============================================================================
class RequestRecorder(object):
    """Recorder for a single ``capture_http`` context.

    Owns the writer, filter function and write lock of one context and
    hands out an independent :class:`RecordingTransaction` per request,
    so that requests are always attributed to the context that was
    innermost when the request was started.
    """

    def __init__(self, writer, filter_func=None, record_ip=True):
        self.writer = writer
        self.filter_func = filter_func
        self.lock = threading.Lock()
        self.record_ip = record_ip
        self.active = True

    def start_transaction(self):
        return RecordingTransaction(self)

    def _create_buffer(self):
        return SpooledTemporaryFile(BUFF_SIZE)


# ============================================================================
httplib.HTTPConnection = RecordingHTTPConnection
# ============================================================================

@contextmanager
def capture_http(warc_writer=None, filter_func=None, append=True,
                record_ip=True, **kwargs):
    """Capture HTTP(S) traffic of the current thread into a WARC.

    Requests are attributed to the innermost ``capture_http`` context
    that is active on the current thread when the request is *started*
    (``putrequest``), regardless of when the underlying connection was
    created:

    - Connections created outside any context may be reused inside a
      context; requests sent on them while the context is active are
      recorded.
    - Requests started outside any context are never recorded, even on
      connections that were used for recording before.
    - Contexts may be nested: while an inner context is active its
      requests go to the inner writer; when the inner context exits
      (normally or via an exception), the outer context is restored.
    - A response is attributed to the context that started its
      request, even if the response body is read while a different
      (inner) context is active. Responses should be closed (read to
      completion or explicitly closed) before their owning context
      exits; transactions still open when their context exits are
      discarded without writing.
    - Recording state is thread-local and does not propagate across
      threads.

    Each request/response pair is written at most once, when its
    response is closed. If a response is closed early, only the bytes
    actually read are recorded.
    """
    out = None
    if warc_writer == None:
        if 'gzip' not in kwargs:
            kwargs['gzip'] = False

        warc_writer = BufferWARCWriter(**kwargs)

    if isinstance(warc_writer, str):
        out = open(warc_writer, 'ab' if append else 'xb')
        warc_writer = WARCWriter(out, **kwargs)

    recorder = RequestRecorder(warc_writer, filter_func, record_ip=record_ip)

    local = RecordingHTTPConnection.local
    stack = getattr(local, 'recorder_stack', None)
    if stack is None:
        stack = local.recorder_stack = []

    stack.append(recorder)

    try:
        yield warc_writer

    finally:
        # restore the enclosing context (if any), even on exception
        recorder.active = False
        try:
            stack.remove(recorder)
        except ValueError:  #pragma: no cover
            pass
        if out:
            out.close()
