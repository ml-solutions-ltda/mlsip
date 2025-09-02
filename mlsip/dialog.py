import enum
import asyncio
import logging
from collections import defaultdict

from multidict import CIMultiDict
from async_timeout import timeout as Timeout

from . import utils
from .auth import AuthenticateAuth, AuthorizationAuth
from .message import Request, Response
from .transaction import UnreliableTransaction

LOG = logging.getLogger(__name__)


class CallState(enum.Enum):
    Calling = enum.auto()
    Proceeding = enum.auto()
    Completed = enum.auto()
    Terminated = enum.auto()


class DialogBase:
    def __init__(self, app, method, from_details, to_details, call_id, peer, contact_details,
                 *, headers=None, payload=None, password=None, cseq=0, inbound=False):
        self.app = app
        self.from_details = from_details
        self.to_details = to_details
        self.contact_details = contact_details
        self.call_id = call_id
        self.peer = peer
        self.password = password
        self.cseq = cseq
        self.inbound = inbound
        self.transactions = defaultdict(dict)
        self.auth = None

        self.original_msg = self._prepare_request(method, headers=headers, payload=payload)
        self._closed = False
        self._closing = None

    @property
    def dialog_id(self):
        return frozenset((
            self.original_msg.to_details['params'].get('tag'),
            self.original_msg.from_details['params']['tag'],
            self.call_id
        ))

    def _receive_response(self, msg):
        if 'tag' not in self.to_details['params']:
            del self.app._dialogs[self.dialog_id]
            self.to_details['params']['tag'] = msg.to_details['params']['tag']
            self.app._dialogs[self.dialog_id] = self
        try:
            transaction = self.transactions[msg.method][msg.cseq]
            transaction._incoming(msg)
        except KeyError:
            if msg.method != 'ACK':
                LOG.debug('Response without Request. Transaction may already be closed. \n%s', msg)

    def _prepare_request(self, method, contact_details=None, headers=None, payload=None,
                         cseq=None, to_details=None):
        if not cseq:
            self.cseq += 1
        if contact_details:
            self.contact_details = contact_details

        headers = CIMultiDict(headers or {})
        if 'User-Agent' not in headers:
            headers['User-Agent'] = self.app.defaults['user_agent']
        headers['Call-ID'] = self.call_id

        return Request(
            method=method,
            cseq=cseq or self.cseq,
            from_details=self.from_details,
            to_details=to_details or self.to_details,
            contact_details=self.contact_details,
            headers=headers,
            payload=payload,
        )

    async def start(self, *, expires=None, timeout=None):
        headers = self.original_msg.headers
        if expires is not None:
            headers['Expires'] = expires
        return await self.request(
            self.original_msg.method,
            headers=headers,
            payload=self.original_msg.payload,
            timeout=timeout
        )

    def ack(self, msg, headers=None, *args, **kwargs):
        headers = CIMultiDict(headers or {})
        headers['Via'] = msg.headers['Via']
        ack = self._prepare_request('ACK', cseq=msg.cseq, to_details=msg.to_details, headers=headers, *args, **kwargs)
        self.peer.send_message(ack)

    async def unauthorized(self, msg, realm='sip', algorithm='md5', **kwargs):
        if 'Authorization' not in msg.headers or self.auth is None:
            self.auth = AuthenticateAuth(
                nonce=utils.gen_str(10),
                realm=realm,
                method=msg.method,
                algorithm=algorithm,
                **kwargs
            )
        headers = CIMultiDict()
        headers['WWW-Authenticate'] = str(self.auth)
        await self.reply(msg, status_code=401, headers=headers)

    def validate_auth(self, message, password):
        if isinstance(message.auth, AuthorizationAuth) and self.auth.validate_authorization(
            message.auth, password=password, username=message.auth['username'],
            uri=message.auth['uri'], payload=message.payload
        ):
            return True
        return message.method == 'CANCEL'

    def close_later(self, delay=None):
        delay = delay or self.app.defaults['dialog_closing_delay']
        if self._closing:
            self._closing.cancel()

        async def closure():
            await asyncio.sleep(delay)
            await self.close()

        self._closing = asyncio.ensure_future(closure())
        self._closing.add_done_callback(utils._callback)

    def _maybe_close(self, msg):
        if msg.method in ('REGISTER', 'SUBSCRIBE') and not self.inbound:
            expire = int(msg.headers.get('Expires', 0))
            delay = int(expire * 1.1) if expire else None
            self.close_later(delay)
        elif msg.method != 'NOTIFY':
            self.close_later()

    def _close(self):
        LOG.debug('Closing: %s', self)
        if self._closing:
            self._closing.cancel()
        for transactions in self.transactions.values():
            for transaction in transactions.values():
                transaction.close()
        self.app._dialogs.pop(self.dialog_id, None)

    def _connection_lost(self):
        for transactions in self.transactions.values():
            for transaction in transactions.values():
                transaction._error(ConnectionError)

    async def start_unreliable_transaction(self, msg, method=None):
        transaction = UnreliableTransaction(self, original_msg=msg, loop=self.app.loop)
        self.transactions[method or msg.method][msg.cseq] = transaction
        return await transaction.start()

    def end_transaction(self, transaction):
        to_delete = [(method, cseq) for method, values in self.transactions.items()
                     for cseq, t in values.items() if t is transaction]
        for method, cseq in to_delete:
            self.transactions[method][cseq].close()
            del self.transactions[method][cseq]

    async def request(self, method, contact_details=None, headers=None, payload=None, timeout=None):
        msg = self._prepare_request(method, contact_details, headers, payload)
        if msg.method != 'ACK':
            async with Timeout(timeout):
                return await self.start_unreliable_transaction(msg)
        else:
            self.peer.send_message(msg)

    async def reply(self, request, status_code, status_message=None, payload=None, headers=None, contact_details=None):
        msg = self._prepare_response(request, status_code, status_message, payload, headers, contact_details)
        self.peer.send_message(msg)

    def _prepare_response(self, request, status_code, status_message=None, payload=None, headers=None, contact_details=None):
        if contact_details:
            self.contact_details = contact_details
        headers = CIMultiDict(headers or {})
        headers.setdefault('User-Agent', self.app.defaults['user_agent'])
        headers['Call-ID'] = self.call_id
        headers['Via'] = request.headers['Via']

        return Response(
            status_code=status_code,
            status_message=status_message,
            headers=headers,
            from_details=self.to_details,
            to_details=self.from_details,
            contact_details=self.contact_details,
            payload=payload,
            cseq=request.cseq,
            method=request.method
        )

    def __repr__(self):
        return f'<{self.__class__.__name__} call_id={self.call_id}, peer={self.peer}>'

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        await self.close()


class Dialog(DialogBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._nonce = None
        self._incoming = asyncio.Queue()

    async def receive_message(self, msg):
        if self._closing:
            self._closing.cancel()
        if self.cseq < msg.cseq:
            self.cseq = msg.cseq
        if isinstance(msg, Response) or msg.method == 'ACK':
            return self._receive_response(msg)
        return await self._receive_request(msg)

    async def _receive_request(self, msg):
        if 'tag' in msg.to_details['params']:
            self.app._dialogs.pop(frozenset((self.original_msg.to_details['params'].get('tag'), None, self.call_id)), None)
        await self._incoming.put(msg)
        self._maybe_close(msg)

    async def refresh(self, headers=None, expires=1800, *args, **kwargs):
        headers = CIMultiDict(headers or {})
        headers.setdefault('Expires', int(expires))
        return await self.request(self.original_msg.method, headers=headers, *args, **kwargs)

    async def close(self, headers=None, fast=False, *args, **kwargs):
        if not self._closed:
            self._closed = True
            if not fast and not self.inbound and self.original_msg.method in ('REGISTER', 'SUBSCRIBE'):
                headers = CIMultiDict(headers or {})
                headers.setdefault('Expires', 0)
                try:
                    await self.request(self.original_msg.method, headers=headers, *args, **kwargs)
                finally:
                    self._close()
            self._close()

    async def notify(self, *args, headers=None, **kwargs):
        headers = CIMultiDict(headers or {})
        headers.setdefault('Event', 'dialog')
        headers.setdefault('Content-Type', 'application/dialog-info+xml')
        headers.setdefault('Subscription-State', 'active')
        return await self.request('NOTIFY', *args, headers=headers, **kwargs)

    def cancel(self, *args, **kwargs):
        cancel = self._prepare_request('CANCEL', *args, **kwargs)
        self.peer.send_message(cancel)

    async def recv(self):
        return await self._incoming.get()


class InviteDialog(DialogBase):
    def __init__(self, *args, **kwargs):
        kwargs['method'] = 'INVITE'
        super().__init__(*args, **kwargs)
        self._queue = asyncio.Queue()
        self._state = CallState.Calling
        self._waiter = asyncio.Future()

    async def receive_message(self, msg):
        if 'tag' not in self.to_details['params']:
            del self.app._dialogs[self.dialog_id]
            self.to_details['params']['tag'] = msg.to_details['params']['tag']
            self.app._dialogs[self.dialog_id] = self

        await self._queue.put(msg)
        await self._handle_state(msg)

    async def _handle_state(self, msg):
        if self._state in (CallState.Calling, CallState.Proceeding):
            if 100 <= msg.status_code < 200:
                self._state = CallState.Proceeding
            elif msg.status_code == 200:
                self._state = CallState.Terminated
                self.ack(msg)
                if not self._waiter.done():
                    self._waiter.set_result(msg)
            elif 300 <= msg.status_code < 700:
                self._state = CallState.Completed
                self.ack(msg)
                if not self._waiter.done():
                    self._waiter.set_result(msg)
        elif self._state == CallState.Completed:
            self.ack(msg)
        elif self._state == CallState.Terminated:
            if isinstance(msg, Response) or msg.method == 'ACK':
                return self._receive_response(msg)
            else:
                return await self._receive_request(msg)

    async def _receive_request(self, msg):
        if 'tag' in msg.from_details['params']:
            self.to_details['params']['tag'] = msg.from_details['params']['tag']
        if msg.method == 'BYE':
            self._closed = True
        self._maybe_close(msg)

    @property
    def state(self):
        return self._state

    async def start(self, *, expires=None):
        self.peer.send_message(self.original_msg)

    async def recv(self):
        return await self._queue.get()

    async def wait_for_terminate(self):
        while not self._waiter.done():
            yield await self._queue.get()

    async def ready(self):
        msg = await self._waiter
        if msg.status_code != 200:
            raise RuntimeError(f"INVITE failed with {msg.status_code}")

    async def close(self, timeout=None):
        if not self._closed:
            self._closed = True
            msg = None
            if self._state == CallState.Terminated:
                msg = self._prepare_request('BYE')
            elif self._state != CallState.Completed:
                msg = self._prepare_request('CANCEL')
            if msg:
                transaction = UnreliableTransaction(self, original_msg=msg, loop=self.app.loop)
                self.transactions[msg.method][msg.cseq] = transaction
                try:
                    async with Timeout(timeout):
                        await transaction.start()
                finally:
                    self._close()
        self._close()
