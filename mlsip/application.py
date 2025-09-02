# mlsip/application.py
import asyncio
import logging
import traceback
from collections.abc import MutableMapping
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union

import aiodns  # Resolver de DNS assíncrono

from .dialplan import Dialplan
from .protocol import Protocol, create_connector
from .dialog import Dialog
from .peers import Peer
from .contact import Contact
from .via import Via

LOG = logging.getLogger("mlsip")

Middleware = Callable[["Application", Any, Any, Callable], Awaitable[Any]]
Handler = Callable[[Any, Any], Awaitable[Any]]


class Application(MutableMapping):
    """
    Representa uma aplicação SIP.

    Gerencia:
      - Middlewares
      - Dialplan (roteamento de requisições)
      - Peers e diálogos
      - Conexões (UDP, TCP, WS)
      - Ciclo de vida (inicialização e fechamento)

    Exemplo de uso:
        app = Application()
        app["user_agent"] = "mlsip/0.1"
        app.run_forever()
    """

    def __init__(self, loop: Optional[asyncio.AbstractEventLoop] = None, **kwargs: Any) -> None:
        self.loop: asyncio.AbstractEventLoop = loop or asyncio.get_event_loop()
        self.dns: aiodns.DNSResolver = aiodns.DNSResolver(loop=self.loop)

        # Middlewares de tratamento
        self._middlewares: List[Middleware] = [
            self.error_middleware,
            self.middleware,
        ]

        # Configurações padrão
        self._defaults: Dict[str, Any] = {
            "user_agent": "mlsip/0.1",
            "override_contact_host": None,
            "override_contact_port": None,
            "outbound_proxy": None,
        }

        # Estado interno
        self.dialplan: Dialplan = Dialplan()
        self._connectors: List[Callable] = []
        self._protocols: List[Protocol] = []
        self._peers: Dict[str, Peer] = {}
        self._dialogs: Dict[str, Dialog] = {}
        self._fut: Optional[asyncio.Future] = None

        # Configurações dinâmicas (dict-like)
        self._kwargs: Dict[str, Any] = kwargs

    # ---------------------------------------------------------------------
    # Propriedades auxiliares
    # ---------------------------------------------------------------------

    @property
    def user_agent(self) -> str:
        """Retorna o User-Agent configurado."""
        return self._kwargs.get("user_agent", self._defaults["user_agent"])

    # ---------------------------------------------------------------------
    # Middlewares
    # ---------------------------------------------------------------------

    async def middleware(self, app: "Application", msg: Any, addr: Any, handler: Handler) -> Any:
        """Middleware padrão que apenas despacha a requisição."""
        return await handler(msg, addr)

    async def error_middleware(self, app: "Application", msg: Any, addr: Any, handler: Handler) -> Any:
        """Captura exceções e envia resposta SIP 500 (Internal Error)."""
        try:
            return await handler(msg, addr)
        except Exception as e:
            LOG.exception("Erro ao processar mensagem SIP")
            try:
                await app._respond(msg, code=500, reason="Internal Error")
            except Exception:
                LOG.error("Falha ao enviar resposta de erro", exc_info=True)
            return None

    # ---------------------------------------------------------------------
    # Configuração e registro
    # ---------------------------------------------------------------------

    def add_protocol(self, proto: Protocol) -> None:
        """Adiciona protocolo ativo (UDP/TCP/WS)."""
        self._protocols.append(proto)

    def add_connector(self, protocol: str, *args: Any, **kwargs: Any) -> None:
        """Registra um conector (ex.: UDP, TCP)."""
        self._connectors.append(create_connector(protocol, *args, **kwargs))

    def register_peer(self, peer: Peer) -> None:
        """Registra um peer SIP."""
        self._peers[peer.name] = peer

    def unregister_peer(self, peer: Peer) -> None:
        """Remove um peer SIP registrado."""
        self._peers.pop(peer.name, None)

    # ---------------------------------------------------------------------
    # Ciclo de vida
    # ---------------------------------------------------------------------

    def run_forever(self) -> None:
        """Executa a aplicação indefinidamente."""
        self._fut = asyncio.ensure_future(self._run(), loop=self.loop)
        try:
            self.loop.run_forever()
        except KeyboardInterrupt:
            LOG.info("Encerrando aplicação SIP...")
            self.loop.run_until_complete(self.close())

    async def _run(self) -> None:
        """Inicializa todos os conectores registrados."""
        for connector in self._connectors:
            await connector(self)

    async def finish(self) -> None:
        """Finaliza peers ativos."""
        for peer in list(self._peers.values()):
            try:
                await peer.close()
            except Exception:
                LOG.warning("Erro ao fechar peer %s", peer.name, exc_info=True)

    async def close(self) -> None:
        """Fecha protocolos e finaliza execução."""
        await self.finish()

        for proto in self._protocols:
            proto.close()

        if self._fut:
            self._fut.cancel()

    # ---------------------------------------------------------------------
    # Roteamento de mensagens
    # ---------------------------------------------------------------------

    async def _dispatch(self, msg: Any, addr: Any, protocol: Protocol) -> None:
        """Despacha uma mensagem SIP pelo pipeline de middlewares."""
        async def handler(m: Any, a: Any) -> Any:
            return await self._run_dialplan(m, a, protocol)

        middleware_chain = handler
        for m in reversed(self._middlewares):
            next_handler = middleware_chain
            middleware_chain = lambda m=msg, a=addr, mw=m, nh=next_handler: mw(self, m, a, nh)

        await middleware_chain(msg, addr)

    async def _run_dialplan(self, msg: Any, addr: Any, protocol: Protocol) -> None:
        """Executa o dialplan para uma mensagem SIP."""
        dialog_id = Dialog.compute_id(msg)
        if dialog_id in self._dialogs:
            dialog = self._dialogs[dialog_id]
            await dialog.run(msg, addr, protocol)
            return

        handler = self.dialplan.resolve(msg)
        if handler:
            await handler(self, msg, addr, protocol)
        else:
            await self._respond(msg, code=501, reason="Not Implemented")

    # ---------------------------------------------------------------------
    # Respostas SIP utilitárias
    # ---------------------------------------------------------------------

    async def _respond(self, msg: Any, code: int, reason: str) -> None:
        """Envia uma resposta SIP simples."""
        proto = msg.protocol  # assumindo que msg já tem protocolo associado
        await proto.send_response(msg, code=code, reason=reason)

    # ---------------------------------------------------------------------
    # MutableMapping API
    # ---------------------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        return self._kwargs.get(key, self._defaults.get(key))

    def __setitem__(self, key: str, value: Any) -> None:
        self._kwargs[key] = value

    def __delitem__(self, key: str) -> None:
        if key in self._kwargs:
            del self._kwargs[key]

    def __iter__(self):
        return iter({**self._defaults, **self._kwargs})

    def __len__(self) -> int:
        return len({**self._defaults, **self._kwargs})
