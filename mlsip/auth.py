"""
mlsip.auth
~~~~~~~~~~

Módulo de autenticação SIP baseado em Digest Authentication (RFC 3261 / RFC 2617).
Responsável por gerar e validar cabeçalhos Authorization e WWW-Authenticate.
"""

import hashlib
import os
import re
import time
from typing import Optional, Dict


# ==========================================================
# Funções utilitárias
# ==========================================================

def _md5_hex(data: str) -> str:
    """Retorna o MD5 hexdigest de uma string."""
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def _gen_nonce() -> str:
    """Gera um nonce aleatório para desafio de autenticação."""
    return hashlib.md5(f"{time.time()}-{os.urandom(8)}".encode("utf-8")).hexdigest()


# ==========================================================
# Classes principais
# ==========================================================

class DigestChallenge:
    """
    Representa um desafio WWW-Authenticate enviado pelo servidor.
    Exemplo:
        WWW-Authenticate: Digest realm="mlsip", nonce="abc123", algorithm=MD5, qop="auth"
    """

    def __init__(self, realm: str, algorithm: str = "MD5", qop: str = "auth"):
        self.realm = realm
        self.nonce = _gen_nonce()
        self.algorithm = algorithm.upper()
        self.qop = qop

    def to_header(self) -> str:
        """Gera o cabeçalho WWW-Authenticate."""
        return (
            f'Digest realm="{self.realm}", '
            f'nonce="{self.nonce}", '
            f'algorithm={self.algorithm}, '
            f'qop="{self.qop}"'
        )


class DigestResponse:
    """
    Representa a resposta de autenticação enviada pelo cliente no cabeçalho Authorization.
    Calcula e valida a resposta MD5 de acordo com o desafio do servidor.
    """

    def __init__(
        self,
        username: str,
        password: str,
        method: str,
        uri: str,
        realm: str,
        nonce: str,
        nc: str = "00000001",
        cnonce: Optional[str] = None,
        qop: str = "auth",
        algorithm: str = "MD5",
    ):
        self.username = username
        self.password = password
        self.method = method
        self.uri = uri
        self.realm = realm
        self.nonce = nonce
        self.nc = nc
        self.cnonce = cnonce or _gen_nonce()
        self.qop = qop
        self.algorithm = algorithm.upper()

        self.response = self._calculate_response()

    # ------------------------------------------------------

    def _calculate_response(self) -> str:
        """Calcula o hash de resposta (HA1/HA2/response)."""
        if self.algorithm != "MD5":
            raise ValueError(f"Algoritmo não suportado: {self.algorithm}")

        ha1 = _md5_hex(f"{self.username}:{self.realm}:{self.password}")
        ha2 = _md5_hex(f"{self.method}:{self.uri}")

        return _md5_hex(
            f"{ha1}:{self.nonce}:{self.nc}:{self.cnonce}:{self.qop}:{ha2}"
        )

    def to_header(self) -> str:
        """Retorna o cabeçalho Authorization pronto para envio."""
        return (
            f'Digest username="{self.username}", '
            f'realm="{self.realm}", '
            f'nonce="{self.nonce}", '
            f'uri="{self.uri}", '
            f'algorithm={self.algorithm}, '
            f'response="{self.response}", '
            f'qop={self.qop}, '
            f'nc={self.nc}, '
            f'cnonce="{self.cnonce}"'
        )

    # ------------------------------------------------------

    @classmethod
    def from_header(cls, header: str, password: str, method: str) -> "DigestResponse":
        """
        Constrói um DigestResponse a partir de um cabeçalho Authorization SIP.
        """
        pattern = re.compile(r'(\w+)="?(.*?)"?(?:,|$)')
        parts: Dict[str, str] = dict(pattern.findall(header))

        return cls(
            username=parts.get("username"),
            password=password,
            method=method,
            uri=parts.get("uri"),
            realm=parts.get("realm"),
            nonce=parts.get("nonce"),
            nc=parts.get("nc", "00000001"),
            cnonce=parts.get("cnonce"),
            qop=parts.get("qop", "auth"),
            algorithm=parts.get("algorithm", "MD5"),
        )

    # ------------------------------------------------------

    def verify(self, expected_password: str) -> bool:
        """
        Verifica se a resposta recebida bate com a senha esperada.
        """
        expected = DigestResponse(
            username=self.username,
            password=expected_password,
            method=self.method,
            uri=self.uri,
            realm=self.realm,
            nonce=self.nonce,
            nc=self.nc,
            cnonce=self.cnonce,
            qop=self.qop,
            algorithm=self.algorithm,
        )
        return self.response == expected.response
