import base64
import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import InvalidTokenError

from auth_core.entity.session import (
    AccessClaims,
    ClientType,
    SessionError,
    SessionErrorCode,
)


class LocalRS256TokenProvider:
    def __init__(
        self,
        issuer: str,
        audience: str,
        access_ttl_seconds: int = 900,
        private_key: rsa.RSAPrivateKey | None = None,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._access_ttl = timedelta(seconds=access_ttl_seconds)
        self._private_key = private_key or rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self._public_key = self._private_key.public_key()
        public_der = self._public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._kid = hashlib.sha256(public_der).hexdigest()[:16]

    def issue(
        self,
        user_id: UUID,
        session_id: UUID,
        family_id: UUID,
        jti: UUID,
        client_type: ClientType,
        assurance: tuple[str, ...],
        now: datetime,
        workspace_id: UUID | None = None,
        workspace_type: str | None = None,
        roles: tuple[str, ...] = (),
    ) -> tuple[str, datetime]:
        issued_at = now.astimezone(UTC)
        expires_at = issued_at + self._access_ttl
        claims = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": str(user_id),
            "sid": str(session_id),
            "fid": str(family_id),
            "jti": str(jti),
            "iat": issued_at,
            "nbf": issued_at,
            "exp": expires_at,
            "client_type": client_type.value,
            "amr": list(assurance),
        }
        if workspace_id is not None and workspace_type is not None:
            claims["wid"] = str(workspace_id)
            claims["wtype"] = workspace_type
            claims["roles"] = list(roles)
        token = jwt.encode(
            claims,
            self._private_key,
            algorithm="RS256",
            headers={"kid": self._kid, "typ": "JWT"},
        )
        return token, expires_at

    def verify(self, token: str, now: datetime) -> AccessClaims:
        del now
        try:
            payload = jwt.decode(
                token,
                self._public_key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "nbf", "sub", "sid", "fid", "jti"]},
            )
            issued_at = datetime.fromtimestamp(int(payload["iat"]), UTC)
            expires_at = datetime.fromtimestamp(int(payload["exp"]), UTC)
            assurance_value = payload.get("amr", [])
            assurance = tuple(str(item) for item in assurance_value)
            workspace_id = UUID(str(payload["wid"])) if payload.get("wid") else None
            workspace_type = str(payload["wtype"]) if payload.get("wtype") else None
            role_values = payload.get("roles", [])
            roles = tuple(str(item) for item in role_values)
            return AccessClaims(
                user_id=UUID(str(payload["sub"])),
                session_id=UUID(str(payload["sid"])),
                family_id=UUID(str(payload["fid"])),
                jti=UUID(str(payload["jti"])),
                issued_at=issued_at,
                expires_at=expires_at,
                client_type=ClientType(str(payload["client_type"])),
                assurance=assurance,
                workspace_id=workspace_id,
                workspace_type=workspace_type,
                roles=roles,
            )
        except (InvalidTokenError, KeyError, TypeError, ValueError) as error:
            raise SessionError(
                SessionErrorCode.TOKEN_INVALID,
                "The access token is invalid or expired.",
                401,
            ) from error

    def jwks(self) -> Mapping[str, object]:
        numbers = self._public_key.public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self._kid,
                    "n": self._encode_integer(numbers.n),
                    "e": self._encode_integer(numbers.e),
                }
            ]
        }

    @staticmethod
    def _encode_integer(value: int) -> str:
        size = (value.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(value.to_bytes(size, "big")).decode().rstrip("=")


def jwks_dict(value: Mapping[str, object]) -> dict[str, Any]:
    return cast(dict[str, Any], value)
