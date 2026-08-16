from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from auth_core.entity.session import ClientType, SessionError
from auth_core.infrastructure.security.tokens import LocalRS256TokenProvider


def test_rs256_access_token_has_public_jwks_and_required_claims() -> None:
    provider = LocalRS256TokenProvider("https://issuer.test", "grox-test")
    now = datetime.now(UTC)
    user_id, session_id, family_id, jti = (uuid4() for _ in range(4))

    token, expires_at = provider.issue(
        user_id,
        session_id,
        family_id,
        jti,
        ClientType.WEB,
        ("password", "mfa"),
        now,
    )
    claims = provider.verify(token, now)
    jwks = provider.jwks()

    assert claims.user_id == user_id
    assert claims.session_id == session_id
    assert claims.assurance == ("password", "mfa")
    assert expires_at <= now + timedelta(minutes=15, seconds=1)
    assert jwks["keys"]
    assert "private" not in str(jwks).lower()


def test_access_token_from_another_signing_key_is_rejected() -> None:
    issuer = LocalRS256TokenProvider("https://issuer.test", "grox-test")
    verifier = LocalRS256TokenProvider("https://issuer.test", "grox-test")
    now = datetime.now(UTC)
    token, _ = issuer.issue(
        uuid4(), uuid4(), uuid4(), uuid4(), ClientType.MOBILE, ("passkey",), now
    )

    with pytest.raises(SessionError):
        verifier.verify(token, now)
