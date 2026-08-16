import base64
import hmac
import json
from hashlib import sha256

import pytest

from auth_core.entity.login import OIDCProfile
from auth_core.infrastructure.providers.oidc import LocalOIDCProvider


@pytest.mark.asyncio
async def test_local_oidc_simulator_enforces_issuer_audience_nonce_and_pkce() -> None:
    provider = LocalOIDCProvider(b"local-oidc-test-signing-secret", "http://localhost:3000")
    profile = OIDCProfile("google", "subject-1", "person@example.com", True)
    code = provider.issue_test_code(profile, "expected-nonce", "expected-verifier")

    verified = await provider.verify_callback(
        "google", code, "expected-nonce", "expected-verifier"
    )

    assert verified == profile


@pytest.mark.asyncio
async def test_local_oidc_simulator_rejects_wrong_audience_even_with_valid_signature() -> None:
    secret = b"local-oidc-test-signing-secret"
    nonce = "expected-nonce"
    verifier = "expected-verifier"
    payload = json.dumps(
        {
            "provider": "google",
            "issuer": "http://localhost:3000/auth/local-oidc",
            "audience": "another-application",
            "subject": "subject-1",
            "email": "person@example.com",
            "email_verified": True,
        },
        separators=(",", ":"),
    ).encode()
    encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    signature = hmac.new(secret, payload + nonce.encode() + verifier.encode(), sha256).hexdigest()
    code = f"{encoded}.{signature}"
    provider = LocalOIDCProvider(secret, "http://localhost:3000")

    with pytest.raises(ValueError):
        await provider.verify_callback("google", code, nonce, verifier)
