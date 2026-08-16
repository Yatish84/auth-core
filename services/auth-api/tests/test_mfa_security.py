import pytest

from auth_core.infrastructure.providers.totp import PyOTPProvider
from auth_core.infrastructure.providers.webauthn import PyWebAuthnProvider
from auth_core.infrastructure.security.secrets import LocalAESGCMSecretCipher

TEST_KEY = "bG9jYWwtbWZhLWtleS1jaGFuZ2UtbWUtMzItYnl0ZXM="


def test_aes_gcm_secret_rejects_tampering_and_wrong_context() -> None:
    cipher = LocalAESGCMSecretCipher(TEST_KEY)
    encrypted = cipher.encrypt(b"totp-secret", b"user-one")

    assert cipher.decrypt(encrypted, b"user-one") == b"totp-secret"
    with pytest.raises(ValueError):
        cipher.decrypt(encrypted, b"user-two")
    with pytest.raises(ValueError):
        cipher.decrypt(encrypted[:-1] + bytes([encrypted[-1] ^ 1]), b"user-one")


def test_totp_provider_rejects_reuse_of_accepted_time_step() -> None:
    provider = PyOTPProvider("Vittavaan Test")
    secret = provider.generate_secret()
    import pyotp

    code = pyotp.TOTP(secret).now()
    step = provider.verify(secret, code, None)

    assert step is not None
    assert provider.verify(secret, code, step) is None


def test_webauthn_options_require_resident_key_and_user_verification() -> None:
    provider = PyWebAuthnProvider(
        "localhost", "Vittavaan Test", ["http://localhost:3000"]
    )
    from uuid import uuid4

    options, challenge = provider.registration_options(
        uuid4(), "person@example.com", ()
    )

    selection = options["authenticatorSelection"]
    assert selection["residentKey"] == "required"
    assert selection["userVerification"] == "required"
    assert challenge
