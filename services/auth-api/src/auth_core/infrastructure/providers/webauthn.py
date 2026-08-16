import json
from typing import Any
from uuid import UUID

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from auth_core.entity.mfa import StoredPasskey


class PyWebAuthnProvider:
    def __init__(self, rp_id: str, rp_name: str, expected_origins: list[str]) -> None:
        self._rp_id = rp_id
        self._rp_name = rp_name
        self._origins = expected_origins

    def registration_options(
        self,
        user_id: UUID,
        user_name: str,
        existing_credentials: tuple[bytes, ...],
    ) -> tuple[dict[str, Any], bytes]:
        options = generate_registration_options(
            rp_id=self._rp_id,
            rp_name=self._rp_name,
            user_id=user_id.bytes,
            user_name=user_name,
            user_display_name=user_name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                require_resident_key=True,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=value) for value in existing_credentials
            ],
        )
        return json.loads(options_to_json(options)), options.challenge

    def verify_registration(
        self, credential: dict[str, Any], expected_challenge: bytes
    ) -> tuple[bytes, bytes, int, tuple[str, ...], bool, bool]:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=self._rp_id,
            expected_origin=self._origins,
            require_user_verification=True,
        )
        transports = self._transports(credential)
        return (
            verified.credential_id,
            verified.credential_public_key,
            verified.sign_count,
            transports,
            verified.credential_device_type.value == "multi_device",
            verified.credential_backed_up,
        )

    def authentication_options(
        self, credentials: tuple[StoredPasskey, ...]
    ) -> tuple[dict[str, Any], bytes]:
        descriptors = [
            PublicKeyCredentialDescriptor(
                id=item.credential_id,
                transports=[AuthenticatorTransport(value) for value in item.transports],
            )
            for item in credentials
        ]
        options = generate_authentication_options(
            rp_id=self._rp_id,
            allow_credentials=descriptors or None,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return json.loads(options_to_json(options)), options.challenge

    def credential_id(self, credential: dict[str, Any]) -> bytes:
        raw_id = credential.get("rawId")
        if not isinstance(raw_id, str):
            raise ValueError("Passkey credential ID is missing")
        return base64url_to_bytes(raw_id)

    def verify_authentication(
        self,
        credential: dict[str, Any],
        expected_challenge: bytes,
        stored: StoredPasskey,
    ) -> tuple[int, bool]:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=self._rp_id,
            expected_origin=self._origins,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=True,
        )
        return verified.new_sign_count, verified.credential_backed_up

    @staticmethod
    def _transports(credential: dict[str, Any]) -> tuple[str, ...]:
        response = credential.get("response")
        if not isinstance(response, dict):
            return ()
        values = response.get("transports", [])
        if not isinstance(values, list):
            return ()
        return tuple(
            value
            for value in values
            if isinstance(value, str) and value in {item.value for item in AuthenticatorTransport}
        )
