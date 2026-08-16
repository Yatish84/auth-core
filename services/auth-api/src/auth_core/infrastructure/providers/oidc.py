import base64
import hmac
import json
from hashlib import sha256

from auth_core.entity.login import OIDCProfile


class LocalOIDCProvider:
    def __init__(self, signing_secret: bytes, frontend_url: str) -> None:
        self._signing_secret = signing_secret
        self._frontend_url = frontend_url.rstrip("/")
        self._issuer = f"{self._frontend_url}/auth/local-oidc"
        self._audience = "auth-core-local"

    def authorization_url(self, provider: str, state: str, nonce: str, code_challenge: str) -> str:
        return (
            f"{self._frontend_url}/auth/local-oidc?provider={provider}&state={state}"
            f"&nonce={nonce}&code_challenge={code_challenge}"
        )

    async def verify_callback(
        self, provider: str, code: str, nonce: str, code_verifier: str
    ) -> OIDCProfile:
        try:
            encoded_payload, supplied_signature = code.split(".", 1)
            payload_bytes = base64.urlsafe_b64decode(encoded_payload + "==")
            expected = hmac.new(
                self._signing_secret,
                payload_bytes + nonce.encode() + code_verifier.encode(),
                sha256,
            ).hexdigest()
            if not hmac.compare_digest(supplied_signature, expected):
                raise ValueError
            payload = json.loads(payload_bytes)
            if (
                payload["provider"] != provider
                or payload["issuer"] != self._issuer
                or payload["audience"] != self._audience
            ):
                raise ValueError
            return OIDCProfile(
                provider=provider,
                subject=str(payload["subject"]),
                email=str(payload["email"]),
                email_verified=payload.get("email_verified") is True,
                given_name=payload.get("given_name"),
                family_name=payload.get("family_name"),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("Invalid local OIDC code") from error

    def issue_test_code(self, profile: OIDCProfile, nonce: str, code_verifier: str) -> str:
        payload = json.dumps(
            {
                "provider": profile.provider,
                "issuer": self._issuer,
                "audience": self._audience,
                "subject": profile.subject,
                "email": profile.email,
                "email_verified": profile.email_verified,
                "given_name": profile.given_name,
                "family_name": profile.family_name,
            },
            separators=(",", ":"),
        ).encode()
        encoded = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        signature = hmac.new(
            self._signing_secret, payload + nonce.encode() + code_verifier.encode(), sha256
        ).hexdigest()
        return f"{encoded}.{signature}"
