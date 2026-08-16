import base64
import hmac
import secrets
import string
from hashlib import sha256
from typing import Any
from uuid import UUID, uuid4

from auth_core.control.ports.login import LoginPasswordHasher
from auth_core.control.ports.mfa import (
    MFANotificationProvider,
    MFARepository,
    SecretCipher,
    TOTPProvider,
    WebAuthnProvider,
)
from auth_core.entity.mfa import (
    MFAChallenge,
    MFACompletion,
    MFACompletionType,
    MFAError,
    MFAErrorCode,
    MFAFactor,
    MFAFactorSummary,
    MFAMethod,
    MFAUserProfile,
    PasskeyOptions,
    StoredPasskey,
    TOTPEnrollment,
)
from auth_core.infrastructure.redis_security import RedisSecurityStore

MFA_FAILURE_LIMIT = 3
MFA_FAILURE_WINDOW = 900
OTP_MAX_ATTEMPTS = 3
OTP_REQUEST_LIMIT = 3
OTP_REQUEST_WINDOW = 60
BACKUP_CODE_COUNT = 10
BACKUP_CODE_ALPHABET = string.ascii_uppercase + string.digits


class MFAControl:
    def __init__(
        self,
        repository: MFARepository,
        password_hasher: LoginPasswordHasher,
        secret_cipher: SecretCipher,
        totp_provider: TOTPProvider,
        notification_provider: MFANotificationProvider,
        webauthn_provider: WebAuthnProvider,
        redis_store: RedisSecurityStore,
        otp_pepper: bytes,
        backup_code_pepper: bytes,
    ) -> None:
        self._repository = repository
        self._password_hasher = password_hasher
        self._cipher = secret_cipher
        self._totp = totp_provider
        self._notifications = notification_provider
        self._webauthn = webauthn_provider
        self._redis = redis_store
        self._otp_pepper = otp_pepper
        self._backup_pepper = backup_code_pepper

    async def available_methods(self, workflow_token: str) -> tuple[MFAMethod, ...]:
        workflow, user_id = await self._workflow(workflow_token)
        del workflow
        profile = await self._active_profile(user_id)
        factors = await self._repository.active_factors(user_id)
        methods = self._methods(profile.email is not None, profile.phone_e164 is not None, factors)
        return tuple(sorted(methods, key=lambda item: item.value))

    async def list_factors(self, workflow_token: str) -> tuple[MFAFactorSummary, ...]:
        workflow, user_id = await self._workflow(workflow_token)
        self._require_mfa_assurance(workflow)
        await self._active_profile(user_id)
        factors = await self._repository.active_factors(user_id)
        return tuple(
            MFAFactorSummary(item.mfa_id, item.factor_type, item.label)
            for item in factors
        )

    async def revoke_factor(
        self,
        workflow_token: str,
        factor_id: UUID,
        correlation_id: UUID | None = None,
    ) -> MFACompletion:
        workflow, user_id = await self._workflow(workflow_token)
        self._require_mfa_assurance(workflow)
        factors = await self._repository.active_factors(user_id)
        target = next((item for item in factors if item.mfa_id == factor_id), None)
        if target is None:
            raise self._method_unavailable()
        strong_factors = [
            item for item in factors if item.factor_type in {"totp", "passkey"}
        ]
        if target.factor_type in {"totp", "passkey"} and len(strong_factors) <= 1:
            raise MFAError(
                MFAErrorCode.LAST_FACTOR,
                "Enroll another strong security method before removing this one.",
                409,
            )
        consumed = await self._redis.consume_login_workflow(workflow_token)
        if consumed is None or not await self._repository.revoke_factor(user_id, factor_id):
            raise self._workflow_invalid()
        await self._repository.audit(
            "MFA_FACTOR_REVOKED",
            "success",
            correlation_id or uuid4(),
            user_id,
            {"factor_type": target.factor_type},
        )
        return await self._complete(
            user_id, workflow, "factor_management", correlation_id or uuid4()
        )

    async def issue_challenge(
        self, workflow_token: str, method: MFAMethod
    ) -> MFAChallenge:
        workflow, user_id = await self._workflow(workflow_token)
        profile = await self._active_profile(user_id)
        factors = await self._repository.active_factors(user_id)
        available = self._methods(
            profile.email is not None, profile.phone_e164 is not None, factors
        )
        if method not in available or method == MFAMethod.PASSKEY:
            raise self._method_unavailable()
        consumed = await self._redis.consume_login_workflow(workflow_token)
        if consumed is None:
            raise self._workflow_invalid()
        token = secrets.token_urlsafe(32)
        payload: dict[str, Any] = {
            "purpose": "verify",
            "method": method.value,
            "user_id": str(user_id),
            "workflow": consumed,
        }
        destination_hint: str | None = None
        if method == MFAMethod.TOTP:
            factor = next(item for item in factors if item.factor_type == "totp")
            payload["factor_id"] = str(factor.mfa_id)
        elif method == MFAMethod.EMAIL_OTP and profile.email:
            destination_hint = self._mask_email(profile.email)
            await self._send_otp(token, user_id, method, profile.email, None)
        elif method == MFAMethod.SMS_OTP and profile.phone_e164:
            destination_hint = f"***{profile.phone_e164[-4:]}"
            await self._send_otp(token, user_id, method, None, profile.phone_e164)
        await self._redis.store_mfa_challenge(token, payload)
        return MFAChallenge(token, method, destination_hint)

    async def resend_challenge(self, challenge_token: str) -> MFAChallenge:
        payload = await self._redis.get_mfa_challenge(challenge_token)
        if payload is None or payload.get("purpose") != "verify":
            raise self._challenge_invalid()
        method = MFAMethod(str(payload["method"]))
        if method not in {MFAMethod.EMAIL_OTP, MFAMethod.SMS_OTP}:
            raise self._method_unavailable()
        user_id = UUID(str(payload["user_id"]))
        profile = await self._active_profile(user_id)
        email = profile.email if method == MFAMethod.EMAIL_OTP else None
        phone = profile.phone_e164 if method == MFAMethod.SMS_OTP else None
        if email is None and phone is None:
            raise self._method_unavailable()
        await self._send_otp(challenge_token, user_id, method, email, phone)
        hint = self._mask_email(email) if email else f"***{phone[-4:]}" if phone else None
        return MFAChallenge(challenge_token, method, hint)

    async def verify_challenge(
        self,
        challenge_token: str,
        code: str,
        correlation_id: UUID | None = None,
    ) -> MFACompletion:
        payload = await self._redis.get_mfa_challenge(challenge_token)
        if payload is None or payload.get("purpose") != "verify":
            raise self._challenge_invalid()
        user_id = UUID(str(payload["user_id"]))
        method = MFAMethod(str(payload["method"]))
        valid = False
        if method == MFAMethod.TOTP:
            valid = await self._verify_totp(payload, code)
        elif method in {MFAMethod.EMAIL_OTP, MFAMethod.SMS_OTP}:
            valid = (
                await self._redis.verify_and_consume_otp(
                    user_id,
                    self._otp_purpose(challenge_token),
                    self._otp_hash(code),
                    OTP_MAX_ATTEMPTS,
                )
                == 1
            )
        elif method == MFAMethod.BACKUP_CODE:
            valid = await self._repository.consume_backup_code(
                user_id, self._backup_hash(code)
            )
        if not valid:
            await self._record_failure(challenge_token, user_id, method, payload)
        consumed = await self._redis.consume_mfa_challenge(challenge_token)
        if consumed is None:
            raise self._challenge_invalid()
        return await self._complete(
            user_id, dict(consumed["workflow"]), method.value, correlation_id or uuid4()
        )

    async def setup_totp(self, workflow_token: str, label: str) -> TOTPEnrollment:
        workflow, user_id = await self._workflow(workflow_token)
        profile = await self._active_profile(user_id)
        await self._require_enrollment_assurance(workflow, user_id)
        consumed = await self._redis.consume_login_workflow(workflow_token)
        if consumed is None:
            raise self._workflow_invalid()
        secret = self._totp.generate_secret()
        encrypted = self._cipher.encrypt(secret.encode(), user_id.bytes)
        factor = await self._repository.create_pending_totp(user_id, encrypted, label)
        token = secrets.token_urlsafe(32)
        await self._redis.store_mfa_challenge(
            token,
            {
                "purpose": "enroll_totp",
                "user_id": str(user_id),
                "factor_id": str(factor.mfa_id),
                "workflow": consumed,
            },
        )
        account_name = profile.email or profile.phone_e164 or str(user_id)
        return TOTPEnrollment(
            token,
            self._totp.provisioning_uri(secret, account_name),
            secret,
        )

    async def confirm_totp(
        self,
        enrollment_token: str,
        code: str,
        correlation_id: UUID | None = None,
    ) -> MFACompletion:
        payload = await self._redis.get_mfa_challenge(enrollment_token)
        if payload is None or payload.get("purpose") != "enroll_totp":
            raise self._enrollment_invalid()
        user_id = UUID(str(payload["user_id"]))
        factor_id = UUID(str(payload["factor_id"]))
        factor = await self._repository.factor(user_id, factor_id)
        if factor is None or factor.encrypted_secret is None or factor.status != "pending":
            raise self._enrollment_invalid()
        secret = self._cipher.decrypt(factor.encrypted_secret, user_id.bytes).decode()
        accepted_step = self._totp.verify(secret, code, None)
        if accepted_step is None:
            await self._record_factor_failure(factor_id)
            raise self._code_invalid()
        if not await self._repository.activate_totp(user_id, factor_id, accepted_step):
            raise self._enrollment_invalid()
        consumed = await self._redis.consume_mfa_challenge(enrollment_token)
        if consumed is None:
            raise self._enrollment_invalid()
        backup_codes = await self._ensure_backup_codes(user_id)
        completion = await self._complete(
            user_id, dict(consumed["workflow"]), "totp_enrollment", correlation_id or uuid4()
        )
        return MFACompletion(completion.result, completion.workflow_token, backup_codes)

    async def passkey_registration_options(
        self, workflow_token: str, label: str
    ) -> PasskeyOptions:
        workflow, user_id = await self._workflow(workflow_token)
        profile = await self._active_profile(user_id)
        await self._require_enrollment_assurance(workflow, user_id)
        consumed = await self._redis.consume_login_workflow(workflow_token)
        if consumed is None:
            raise self._workflow_invalid()
        existing = await self._repository.passkeys(user_id)
        account_name = profile.email or profile.phone_e164 or str(user_id)
        options, challenge = self._webauthn.registration_options(
            user_id, account_name, tuple(item.credential_id for item in existing)
        )
        token = secrets.token_urlsafe(32)
        await self._redis.store_webauthn_challenge(
            token,
            {
                "purpose": "register",
                "user_id": str(user_id),
                "label": label,
                "challenge": self._encode(challenge),
                "workflow": consumed,
            },
        )
        return PasskeyOptions(token, options)

    async def confirm_passkey_registration(
        self,
        challenge_token: str,
        credential: dict[str, Any],
        correlation_id: UUID | None = None,
    ) -> MFACompletion:
        payload = await self._redis.consume_webauthn_challenge(challenge_token)
        if payload is None or payload.get("purpose") != "register":
            raise self._passkey_invalid()
        user_id = UUID(str(payload["user_id"]))
        try:
            result = self._webauthn.verify_registration(
                credential, self._decode(str(payload["challenge"]))
            )
            await self._repository.create_passkey(
                user_id,
                str(payload["label"]),
                *result,
            )
        except Exception as error:
            raise self._passkey_invalid() from error
        backup_codes = await self._ensure_backup_codes(user_id)
        completion = await self._complete(
            user_id,
            dict(payload["workflow"]),
            "passkey_enrollment",
            correlation_id or uuid4(),
        )
        return MFACompletion(completion.result, completion.workflow_token, backup_codes)

    async def passkey_authentication_options(
        self, workflow_token: str | None = None
    ) -> PasskeyOptions:
        workflow: dict[str, Any] | None = None
        credentials: tuple[StoredPasskey, ...] = ()
        if workflow_token:
            workflow, user_id = await self._workflow(workflow_token)
            credentials = await self._repository.passkeys(user_id)
            if not credentials:
                raise self._method_unavailable()
            consumed = await self._redis.consume_login_workflow(workflow_token)
            if consumed is None:
                raise self._workflow_invalid()
            workflow = consumed
        options, challenge = self._webauthn.authentication_options(credentials)
        token = secrets.token_urlsafe(32)
        await self._redis.store_webauthn_challenge(
            token,
            {
                "purpose": "authenticate",
                "challenge": self._encode(challenge),
                "workflow": workflow,
            },
        )
        return PasskeyOptions(token, options)

    async def verify_passkey(
        self,
        challenge_token: str,
        credential: dict[str, Any],
        correlation_id: UUID | None = None,
    ) -> MFACompletion:
        payload = await self._redis.consume_webauthn_challenge(challenge_token)
        if payload is None or payload.get("purpose") != "authenticate":
            raise self._passkey_invalid()
        try:
            credential_id = self._webauthn.credential_id(credential)
            stored = await self._repository.passkey(credential_id)
            if stored is None:
                raise ValueError
            workflow = payload.get("workflow")
            if isinstance(workflow, dict) and str(stored.user_id) != workflow.get("user_id"):
                raise ValueError
            new_count, backup_state = self._webauthn.verify_authentication(
                credential,
                self._decode(str(payload["challenge"])),
                stored,
            )
            updated = await self._repository.update_passkey_counter(
                credential_id, stored.sign_count, new_count, backup_state
            )
            if not updated:
                raise ValueError
        except Exception as error:
            raise self._passkey_invalid() from error
        effective_workflow = (
            dict(workflow)
            if isinstance(workflow, dict)
            else {"decision": "passkey_primary", "user_id": str(stored.user_id)}
        )
        return await self._complete(
            stored.user_id, effective_workflow, "passkey", correlation_id or uuid4()
        )

    async def prove_collision_password(
        self,
        workflow_token: str,
        password: str,
        correlation_id: UUID | None = None,
    ) -> MFACompletion:
        workflow, user_id = await self._workflow(workflow_token)
        if workflow.get("decision") != "collision_proof_required":
            raise self._workflow_invalid()
        password_hash = await self._repository.password_hash(user_id)
        if password_hash is None or not self._password_hasher.verify(password_hash, password):
            raise self._code_invalid()
        consumed = await self._redis.consume_login_workflow(workflow_token)
        if consumed is None:
            raise self._workflow_invalid()
        return await self._complete(
            user_id, consumed, "password_reauthentication", correlation_id or uuid4()
        )

    async def _verify_totp(self, payload: dict[str, Any], code: str) -> bool:
        factor_id = UUID(str(payload["factor_id"]))
        if await self._redis.factor_is_locked(factor_id):
            raise self._factor_locked()
        user_id = UUID(str(payload["user_id"]))
        factor = await self._repository.factor(user_id, factor_id)
        if factor is None or factor.encrypted_secret is None or factor.status != "active":
            return False
        secret = self._cipher.decrypt(factor.encrypted_secret, user_id.bytes).decode()
        accepted_step = self._totp.verify(secret, code, factor.last_totp_step)
        if accepted_step is None:
            return False
        return await self._repository.advance_totp_step(
            factor.mfa_id, factor.last_totp_step, accepted_step
        )

    async def _send_otp(
        self,
        challenge_token: str,
        user_id: UUID,
        method: MFAMethod,
        email: str | None,
        phone: str | None,
    ) -> None:
        subject = email or phone
        if subject is None:
            raise self._method_unavailable()
        count = await self._redis.increment_rate_limit(
            f"mfa_{method.value}", subject, OTP_REQUEST_WINDOW
        )
        if count > OTP_REQUEST_LIMIT:
            raise MFAError(
                MFAErrorCode.FACTOR_LOCKED,
                "Too many security-code requests. Please wait and try again.",
                429,
            )
        code = f"{secrets.randbelow(1_000_000):06d}"
        await self._redis.store_otp_hash(
            user_id, self._otp_purpose(challenge_token), self._otp_hash(code)
        )
        try:
            if email:
                await self._notifications.send_email_code(email, code)
            elif phone:
                await self._notifications.send_sms_code(phone, code)
        except Exception as error:
            await self._redis.consume_otp(user_id, self._otp_purpose(challenge_token))
            raise self._provider_unavailable() from error

    async def _record_failure(
        self,
        challenge_token: str,
        user_id: UUID,
        method: MFAMethod,
        payload: dict[str, Any],
    ) -> None:
        if method == MFAMethod.TOTP:
            await self._record_factor_failure(UUID(str(payload["factor_id"])))
        else:
            count = await self._redis.increment_rate_limit(
                "mfa_challenge_failure", str(user_id), MFA_FAILURE_WINDOW
            )
            if count >= MFA_FAILURE_LIMIT:
                await self._redis.consume_mfa_challenge(challenge_token)
        raise self._code_invalid()

    async def _record_factor_failure(self, factor_id: UUID) -> None:
        count = await self._redis.increment_rate_limit(
            "mfa_factor_failure", str(factor_id), MFA_FAILURE_WINDOW
        )
        if count >= MFA_FAILURE_LIMIT:
            await self._redis.lock_factor(factor_id)

    async def _complete(
        self,
        user_id: UUID,
        workflow: dict[str, Any],
        method: str,
        correlation_id: UUID,
    ) -> MFACompletion:
        if workflow.get("decision") == "collision_proof_required":
            provider = workflow.get("oidc_provider")
            subject = workflow.get("oidc_subject")
            if not isinstance(provider, str) or not isinstance(subject, str):
                raise self._workflow_invalid()
            if not await self._repository.link_oidc_identity(user_id, provider, subject):
                raise self._workflow_invalid()
            await self._repository.audit(
                "OIDC_ACCOUNT_COLLISION_RESOLVED",
                "success",
                correlation_id,
                user_id,
                {"method": method, "provider": provider},
            )
            return MFACompletion(MFACompletionType.IDENTITY_LINKED, None)
        token = secrets.token_urlsafe(32)
        await self._redis.store_login_workflow(
            token,
            {
                "user_id": str(user_id),
                "decision": "session_ready",
                "assurance": "mfa",
                "mfa_method": method,
            },
        )
        await self._repository.audit(
            "MFA_VERIFIED",
            "success",
            correlation_id,
            user_id,
            {"method": method},
        )
        return MFACompletion(MFACompletionType.SESSION_READY, token)

    async def _ensure_backup_codes(self, user_id: UUID) -> tuple[str, ...]:
        factors = await self._repository.active_factors(user_id)
        if any(item.factor_type == "backup_codes" for item in factors):
            return ()
        codes = tuple(self._new_backup_code() for _ in range(BACKUP_CODE_COUNT))
        await self._repository.store_backup_codes(
            user_id, tuple(self._backup_hash(code) for code in codes)
        )
        return codes

    async def _workflow(self, token: str) -> tuple[dict[str, Any], UUID]:
        payload = await self._redis.get_login_workflow(token)
        if payload is None:
            raise self._workflow_invalid()
        try:
            user_id = UUID(str(payload["user_id"]))
        except (KeyError, ValueError) as error:
            raise self._workflow_invalid() from error
        return payload, user_id

    async def _active_profile(self, user_id: UUID) -> MFAUserProfile:
        profile = await self._repository.user_profile(user_id)
        if profile is None or profile.state != "active":
            raise self._workflow_invalid()
        return profile

    async def _require_enrollment_assurance(
        self, workflow: dict[str, Any], user_id: UUID
    ) -> None:
        factors = await self._repository.active_factors(user_id)
        has_strong_factor = any(
            item.factor_type in {"totp", "passkey"} for item in factors
        )
        if has_strong_factor:
            self._require_mfa_assurance(workflow)

    @staticmethod
    def _require_mfa_assurance(workflow: dict[str, Any]) -> None:
        if workflow.get("assurance") != "mfa":
            raise MFAControl._workflow_invalid()

    @staticmethod
    def _methods(
        has_email: bool, has_phone: bool, factors: tuple[MFAFactor, ...]
    ) -> set[MFAMethod]:
        methods: set[MFAMethod] = set()
        if has_email:
            methods.add(MFAMethod.EMAIL_OTP)
        if has_phone:
            methods.add(MFAMethod.SMS_OTP)
        mapping = {
            "totp": MFAMethod.TOTP,
            "passkey": MFAMethod.PASSKEY,
            "backup_codes": MFAMethod.BACKUP_CODE,
        }
        methods.update(mapping[item.factor_type] for item in factors if item.factor_type in mapping)
        return methods

    def _otp_hash(self, code: str) -> str:
        return hmac.new(self._otp_pepper, code.encode(), sha256).hexdigest()

    def _backup_hash(self, code: str) -> str:
        normalized = code.replace("-", "").upper()
        return hmac.new(self._backup_pepper, normalized.encode(), sha256).hexdigest()

    @staticmethod
    def _new_backup_code() -> str:
        raw = "".join(secrets.choice(BACKUP_CODE_ALPHABET) for _ in range(16))
        return "-".join(raw[index : index + 4] for index in range(0, 16, 4))

    @staticmethod
    def _otp_purpose(challenge_token: str) -> str:
        return f"mfa:{challenge_token}"

    @staticmethod
    def _mask_email(email: str) -> str:
        local, domain = email.split("@", 1)
        return f"{local[:1]}***@{domain}"

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    @staticmethod
    def _workflow_invalid() -> MFAError:
        return MFAError(
            MFAErrorCode.WORKFLOW_INVALID,
            "This security workflow is invalid or expired.",
            400,
        )

    @staticmethod
    def _challenge_invalid() -> MFAError:
        return MFAError(
            MFAErrorCode.CHALLENGE_INVALID,
            "This security challenge is invalid or expired.",
            400,
        )

    @staticmethod
    def _code_invalid() -> MFAError:
        return MFAError(
            MFAErrorCode.CODE_INVALID,
            "The security code is invalid or expired.",
            400,
        )

    @staticmethod
    def _factor_locked() -> MFAError:
        return MFAError(
            MFAErrorCode.FACTOR_LOCKED,
            "This security method is temporarily locked. Please wait and try again.",
            429,
        )

    @staticmethod
    def _method_unavailable() -> MFAError:
        return MFAError(
            MFAErrorCode.METHOD_UNAVAILABLE,
            "This security method is not available for the current workflow.",
            400,
        )

    @staticmethod
    def _enrollment_invalid() -> MFAError:
        return MFAError(
            MFAErrorCode.ENROLLMENT_INVALID,
            "This enrollment is invalid or expired.",
            400,
        )

    @staticmethod
    def _passkey_invalid() -> MFAError:
        return MFAError(
            MFAErrorCode.PASSKEY_INVALID,
            "The passkey response could not be verified.",
            400,
        )

    @staticmethod
    def _provider_unavailable() -> MFAError:
        return MFAError(
            MFAErrorCode.PROVIDER_UNAVAILABLE,
            "A required security-code service is temporarily unavailable.",
            503,
        )
