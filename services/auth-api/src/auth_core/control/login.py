import asyncio
import base64
import hmac
import re
import secrets
from hashlib import sha256
from uuid import UUID, uuid4

from auth_core.control.ports.login import (
    LoginCaptchaProvider,
    LoginPasswordHasher,
    LoginRepository,
    LoginSMSProvider,
    OIDCProvider,
)
from auth_core.entity.login import (
    LoginDecision,
    LoginDecisionType,
    LoginError,
    LoginErrorCode,
    LoginIdentity,
    RiskLevel,
)
from auth_core.entity.registration import DuplicateContactError
from auth_core.entity.user import normalize_email
from auth_core.infrastructure.redis_security import RedisSecurityStore

PASSWORD_ATTEMPT_LIMIT = 5
PASSWORD_ATTEMPT_WINDOW = 60
PHONE_OTP_LIMIT = 3
PHONE_OTP_WINDOW = 60
OTP_MAX_ATTEMPTS = 3
PHONE_PATTERN = re.compile(r"^\+[1-9]\d{7,14}$")
OIDC_PROVIDERS = {"google", "apple", "microsoft"}


class LoginControl:
    def __init__(
        self,
        repository: LoginRepository,
        password_hasher: LoginPasswordHasher,
        captcha_provider: LoginCaptchaProvider,
        sms_provider: LoginSMSProvider,
        oidc_provider: OIDCProvider,
        redis_store: RedisSecurityStore,
        signal_hmac_secret: bytes,
        otp_pepper: bytes,
    ) -> None:
        self._repository = repository
        self._password_hasher = password_hasher
        self._captcha_provider = captcha_provider
        self._sms_provider = sms_provider
        self._oidc_provider = oidc_provider
        self._redis = redis_store
        self._signal_secret = signal_hmac_secret
        self._otp_pepper = otp_pepper
        self._dummy_password_hash = password_hasher.hash(
            "dummy-password-used-only-for-constant-work"
        )

    async def login_password(
        self,
        email: str,
        password: str,
        fingerprint: str,
        ip_address: str | None,
        correlation_id: UUID | None = None,
    ) -> LoginDecision:
        normalized_email = normalize_email(email)
        event_id = correlation_id or uuid4()
        await self._check_login_lock(normalized_email, ip_address)
        identity = await self._repository.password_identity(normalized_email)
        password_hash = (
            identity.password_hash
            if identity and identity.password_hash
            else self._dummy_password_hash
        )
        valid = await asyncio.to_thread(self._password_hasher.verify, password_hash, password)
        if identity is None or not valid or not identity.verified or identity.state != "active":
            await self._record_password_failure(normalized_email, ip_address, identity, event_id)
            raise self._invalid_credentials()
        await self._redis.reset_rate_limit(
            "login_password", normalized_email, PASSWORD_ATTEMPT_WINDOW
        )
        if self._password_hasher.needs_rehash(password_hash):
            updated = await asyncio.to_thread(self._password_hasher.hash, password)
            await self._repository.update_password_hash(identity.user_id, updated)
        decision = await self._primary_decision(
            identity, fingerprint, ip_address, "password", event_id
        )
        return decision

    async def request_phone_otp(
        self,
        phone: str,
        captcha_token: str,
        ip_address: str | None,
    ) -> None:
        normalized_phone = self._normalize_phone(phone)
        await self._verify_captcha(captcha_token, ip_address, "login_phone_request")
        count = await self._redis.increment_rate_limit(
            "login_phone_request", normalized_phone, PHONE_OTP_WINDOW
        )
        if count > PHONE_OTP_LIMIT:
            raise LoginError(
                LoginErrorCode.TEMPORARILY_LOCKED,
                "Too many requests. Please wait and try again.",
                429,
            )
        identity = await self._repository.phone_identity(normalized_phone)
        if identity is None or not identity.verified or identity.state != "active":
            return
        code = f"{secrets.randbelow(1_000_000):06d}"
        await self._redis.store_otp_hash(identity.user_id, "phone_login", self._otp_hash(code))
        try:
            await self._sms_provider.send_verification(normalized_phone, code)
        except Exception as error:
            await self._redis.consume_otp(identity.user_id, "phone_login")
            raise self._provider_unavailable() from error

    async def login_phone(
        self,
        phone: str,
        code: str,
        captcha_token: str,
        fingerprint: str,
        ip_address: str | None,
        correlation_id: UUID | None = None,
    ) -> LoginDecision:
        normalized_phone = self._normalize_phone(phone)
        event_id = correlation_id or uuid4()
        await self._verify_captcha(captcha_token, ip_address, "login_phone_confirm")
        identity = await self._repository.phone_identity(normalized_phone)
        if identity is None or not identity.verified or identity.state != "active":
            raise self._invalid_otp()
        outcome = await self._redis.verify_and_consume_otp(
            identity.user_id, "phone_login", self._otp_hash(code), OTP_MAX_ATTEMPTS
        )
        if outcome != 1:
            await self._repository.audit(
                "PHONE_LOGIN_FAILED", "failure", event_id, identity.user_id, {}
            )
            raise self._invalid_otp()
        return await self._primary_decision(
            identity, fingerprint, ip_address, "phone_otp", event_id
        )

    async def start_oidc(self, provider: str) -> tuple[str, str]:
        normalized_provider = self._provider(provider)
        state = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(24)
        verifier = secrets.token_urlsafe(48)
        challenge = (
            base64.urlsafe_b64encode(sha256(verifier.encode()).digest()).decode().rstrip("=")
        )
        await self._redis.store_oidc_workflow(
            state,
            {"provider": normalized_provider, "nonce": nonce, "code_verifier": verifier},
        )
        return (
            self._oidc_provider.authorization_url(normalized_provider, state, nonce, challenge),
            state,
        )

    async def login_oidc(
        self,
        provider: str,
        state: str,
        code: str,
        fingerprint: str,
        ip_address: str | None,
        correlation_id: UUID | None = None,
    ) -> LoginDecision:
        normalized_provider = self._provider(provider)
        event_id = correlation_id or uuid4()
        workflow = await self._redis.consume_oidc_workflow(state)
        if workflow is None or workflow.get("provider") != normalized_provider:
            raise self._invalid_oidc()
        try:
            profile = await self._oidc_provider.verify_callback(
                normalized_provider,
                code,
                str(workflow["nonce"]),
                str(workflow["code_verifier"]),
            )
        except Exception as error:
            raise self._invalid_oidc() from error
        if not profile.email_verified:
            raise self._invalid_oidc()
        identity = await self._repository.oidc_identity(profile.provider, profile.subject)
        if identity is None:
            collision = await self._repository.active_user_by_email(profile.email)
            if collision is not None:
                return await self._workflow_decision(
                    collision,
                    LoginDecisionType.COLLISION_PROOF_REQUIRED,
                    RiskLevel.HIGH,
                    await self._repository.fallback_methods(collision.user_id),
                    "oidc_collision",
                    event_id,
                    {
                        "oidc_provider": profile.provider,
                        "oidc_subject": profile.subject,
                    },
                )
            try:
                identity = await self._repository.provision_oidc(profile, event_id)
            except DuplicateContactError:
                raise self._invalid_oidc() from None
        if identity.state != "active" or not identity.verified:
            raise self._invalid_oidc()
        return await self._primary_decision(
            identity, fingerprint, ip_address, profile.provider, event_id
        )

    async def fallback_options(self, workflow_token: str) -> tuple[str, ...]:
        payload = await self._redis.get_login_workflow(workflow_token)
        if payload is None:
            raise LoginError(
                LoginErrorCode.WORKFLOW_INVALID,
                "This login workflow is invalid or expired.",
                400,
            )
        methods = payload.get("allowed_methods", [])
        return tuple(str(method) for method in methods)

    async def _primary_decision(
        self,
        identity: LoginIdentity,
        fingerprint: str,
        ip_address: str | None,
        method: str,
        correlation_id: UUID,
    ) -> LoginDecision:
        fingerprint_hash = self._signal_hash(fingerprint)
        signals = await self._repository.device_signals(
            identity.user_id, fingerprint_hash, ip_address
        )
        score = (
            (0 if signals.known else 50)
            + (0 if signals.trusted else 20)
            + (30 if signals.ip_changed else 0)
        )
        risk = RiskLevel.HIGH if score >= 50 else RiskLevel.MEDIUM if score >= 25 else RiskLevel.LOW
        methods = await self._repository.fallback_methods(identity.user_id)
        decision = (
            LoginDecisionType.SESSION_READY
            if risk == RiskLevel.LOW
            else LoginDecisionType.MFA_REQUIRED
        )
        return await self._workflow_decision(
            identity, decision, risk, methods, method, correlation_id
        )

    async def _workflow_decision(
        self,
        identity: LoginIdentity,
        decision: LoginDecisionType,
        risk: RiskLevel,
        methods: tuple[str, ...],
        method: str,
        correlation_id: UUID,
        context: dict[str, str] | None = None,
    ) -> LoginDecision:
        token = secrets.token_urlsafe(32)
        payload = {
            "user_id": str(identity.user_id),
            "decision": decision.value,
            "risk": risk.value,
            "allowed_methods": list(methods),
            "primary_method": method,
        }
        if context:
            payload.update(context)
        await self._redis.store_login_workflow(token, payload)
        await self._repository.audit(
            (
                "OIDC_ACCOUNT_COLLISION_DETECTED"
                if decision == LoginDecisionType.COLLISION_PROOF_REQUIRED
                else "PRIMARY_LOGIN_VERIFIED"
            ),
            "denied" if decision == LoginDecisionType.COLLISION_PROOF_REQUIRED else "success",
            correlation_id,
            identity.user_id,
            {"method": method, "risk": risk.value, "decision": decision.value},
        )
        return LoginDecision(decision, risk, token, methods)

    async def _record_password_failure(
        self,
        email: str,
        ip_address: str | None,
        identity: LoginIdentity | None,
        correlation_id: UUID,
    ) -> None:
        email_count = await self._redis.increment_rate_limit(
            "login_password", email, PASSWORD_ATTEMPT_WINDOW
        )
        ip_count = 0
        if ip_address:
            ip_count = await self._redis.increment_rate_limit(
                "login_password_ip", ip_address, PASSWORD_ATTEMPT_WINDOW
            )
        if email_count >= PASSWORD_ATTEMPT_LIMIT:
            await self._redis.lock_login(email)
        if ip_address and ip_count >= PASSWORD_ATTEMPT_LIMIT:
            await self._redis.lock_login(ip_address)
        await self._repository.audit(
            "PASSWORD_LOGIN_FAILED",
            "failure",
            correlation_id,
            identity.user_id if identity else None,
            {},
        )

    async def _check_login_lock(self, email: str, ip_address: str | None) -> None:
        if await self._redis.login_is_locked(email) or (
            ip_address and await self._redis.login_is_locked(ip_address)
        ):
            raise LoginError(
                LoginErrorCode.TEMPORARILY_LOCKED,
                "Login is temporarily unavailable. Please wait and try again.",
                429,
            )

    async def _verify_captcha(self, token: str, ip_address: str | None, action: str) -> None:
        try:
            valid = await self._captcha_provider.verify(token, ip_address, action)
        except Exception as error:
            raise self._provider_unavailable() from error
        if not valid:
            raise LoginError(
                LoginErrorCode.CAPTCHA_INVALID,
                "The security check could not be verified. Please try again.",
                400,
            )

    def _signal_hash(self, value: str) -> str:
        return hmac.new(self._signal_secret, value.encode(), sha256).hexdigest()

    def _otp_hash(self, value: str) -> str:
        return hmac.new(self._otp_pepper, value.encode(), sha256).hexdigest()

    @staticmethod
    def _normalize_phone(phone: str) -> str:
        normalized = re.sub(r"[\s()-]", "", phone)
        if not PHONE_PATTERN.fullmatch(normalized):
            raise LoginControl._invalid_otp()
        return normalized

    @staticmethod
    def _provider(provider: str) -> str:
        normalized = provider.casefold()
        if normalized not in OIDC_PROVIDERS:
            raise LoginControl._invalid_oidc()
        return normalized

    @staticmethod
    def _invalid_credentials() -> LoginError:
        return LoginError(
            LoginErrorCode.INVALID_CREDENTIALS,
            "The supplied credentials could not be verified.",
            401,
        )

    @staticmethod
    def _invalid_otp() -> LoginError:
        return LoginError(
            LoginErrorCode.OTP_INVALID,
            "The verification code is invalid or expired.",
            400,
        )

    @staticmethod
    def _invalid_oidc() -> LoginError:
        return LoginError(
            LoginErrorCode.OIDC_INVALID,
            "The social login response could not be verified.",
            400,
        )

    @staticmethod
    def _provider_unavailable() -> LoginError:
        return LoginError(
            LoginErrorCode.PROVIDER_UNAVAILABLE,
            "A required login service is temporarily unavailable. Please try again.",
            503,
        )
