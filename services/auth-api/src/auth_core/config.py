from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "local"
    app_name: str = "auth-core"
    database_url: str = (
        "postgresql+asyncpg://auth_core:local-development-only@localhost:5432/auth_core"
    )
    redis_url: str = "redis://localhost:6379/0"
    redis_key_hmac_secret: str = "local-development-key-change-me"
    otp_hmac_secret: str = "local-otp-key-change-me"
    login_signal_hmac_secret: str = "local-login-signal-key-change-me"
    local_oidc_signing_secret: str = "local-oidc-signing-key-change-me"
    local_oidc_frontend_url: str = "http://localhost:3000"
    local_data_encryption_key: str = (
        "bG9jYWwtbWZhLWtleS1jaGFuZ2UtYmVmb3JlLXByb2Q="
    )
    backup_code_hmac_secret: str = "local-backup-code-key-change-me"
    totp_issuer: str = "Vittavaan"
    webauthn_rp_id: str = "localhost"
    webauthn_rp_name: str = "Vittavaan"
    webauthn_allowed_origins: str = "http://localhost:3000"
    cors_allowed_origins: str = "http://localhost:3000"
    local_captcha_token: str = "local-development-pass"
    verification_base_url: str = "http://localhost:3000/verify-email"
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    email_sender: str = "no-reply@local.vittavaan.test"
    local_sms_inbox: str = "sms@local.vittavaan.test"
    hibp_user_agent: str = "Vittavaan-auth-core/0.1 security@vittavaan.test"
    registration_provider_mode: str = "local"
    login_provider_mode: str = "local"
    secret_encryption_mode: str = "local"

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

    @property
    def allowed_webauthn_origins(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.webauthn_allowed_origins.split(",")
            if origin.strip()
        ]

    @model_validator(mode="after")
    def reject_local_registration_providers_in_production(self) -> "Settings":
        if self.app_env == "production" and self.registration_provider_mode == "local":
            raise ValueError("Production cannot use local registration provider adapters")
        if self.app_env == "production" and self.login_provider_mode == "local":
            raise ValueError("Production cannot use local login provider adapters")
        if self.app_env == "production" and self.secret_encryption_mode == "local":
            raise ValueError("Production cannot use the local secret encryption adapter")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
