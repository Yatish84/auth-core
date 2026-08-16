from auth_core.config import get_settings
from auth_core.infrastructure.security.tokens import LocalRS256TokenProvider

settings = get_settings()
token_provider = LocalRS256TokenProvider(settings.jwt_issuer, settings.jwt_audience)
