import hmac


class LocalCaptchaProvider:
    def __init__(self, expected_token: str) -> None:
        self._expected_token = expected_token

    async def verify(self, token: str, remote_ip: str | None, action: str) -> bool:
        del remote_ip, action
        return hmac.compare_digest(token, self._expected_token)

