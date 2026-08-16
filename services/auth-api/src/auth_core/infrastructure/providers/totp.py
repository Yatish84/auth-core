from datetime import UTC, datetime

import pyotp


class PyOTPProvider:
    def __init__(self, issuer: str) -> None:
        self._issuer = issuer

    def generate_secret(self) -> str:
        return pyotp.random_base32()

    def provisioning_uri(self, secret: str, account_name: str) -> str:
        return pyotp.TOTP(secret).provisioning_uri(
            name=account_name, issuer_name=self._issuer
        )

    def verify(self, secret: str, code: str, last_step: int | None) -> int | None:
        totp = pyotp.TOTP(secret)
        now = datetime.now(UTC)
        current_step = totp.timecode(now)
        for offset in (-1, 0, 1):
            candidate_step = current_step + offset
            if last_step is not None and candidate_step <= last_step:
                continue
            if pyotp.utils.strings_equal(totp.at(now, counter_offset=offset), code):
                return candidate_step
        return None
