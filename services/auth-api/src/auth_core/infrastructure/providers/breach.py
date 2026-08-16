from hashlib import sha1

import httpx


class HibpBreachPasswordProvider:
    def __init__(self, user_agent: str, timeout_seconds: float = 5.0) -> None:
        self._user_agent = user_agent
        self._timeout_seconds = timeout_seconds

    async def breach_count(self, password: str) -> int:
        digest = sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
            response = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true", "User-Agent": self._user_agent},
            )
            response.raise_for_status()
        for line in response.text.splitlines():
            candidate, count = line.split(":", 1)
            if candidate == suffix:
                return int(count)
        return 0

