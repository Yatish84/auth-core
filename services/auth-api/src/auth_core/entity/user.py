from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID


class UserState(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    LOCKED = "locked"
    SUSPENDED = "suspended"
    DISABLED = "disabled"
    ANONYMIZED = "anonymized"


@dataclass(frozen=True, slots=True)
class UserRecord:
    user_id: UUID
    email: str | None
    state: UserState
    version: int


def normalize_email(email: str) -> str:
    return email.strip().casefold()
