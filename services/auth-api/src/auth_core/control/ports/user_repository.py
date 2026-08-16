from typing import Protocol
from uuid import UUID

from auth_core.entity.user import UserRecord, UserState


class UserRepository(Protocol):
    async def create(self, email: str) -> UserRecord: ...

    async def get_by_email(self, email: str) -> UserRecord | None: ...

    async def change_state(
        self, user_id: UUID, expected_version: int, new_state: UserState
    ) -> UserRecord | None: ...
