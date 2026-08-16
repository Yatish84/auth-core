from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_core.entity.user import UserRecord, UserState, normalize_email
from auth_core.infrastructure.persistence.models import User


class SqlAlchemyUserRepository:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def create(self, email: str) -> UserRecord:
        async with self._sessions.begin() as session:
            model = User(email=normalize_email(email))
            session.add(model)
            await session.flush()
            return self._to_record(model)

    async def get_by_email(self, email: str) -> UserRecord | None:
        async with self._sessions() as session:
            result = await session.scalar(
                select(User).where(
                    User.email == normalize_email(email), User.anonymized_at.is_(None)
                )
            )
            return self._to_record(result) if result is not None else None

    async def change_state(
        self, user_id: UUID, expected_version: int, new_state: UserState
    ) -> UserRecord | None:
        async with self._sessions.begin() as session:
            result = await session.scalar(
                update(User)
                .where(User.user_id == user_id, User.version == expected_version)
                .values(state=new_state.value, version=User.version + 1)
                .returning(User)
            )
            return self._to_record(result) if result is not None else None

    @staticmethod
    def _to_record(model: User) -> UserRecord:
        return UserRecord(
            user_id=model.user_id,
            email=model.email,
            state=UserState(model.state),
            version=model.version,
        )
