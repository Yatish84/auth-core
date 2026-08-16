from auth_core.entity.registration import RegistrationError, RegistrationErrorCode


def enforce_password_policy(password: str) -> None:
    if len(password) < 12 or len(password) > 128:
        raise RegistrationError(
            RegistrationErrorCode.PASSWORD_POLICY,
            "Use a password between 12 and 128 characters.",
            400,
        )

