import asyncio
import smtplib
from datetime import datetime
from email.message import EmailMessage

from auth_core.entity.recovery import ContactProof


class MailpitEmailProvider:
    def __init__(self, host: str, port: int, sender: str) -> None:
        self._host = host
        self._port = port
        self._sender = sender

    async def send_verification(self, email: str, verification_url: str) -> None:
        message = EmailMessage()
        message["From"] = self._sender
        message["To"] = email
        message["Subject"] = "Verify your Vittavaan account"
        message.set_content(
            "Welcome to Vittavaan. Verify your email using this single-use link:\n\n"
            f"{verification_url}\n\nThis link expires in 15 minutes."
        )
        await asyncio.to_thread(self._send, message)

    async def send_security_code(self, email: str, code: str, context: str = "") -> None:
        message = EmailMessage()
        message["From"] = self._sender
        message["To"] = email
        message["Subject"] = "Your Vittavaan security code"
        detail = f" for {context}" if context else ""
        message.set_content(
            f"Your Vittavaan security code{detail} is: {code}\n\n"
            "This code expires in three minutes. Never share it with anyone."
        )
        await asyncio.to_thread(self._send, message)

    async def send_referral(self, email: str, referral_url: str) -> None:
        message = EmailMessage()
        message["From"] = self._sender
        message["To"] = email
        message["Subject"] = "You have been invited to Vittavaan"
        message.set_content(
            "A friend invited you to create your own private Vittavaan portfolio. "
            "This invitation does not share either person's financial information.\n\n"
            f"Create your profile using this link:\n{referral_url}\n\n"
            "This referral link expires in 30 days."
        )
        await asyncio.to_thread(self._send, message)

    async def send_organization_invitation(
        self, email: str, organization_name: str, invitation_url: str
    ) -> None:
        message = EmailMessage()
        message["From"] = self._sender
        message["To"] = email
        message["Subject"] = f"Invitation to join {organization_name}"
        message.set_content(
            f"You have been invited to join {organization_name} on Vittavaan.\n\n"
            f"Review the invitation using this single-use link:\n{invitation_url}\n\n"
            "This invitation expires in seven days. It does not provide access until "
            "you sign in with the invited email and accept it."
        )
        await asyncio.to_thread(self._send, message)

    async def send_password_reset(self, email: str, reset_url: str) -> None:
        await self._send_security_message(
            email,
            "Reset your Vittavaan password",
            "Use this single-use link to reset your password:\n\n"
            f"{reset_url}\n\nThis link expires in 15 minutes. If you did not request it, "
            "you can ignore this message.",
        )

    async def send_password_changed(self, email: str) -> None:
        await self._send_security_message(
            email,
            "Your Vittavaan password was changed",
            "Your Vittavaan password was changed and existing sessions were ended. "
            "Contact support immediately if this was not you.",
        )

    async def send_support_recovery(self, email: str, recovery_url: str) -> None:
        await self._send_security_message(
            email,
            "Vittavaan support recovery link",
            "Support issued this single-use recovery link after identity verification:\n\n"
            f"{recovery_url}\n\nThis link expires in 15 minutes.",
        )

    async def send_contact_code(
        self, destination: str, code: str, proof: ContactProof
    ) -> None:
        await self.send_security_code(
            destination,
            code,
            f"{proof.value} contact verification",
        )

    async def send_contact_changed(self, destination: str) -> None:
        await self._send_security_message(
            destination,
            "Your Vittavaan contact information changed",
            "A primary contact on your Vittavaan account was changed and existing sessions "
            "were ended. Contact support immediately if this was not you.",
        )

    async def send_mfa_reset_requested(
        self, destination: str, execute_after: datetime
    ) -> None:
        await self._send_security_message(
            destination,
            "A governed MFA reset was requested",
            "Support requested an MFA reset for your account. It cannot execute before "
            f"{execute_after.isoformat()}. Contact support immediately if this was unexpected.",
        )

    async def send_mfa_reset_completed(self, destination: str) -> None:
        await self._send_security_message(
            destination,
            "Your Vittavaan MFA methods were reset",
            "The approved MFA reset completed and existing sessions were ended. You must "
            "sign in and enroll a new security method.",
        )

    async def _send_security_message(self, email: str, subject: str, body: str) -> None:
        message = EmailMessage()
        message["From"] = self._sender
        message["To"] = email
        message["Subject"] = subject
        message.set_content(body)
        await asyncio.to_thread(self._send, message)

    def _send(self, message: EmailMessage) -> None:
        with smtplib.SMTP(self._host, self._port, timeout=5) as client:
            client.send_message(message)


class MailpitSMSProvider:
    def __init__(self, email_provider: MailpitEmailProvider, inbox: str) -> None:
        self._email_provider = email_provider
        self._inbox = inbox

    async def send_verification(self, phone_e164: str, code: str) -> None:
        masked_phone = f"***{phone_e164[-4:]}"
        await self._email_provider.send_verification(
            self._inbox,
            f"Local SMS simulation for {masked_phone}: verification code {code}",
        )

    async def send_security_code(self, phone_e164: str, code: str) -> None:
        masked_phone = f"***{phone_e164[-4:]}"
        await self._email_provider.send_security_code(
            self._inbox, code, f"local SMS simulation to {masked_phone}"
        )


class MailpitRecoveryNotificationProvider:
    def __init__(
        self,
        email_provider: MailpitEmailProvider,
        sms_provider: MailpitSMSProvider,
    ) -> None:
        self._email = email_provider
        self._sms = sms_provider

    async def send_password_reset(self, email: str, reset_url: str) -> None:
        await self._email.send_password_reset(email, reset_url)

    async def send_password_changed(self, email: str) -> None:
        await self._email.send_password_changed(email)

    async def send_support_recovery(self, email: str, recovery_url: str) -> None:
        await self._email.send_support_recovery(email, recovery_url)

    async def send_contact_code(
        self, destination: str, code: str, proof: ContactProof
    ) -> None:
        if destination.startswith("+"):
            await self._sms.send_security_code(destination, code)
        else:
            await self._email.send_contact_code(destination, code, proof)

    async def send_contact_changed(self, destination: str) -> None:
        if destination.startswith("+"):
            await self._email.send_contact_changed(self._sms._inbox)
        else:
            await self._email.send_contact_changed(destination)

    async def send_mfa_reset_requested(
        self, destination: str, execute_after: datetime
    ) -> None:
        if destination.startswith("+"):
            await self._email.send_mfa_reset_requested(self._sms._inbox, execute_after)
        else:
            await self._email.send_mfa_reset_requested(destination, execute_after)

    async def send_mfa_reset_completed(self, destination: str) -> None:
        if destination.startswith("+"):
            await self._email.send_mfa_reset_completed(self._sms._inbox)
        else:
            await self._email.send_mfa_reset_completed(destination)


class MailpitMFANotificationProvider:
    def __init__(
        self,
        email_provider: MailpitEmailProvider,
        sms_provider: MailpitSMSProvider,
    ) -> None:
        self._email_provider = email_provider
        self._sms_provider = sms_provider

    async def send_email_code(self, email: str, code: str) -> None:
        await self._email_provider.send_security_code(email, code)

    async def send_sms_code(self, phone_e164: str, code: str) -> None:
        await self._sms_provider.send_security_code(phone_e164, code)
