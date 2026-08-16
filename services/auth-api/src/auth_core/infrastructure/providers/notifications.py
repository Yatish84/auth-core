import asyncio
import smtplib
from email.message import EmailMessage


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
