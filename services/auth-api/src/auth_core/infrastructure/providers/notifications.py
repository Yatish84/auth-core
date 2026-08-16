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
