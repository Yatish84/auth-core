import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class LocalAESGCMSecretCipher:
    VERSION = b"\x01"

    def __init__(self, encoded_key: str) -> None:
        key = base64.b64decode(encoded_key, validate=True)
        if len(key) != 32:
            raise ValueError("Local data encryption key must contain exactly 32 bytes")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        nonce = os.urandom(12)
        return self.VERSION + nonce + self._cipher.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
        if len(ciphertext) < 30 or ciphertext[:1] != self.VERSION:
            raise ValueError("Unsupported encrypted secret")
        nonce = ciphertext[1:13]
        try:
            return self._cipher.decrypt(nonce, ciphertext[13:], associated_data)
        except InvalidTag as error:
            raise ValueError("Encrypted secret could not be authenticated") from error
