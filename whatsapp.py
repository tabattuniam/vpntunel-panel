"""WuzAPI client."""
from __future__ import annotations
import logging
import requests

log = logging.getLogger(__name__)


class WuzAPIClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _normalize(self, number: str) -> str:
        n = number.strip().replace("-", "").replace(" ", "")
        if n.startswith("0"):
            n = "62" + n[1:]
        elif n.startswith("+"):
            n = n[1:]
        return n

    def send(self, number: str, message: str) -> bool:
        phone = self._normalize(number)
        try:
            r = requests.post(
                f"{self.base_url}/chat/send/text",
                json={"Phone": f"{phone}@s.whatsapp.net", "Body": message},
                headers={"token": self.token, "Content-Type": "application/json"},
                timeout=10,
            )
            return r.status_code == 200
        except Exception as e:
            log.error("WA gagal ke %s: %s", number, e)
            return False
