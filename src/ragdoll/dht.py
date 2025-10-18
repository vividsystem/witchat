import asyncio
import base64
import json
from kademlia.network import Server
from typing import Optional


class DHTNode:
    def __init__(
        self, port: int = 8468, bootstrap: Optional[tuple[str, int]] = None, loop=None
    ):
        self.port = port
        self.server = Server()
        self.loop = loop or asyncio.get_event_loop()
        self.bootstrap = bootstrap

    async def start(self):
        await self.server.listen(self.port)
        if self.bootstrap:
            try:
                await self.server.bootstrap([self.bootstrap])
            except Exception as e:
                print(f"DHT Bootstrap failed: {e}")

    async def stop(self):
        await self.server.stop()

    async def publish_contact(self, fingerprint: str, contact: dict):
        await self.server.set(f"contact:{fingerprint}", contact)

    async def lookup_contact(self, fingerprint: str) -> Optional[dict]:
        raw = await self.server.get(f"contact:{fingerprint}")
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    async def push_inbox(self, fingerprint: str, envelope_bytes: bytes):
        key = f"inbox:{fingerprint}"
        current = await self.server.get(key)
        try:
            arr = json.loads(current)
        except Exception:
            arr = []
        arr.append(base64.b64encode(envelope_bytes).decode())
        await self.server.set(key, json.dumps(arr))

    async def pull_inbox(self, fingerprint: str) -> list[bytes]:
        key = f"inbox:{fingerprint}"
        raw = await self.server.get(key) or "[]"
        try:
            arr = json.loads(raw)
        except Exception:
            arr = []

        await self.server.set(key, json.dumps([]))
        return [base64.b64decode(x) for x in arr]
