import base64
import asyncio
import json
from kademlia.network import Server
from typing import Optional
from nacl import signing, public
import witchat.crypto as crypto


class Contact:
    def __init__(self, name: str, pk_bytes: bytes, box_pk_bytes: bytes, port: int):
        self.name = name
        self.pk_bytes = pk_bytes
        self.box_pk_bytes = box_pk_bytes
        self.port = port

    @classmethod
    def from_json(cls, json_str: str):
        data = json.loads(json_str)

        pk_bytes = base64.b64decode(data["pk"])
        box_pk_bytes = base64.b64decode(data["box_pk"])

        return cls(
            name=data["name"],
            pk_bytes=pk_bytes,
            box_pk_bytes=box_pk_bytes,
            port=data["port"],
        )

    def blob(self):
        contact_dict = {
            "name": self.name,
            "pk": base64.b64encode(self.pk_bytes).decode(),
            "box_pk": base64.b64encode(self.box_pk_bytes).decode(),
            "port": self.port,
        }

        return json.dumps(contact_dict)

    def fingerprint(self):
        return crypto.get_fingerprint(self.pk_bytes)


class DHTNode:
    def __init__(
        self,
        sk: signing.SigningKey,
        pk: signing.VerifyKey,
        box_sk: public.PrivateKey,
        box_pk: public.PublicKey,
        name: str,
        port: int = 8468,
        bootstrap: Optional[list[tuple[str, int]]] = None,
    ):
        self.port = port
        self.server = Server()
        self.bootstrap = bootstrap
        self.name = name
        self.sk = sk
        self.pk = pk
        self.box_sk = box_sk
        self.box_pk = box_pk
        self.loop = None
        self._stop_event = asyncio.Event()
        self.ready = asyncio.Event()

    def run(self):
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self.server.listen(self.port))
            if self.bootstrap:
                self.loop.run_until_complete(self.server.bootstrap(self.bootstrap))
            self.loop.run_forever()
        except Exception as e:
            print(f"Running DHT an error occured: {e}")

    async def run_async(self):
        await self.server.listen(self.port)

        if self.bootstrap:
            await self.server.bootstrap(self.bootstrap)

        self.ready.set()
        await self._stop_event.wait()

    def stop(self):
        self._stop_event.set()

    # think of a way to ensure/notify people that key pairs have changed -> other encryption key with same verifykey
    async def publish_contact(self):
        contact = Contact(self.name, bytes(self.pk), bytes(self.box_pk), self.port)
        await self.server.set(f"contact:{self.fingerprint()}", contact.blob())

    async def lookup_contact(self, fingerprint: str) -> Optional[Contact]:
        raw = await self.server.get(f"contact:{fingerprint}")
        if raw is None:
            return None
        try:
            return Contact.from_json(raw)
        except Exception as e:
            print(f"Error trying to get contact: {e}")
            return None

    # TODO: think of a way to protect this inbox so it doesn't get modified/items deleted by other parties
    async def push_inbox(
        self, fingerprint: str, recipient_box_pk: bytes, message: bytes
    ):
        key = f"inbox:{fingerprint}"
        current = await self.server.get(key)
        try:
            arr = json.loads(current)
        except Exception:
            arr = []

        recipient_box_pk = public.PublicKey(recipient_box_pk)

        envelope_bytes = crypto.Envelope(plaintext=message).pack(
            self.sk, self.box_sk, recipient_box_pk
        )

        arr.append(base64.b64encode(envelope_bytes).decode())
        await self.server.set(key, json.dumps(arr))

    async def pull_inbox(self, fingerprint: str) -> list[crypto.Envelope]:
        key = f"inbox:{fingerprint}"
        raw = await self.server.get(key) or "[]".encode()
        try:
            arr = json.loads(raw)
        except Exception:
            arr = []
        envelopes: list[crypto.Envelope] = [
            (crypto.Envelope.unpack(base64.b64decode(x), self.box_sk)) for x in arr
        ]
        # TODO: figure out race condition
        await self.server.set(key, json.dumps([]))
        return envelopes

    def fingerprint(self):
        return crypto.get_fingerprint(bytes(self.pk))
