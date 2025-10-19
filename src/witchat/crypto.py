from pathlib import Path
import json
import base64
import time
from nacl import signing, public, exceptions
from typing import Optional
import hashlib

KEYDIR = Path("~/.ragdoll").expanduser()
SK_PATH = KEYDIR / "ed25519_sk"  # signing secret key
PK_PATH = KEYDIR / "ed25519_pk"  # signing public key
BOX_SK_PATH = KEYDIR / "box_sk"  # encryption secret key
BOX_PK_PATH = KEYDIR / "box_pk"  # encryption public key

KEYDIR.mkdir(exist_ok=True)


def _save(p: Path, b: bytes):
    with open(p, "wb") as f:
        f.write(b)


def _read(p: Path):
    with open(p, "rb") as f:
        return f.read()


def identity_exists() -> bool:
    return (
        SK_PATH.exists()
        and PK_PATH.exists()
        and BOX_SK_PATH.exists()
        and BOX_PK_PATH.exists()
    )


# TODO: add passhprase support/local encryption of keys
def generate_identity(
    passphrase: bytes | None = None,
) -> (signing.SigningKey, signing.VerifyKey, public.PrivateKey, public.PublicKey):
    # ed25519
    sk = signing.SigningKey.generate()
    pk = sk.verify_key

    box_sk = public.PrivateKey.generate()
    box_pk = box_sk.public_key

    return sk, pk, box_sk, box_pk


def save_identity(
    sk: signing.SigningKey,
    pk: signing.VerifyKey,
    box_sk: public.PrivateKey,
    box_pk: public.PublicKey,
    passphrase: bytes | None = None,
):
    _save(SK_PATH, bytes(sk))
    _save(SK_PATH, bytes(pk))
    _save(BOX_SK_PATH, bytes(box_sk))
    _save(BOX_PK_PATH, bytes(box_pk))


# TODO: add passphrase support/local decryption of keys
def load_identitiy(
    passphrase: bytes | None = None,
) -> (signing.SigningKey, signing.VerifyKey, public.PrivateKey, public.PublicKey):
    sk_bytes = _read(SK_PATH)
    pk_bytes = _read(PK_PATH)

    box_sk_bytes = _read(BOX_SK_PATH)
    box_pk_bytes = _read(BOX_PK_PATH)

    sk = signing.SigningKey(sk_bytes)
    pk = signing.VerifyKey(pk_bytes)

    box_sk = public.PrivateKey(box_sk_bytes)
    box_pk = public.PublicKey(box_pk_bytes)

    return sk, pk, box_sk, box_pk


# human readable fingerprint
def get_fingerprint(pk_bytes: bytes):
    return hashlib.sha256(pk_bytes).hexdigest()[:16]


def sign_message(sk: signing.SigningKey, msg: bytes):
    signed = sk.sign(msg)
    return (signed.message, signed.signature)


def verify_signature(vk: signing.VerifyKey, msg: bytes, signature: bytes):
    vk.verify(msg, signature)


# make the encrypted message
# TODO: ephermal encryption using nacl.public.SealedBox?
def pack_envelope(
    sender_signing_sk: signing.SigningKey,
    sender_box_sk: public.PrivateKey,
    recipient_box_pk: public.PublicKey,
    plaintext: bytes,
):
    box = public.Box(sender_box_sk, recipient_box_pk)
    ciphertext = box.encrypt(plaintext)

    header = {
        "sender_pk": base64.b64encode(bytes(sender_signing_sk.verify_key)).decode(),
        "sender_box_pk": base64.b64encode(bytes(sender_box_sk.public_key)).decode(),
        "ts": int(time.time()),
    }

    header_bytes = json.dumps(header).encode()
    (_, signature) = sign_message(sender_signing_sk, header_bytes + ciphertext)

    envelope = {
        "header": base64.b64encode(header_bytes).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "signature": base64.b64encode(signature).decode(),
    }

    return json.dumps(envelope).encode()


# TODO: secure time to not be alterable without perms
class Header:
    def __init__(
        self,
        sender_pk: signing.VerifyKey,
        sender_box_pk: public.PublicKey,
        ts: int = time.time(),
    ):
        self.sender_pk = sender_pk
        self.sender_box_pk = sender_box_pk
        self.ts = ts

    @classmethod
    def from_bytes(
        cls,
        sender_pk_bytes: bytes,
        sender_box_pk_bytes: bytes,
        ts: int = time.time(),
    ):
        sender_pk = signing.VerifyKey(sender_pk_bytes)
        sender_box_pk = public.PublicKey(sender_box_pk_bytes)

        return cls(sender_pk, sender_box_pk, ts)

    @classmethod
    def unpack(cls, header_bytes: bytes):
        header = json.loads(header_bytes)

        sender_pk_bytes = base64.b64decode(header["sender_pk"])
        sender_box_pk_bytes = base64.b64decode(header["sender_box_pk"])

        return cls.from_bytes(
            sender_pk_bytes, sender_box_pk_bytes, time.gmtime(header["ts"])
        )

    def pack(self):
        header_bytes = json.dumps(
            {
                "sender_pk": base64.b64encode(bytes(self.sender_pk)).decode(),
                "sender_box_pk": base64.b64encode(bytes(self.sender_box_pk)).decode(),
                "ts": int(time.time()),
            }
        ).encode()
        return header_bytes


class Envelope:
    def __init__(
        self,
        signature_valid: bool = True,
        plaintext: Optional[bytes] = None,
        signature: Optional[bytes] = None,
        header: Optional[Header] = None,
    ):
        self.header = header
        self.plaintext = plaintext
        self.signature = signature
        self.signature_valid = signature_valid

    def pack(
        self,
        sk: signing.SigningKey,
        box_sk: public.PrivateKey,
        recipient_box_pk: public.PublicKey,
    ) -> Optional[bytes]:
        if self.header is None:
            self.header = Header(sk.verify_key, box_sk.public_key)

        box = public.Box(box_sk, recipient_box_pk)
        ciphertext = box.encrypt(self.plaintext)

        header_bytes = self.header.pack()
        (_, signature) = sign_message(sk, header_bytes + ciphertext)

        envelope = {
            "header": base64.b64encode(header_bytes).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "signature": base64.b64encode(signature).decode(),
        }

        return json.dumps(envelope).encode()

    @classmethod
    def unpack(cls, envelope_bytes: bytes, box_sk: public.PrivateKey):
        envelope = json.loads(envelope_bytes)
        header_bytes = base64.b64decode(envelope["header"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
        signature = base64.b64decode(envelope["signature"])

        try:
            header = Header.unpack(header_bytes)
        except Exception:
            return cls(False, None, signature, None)

        box = public.Box(box_sk, header.sender_box_pk)

        try:
            # will raise exception
            header.sender_pk.verify(header_bytes + ciphertext, signature)
        except exceptions.BadSignatureError:
            return cls(False, None, signature, header)

        try:
            plaintext = box.decrypt(ciphertext)
        except exceptions.CryptoError:
            return cls(False, None, signature, header)

        return cls(True, plaintext, signature, header)
