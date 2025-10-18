from pathlib import Path
import json
import base64
import time
from nacl import signing, public, utils, exceptions
from nacl.encoding import RawEncoder
import hashlib

KEYDIR = Path("~/.p2pchat").expanduser()
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


# TODO: add passhprase support/local encryption of keys
def generate_identity(passphrase: bytes | None = None):
    # ed25519
    sk = signing.SigningKey.generate()
    pk = sk.verify_key

    _save(SK_PATH, sk.encode())
    _save(SK_PATH, pk.encode())

    box_sk = public.PrivateKey.generate()
    box_pk = box_sk.public_key
    _save(BOX_SK_PATH, bytes(box_sk))
    _save(BOX_PK_PATH, bytes(box_pk))

    return sk, pk, box_sk, box_pk


# TODO: add passphrase support/local decryption of keys
def load_identitiy(passphrase: bytes | None = None):
    sk_bytes = _read(SK_PATH)
    pk_bytes = _read(PK_PATH)

    box_sk_bytes = _read(BOX_SK_PATH)
    box_pk_bytes = _read(BOX_PK_PATH)

    sk = signing.SigningKey(sk_bytes)
    pk = signing.SigningKey(pk_bytes)

    box_sk = public.PrivateKey(box_sk_bytes)
    box_pk = public.PrivateKey(box_pk_bytes)

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
    recipient_box_pk: bytes,
    plaintext: bytes,
):
    box = public.Box(sender_box_sk, recipient_box_pk)
    ciphertext = box.encrypt(plaintext)

    header = {
        "sender_vk": base64.b64encode(sender_signing_sk.verify_key).decode(),
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


def unpack_envelope(
    envelope_bytes: bytes,
    expected_sender_vk: bytes,
    sender_box_pk: bytes,
    box_sk: bytes,
):
    box = public.Box(box_sk, sender_box_pk)
    envelope = json.loads(envelope_bytes)
    vk = signing.VerifyKey(expected_sender_vk)

    header_bytes = base64.b64decode(envelope["header"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    signature = base64.b64decode(envelope["signature"])

    valid = True
    try:
        vk.verify(header_bytes + ciphertext, signature)
    except exceptions.BadSignatureError:
        valid = False
        return valid, None, None

    plaintext = box.decrypt(ciphertext)
    header = json.loads(header_bytes)

    return valid, header, plaintext
