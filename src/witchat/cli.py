# import logging
from typing import Optional
import witchat.crypto as crypto
from witchat.dht import DHTNode, Contact
import socket
import asyncio
import uvloop
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


# handler = logging.StreamHandler()
# formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# handler.setFormatter(formatter)
# log = logging.getLogger("kademlia")
# log.addHandler(handler)
# log.setLevel(logging.DEBUG)


async def main():
    print("Welcome to WitchAt!")
    port = int(input("Your host port (default: 8468):") or 8468)
    bs = input("Nodes to connect to (format: IP:PORT, ...):")
    bootstrap: list[tuple[str, int]] = [
        (socket.gethostbyname(s[0]), int(s[1]))
        for x in bs.strip().replace(" ", "").split(",")
        for s in [x.split(":")]
        if len(s) > 1
    ]

    ident_exists = crypto.identity_exists()
    use_ident = False
    if ident_exists:
        print("Found identity")
        sk, pk, box_sk, box_pk = crypto.load_identity()
        use = input("Use identity(y/n):")
        if use == "y":
            use_ident = True
    elif not ident_exists or not use_ident:
        sk, pk, box_sk, box_pk = crypto.generate_identity()

    print(f"Your fingerprint: {crypto.get_fingerprint(bytes(pk))}")
    name = input(f"Name: ")
    node = DHTNode(sk, pk, box_sk, box_pk, name, port, bootstrap)
    await asyncio.gather(
        node.run_async(),
        inbox_poller(node),
        basic_cli(node),
    )
    print("Node running!")


async def inbox_poller(node: DHTNode):
    await node.ready.wait()
    while True:
        try:
            envelopes = await node.pull_inbox(node.fingerprint())
            if envelopes:
                for envelope in envelopes:
                    sender_fingerprint = crypto.get_fingerprint(
                        bytes(envelope.header.sender_pk)
                    )
                    sender = await node.lookup_contact(sender_fingerprint)
                    if sender is None:
                        print(
                            f"{'✓' if envelope.signature_valid else 'x'}({
                                sender_fingerprint
                            })ANON: {envelope.plaintext.decode('utf-8')}"
                        )
                        continue
                    print(
                        f"{'✓' if envelope.signature_valid else 'x'} {sender.name}({
                            sender_fingerprint
                        }): {envelope.plaintext.decode('utf-8')}"
                    )
        except Exception as e:
            print(f"an error occured polling the inbox: {e}")
        await asyncio.sleep(2)


async def basic_cli(node: DHTNode):
    session = PromptSession()
    contact: Optional[Contact] = None
    while True:
        with patch_stdout():
            inp = await session.prompt_async(
                f"{crypto.get_fingerprint(contact.pk_bytes) if contact else ''}> ",
            )
        s = inp.split(" ")
        if len(inp) == 0:
            continue
        match s[0]:
            case ".enter":
                await node.publish_contact()
                print("Contact published!")
            case ".chat":
                if len(s) < 2:
                    print("chat used incorrectly.")
                    print("chat [hexdigest of other party]")
                    continue
                contact = await node.lookup_contact(s[1])
                if contact is None:
                    print("contact not found")
                    continue
                print(f"name: {contact.name}")
            case ".leave":
                contact = None

            case ".fingerprint":
                print(f"Your fingerprint: {node.fingerprint()}")
            case ".exit":
                print("Exiting")
                node.stop()
                break

            case _:
                if contact is None:
                    print("you have to have selected a contact to chat.")
                    print("use `.chat [fingerprint]`")
                    continue

                msg = " ".join(s)
                await node.push_inbox(
                    contact.fingerprint(), contact.box_pk_bytes, bytes(msg, "utf-8")
                )


def entrypoint():
    uvloop.run(main())


if __name__ == "__main__":
    entrypoint()
