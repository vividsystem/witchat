# import logging
from typing import Optional
import witchat.crypto as crypto
from witchat.dht import DHTNode, Contact
import asyncio
import uvloop

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
    bs = input("Input IPs to connect to (format: IP:PORT, ...):")
    bootstrap: list[tuple[str, int]] = [
        (s[0], int(s[1])) for x in bs.split(",") for s in [x.split(":")] if len(s) > 1
    ]

    print(bootstrap)

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
    while True:
        try:
            items = await node.pull_inbox(node.fingerprint())
            if items:
                for valid, header, msg in items:
                    print(f"{'✓' if valid else 'x'} message: {str(msg)}")
        except Exception as e:
            print(f"an error occured polling the inbox: {e}")
        await asyncio.sleep(2)


async def basic_cli(node: DHTNode):
    contact: Optional[Contact] = None
    while True:
        inp = await asyncio.to_thread(
            input, f"{crypto.get_fingerprint(contact.pk_bytes) if contact else ''}>"
        )
        s = inp.split(" ")
        match s[0]:
            case "enter":
                await node.publish_contact()
                print("Contact published!")
            case "chat":
                if len(s) < 2:
                    print("enter used incorrectly.")
                    print("enter [hexdigest of other party]")
                    continue
                contact = await node.lookup_contact(s[1])
                if contact is None:
                    print("contact not found")
                    continue
                print(f"name: {contact.name}")

            case "send":
                if contact is None:
                    print("you have to have selected a contact to chat.")
                    continue
                await node.push_inbox(
                    contact.fingerprint(), contact.box_pk_bytes, b"Ding dong"
                )

            case "exit":
                print("Exiting")
                break


def entrypoint():
    uvloop.run(main())


if __name__ == "__main__":
    entrypoint()
    entrypoint()
