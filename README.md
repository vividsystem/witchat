# witchat
`witchat` (pronounced: witch hat) is a peer-to-peer messaging platform. That means you don't have to rely on a single source-of-truth or a server.
All messages are encrypted using the [`X25519`](https://en.wikipedia.org/wiki/Curve25519) end-to-end encryption algorithm. Additionally all messages are signed using [`ed25519`](https://en.wikipedia.org/wiki/EdDSA).
Synchronisation and message transfer is done via a [DHT](https://en.wikipedia.org/wiki/Distributed_hash_table).
Allthough privacy is guaranteed(as long as you disregard quantum-computers) in the current version, data integrity is not as anyone can delete the stored messages without leaving a trace. This might get improved upon in the future using hashing similarly like a blockchain.
The current approach isn't optimal efficiency-wise as asymetric encryption takes longer to compute than symetric encryption.
Theoretically it would be more efficient to use asymetric encryption only for key-exchange. 

## Requirements
* python
* uv (heavily recommended)
* a friend to chat to (or a second terminal)
## Installation
NOTE: If you truly want to make this truly decentralized and p2p you will have to port-forward to the internet and that's dangerous. If you want to test the potential capabilities try connecting to `vividsystem.hackclub.app:8468`

```bash
# using uv (recommended)
uv tool install witchat 

# or using pip
pip install witchat 
```
to try it out just use `uvx wisort`


## Usage
On launch you will get asked to specify a port, a number of peer ips to connect to and a display name.
After that you can use following commands:
- `.enter`: sends your contact information and your public keys into the network so that people can safely communicate with you
- `.chat [fingerprint]`: select a user to chat to
- `.leave`: unselects the user you were previously chatting to
- `.fingerprint`: prints out your fingerprint
- `.exit`: exits the programm
If you type anything else, it will get sent as a message to your selected recipient.

## Config
(as of now there is no way to configure witchat)
## Acknowledgements
This project would not be possible without [kademlia](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf).
## License
See [LICENSE](./LICENSE)
