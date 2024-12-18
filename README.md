# ratcheted-exchange

<p align="center">
  <img src="https://github.com/Kseen715/imgs/blob/main/sakura_kharune.png?raw=true" height="100"/>
</p>

## Description

> [!WARNING]
> This implementation may not be secure. Use it only for educational purposes.

This is a simple implementation of client-server communication using the ratcheted exchange protocol. Both the client and the server are implemented in pure Rust. You can find my Double Rachet algorithm implementation in [this repo](https://github.com/Kseen715/double-ratchet).

The server simply sends a message from one client to another. The server does not know the content of the message. The server only knows the ID of the sender and the receiver.

Clients are using the ratcheted exchange protocol to encrypt and decrypt messages.

Checkout this papers/sites to learn more about the ratcheted exchange protocol:

- [my papers about the project you're seeing now](papers/) (RUS)
- [Signal Double Ratchet Protocol](https://signal.org/docs/specifications/doubleratchet/) (ENG)
- [The Double Ratchet: Security Notions, Proofs, and
Modularization for the Signal Protocol](https://eprint.iacr.org/2018/1037.pdf) (ENG)
- [Double Ratchet Algorithm - Wikipedia](https://en.wikipedia.org/wiki/Double_Ratchet_Algorithm) (ENG)
- [Advanced cryptographic ratcheting](https://signal.org/blog/advanced-ratcheting/) (ENG)

## Usage

To run the server, use the following command in [`server`](server/) directory:

```bash
cargo run
```

> [!NOTE]
> The server must be running before the client.

To run the client, use the following command in [`client`](client/) directory:

```bash
cargo run
```

> [!NOTE]
> Second client must be launched ONLY after the first client was initialized with the server.
