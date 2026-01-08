#  Hush  
*(originally forked from Ch1ff3rpunk/OnionTalk (Go)
decided to try it with python instead of Go)*

Secure talk sessions over Tor.  
Because yelling secrets into the internet is like writing on a billboard.



## What is this?

**Hush** is a tiny, opinionated, terminal-based chat tool that lets two humans exchange messages:

- over **Tor**
- with **modern cryptography**
- without trusting **servers, clouds, or vibes**

It is basically:

> *“What if netcat went to therapy, learned crypto, and started caring about boundaries?”*


## Features  
*(a.k.a. reasons this exists, other then "Im bored and procrastinating actual work")*

### End-to-end encryption
- X25519 key exchange  
- HKDF-SHA256 key derivation  
- AES-256-GCM authenticated encryption  

### Directional keys
- Client → Server and Server → Client use different keys  
- Because key reuse is how villains are born  

### Tor-only mindset
- SOCKS5 via Tor  
- No clearnet romance  

### Single-client server
- One connection at a time  
- If someone else calls: **Line Busy.**

### Terminal-native
- No GUI  
- No mouse  
- Just vibes and `std

## How it works (maybe? If I didnt fall asleep during or got off my adderal)

1. Both sides generate ephemeral X25519 key pairs  
2. Public keys are exchanged  
3. A shared secret is derived  
4. Two independent AES-256 keys are created:
   - `c2s` (client → server)
   - `s2c` (server → client)
5. Messages are:
   - framed (length-prefixed)
   - encrypted with AES-GCM
   - authenticated
   - sent

Nobody learns anything they shouldn’t.

If this sounds boring: **good.**  
Boring crypto is **working crypto**.


## Usage

### Server (listener mode)

```bash
python oniontalk.py

Server listens on:

127.0.0.1:8001


(Usually exposed via a Tor hidden service.)

### Client (send mode)
python oniontalk.py -s youronionaddress.onion


Only port 8001 is allowed.
Yes, this is intentional.
No, you cannot negotiate with the program.

| Command  | What it does              |
| -------- | ------------------------- |
| `.MULTI` | Start multi-line message  |
| `.END`   | Finish multi-line message |
| `.QUIT`  | Politely nuke the session |


Example :

.MULTI
This is a long message.
It spans multiple lines.
Like my thoughts at 3am.
.END
```

## Threat model
(aka “what this protects against”)

Protects against:

✔ Passive network observers

✔ Malicious relays

✔ Accidental plaintext leaks

✔ Cryptographic regret

Does not protect against

❌ Someone reading your screen or you reading aloud

❌ Compromised endpoints

❌ Bad passwords (there are none)

❌ Human error (good luck with that)

### Security notes

Nonces are random and never reused

Frames are size-limited (1 MiB)

Keys are ephemeral

Keys are direction-separated

Python cannot guarantee secure memory zeroization.
(If this scares you: use the Go version.)

In other words:
This is not crypto cosplay.

### Why not just use X?

Email: archived forever

Messengers: metadata galore

Custom crypto: no

Hush: small, auditable, boring

Requirements
> pip install cryptography pysocks


Also required:

A functioning Tor SOCKS5 proxy on 127.0.0.1:9050

A terminal

Something to say and someone to talk to

### Disclaimer

This project will not:

make you anonymous by magic

fix your threat model

save you from yourself

But it will encrypt your messages correctly.

### License

Do whatever you want.
Im not your Boss, nor your mom.

Just don’t remove the crypto and call it secure.



## Legal & ethical use

This project is intended only for lawful and ethical purposes, including but not limited to:

-private communication

-learning about cryptography

-research and educational use

-protecting personal privacy

### You must not use this software to:

-facilitate criminal activity

-evade law enforcement for illegal purposes

-distribute illegal content

-harass, threaten, or harm others

I dont endorse and are not responsible for any illegal or malicious use of this software.

Use responsibly.
Encryption is a tool — not a justification. 

