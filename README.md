# ECDH-MITM Demo

**A Three-Act Live Demonstration of Elliptic-Curve Key Exchange, Man-in-the-Middle Attack, and Certificate-Based Defence**

---

## Table of Contents

1. [Overview](#overview)
2. [Learning Objectives](#learning-objectives)
3. [System Requirements](#system-requirements)
4. [Project Structure](#project-structure)
5. [Building the Project](#building-the-project)
6. [Running the Demo](#running-the-demo)
7. [The Three Acts Explained](#the-three-acts-explained)
8. [Architecture and Implementation](#architecture-and-implementation)
9. [Cryptographic Algorithms](#cryptographic-algorithms)
10. [Network Protocol](#network-protocol)
11. [Security Analysis](#security-analysis)
12. [Troubleshooting](#troubleshooting)
13. [References](#references)

---

## Overview

This project is a fully functional, terminal-based cryptography demonstration that walks through three progressive scenarios involving two honest parties — **Alice** (sender) and **Bob** (receiver) — and one adversary — **Oscar** (man-in-the-middle attacker).

```
Act 1 (Honest):    Alice -------> Bob          Direct ECDH, no attacker
Act 2 (Attack):    Alice -> Oscar -> Bob       Oscar intercepts both handshakes
Act 3 (Defence):   Alice -> Oscar -> Bob       Oscar's forged cert rejected; attack fails
```

Each act runs as three separate executables communicating over localhost TCP, making the network traffic inspectable in tools such as Wireshark in real time.

The cryptographic core — P-256 elliptic curve arithmetic — is implemented **from scratch** without any EC library. OpenSSL is used only for ECDSA signing and AES-GCM encryption, which require constant-time implementations to be secure in practice.

---

## Learning Objectives

Upon completing this demonstration, a viewer will understand:

- How the **Elliptic-Curve Diffie-Hellman (ECDH)** protocol establishes a shared secret between two parties who have never communicated before
- Why unauthenticated ECDH is **vulnerable to a Man-in-the-Middle (MITM) attack** and precisely how the attack is carried out
- How **digital certificates** (ECDSA-signed public keys) eliminate the MITM vulnerability by binding a public key to a verified identity
- How **Trust On First Use (TOFU)** and **key pinning** provide a practical intermediate defence in the absence of a formal PKI
- How **AES-256-GCM** provides both confidentiality and message integrity — and why a failed GCM authentication tag signals tampering

---

## System Requirements

| Component       | Minimum Version | Notes                                    |
|-----------------|-----------------|------------------------------------------|
| C++ Compiler    | C++17           | GCC 7+, Clang 5+, MSVC 2019+            |
| CMake           | 3.15            |                                          |
| OpenSSL         | 1.1.1           | 3.x recommended                         |
| Operating System| Any             | Linux, macOS, Windows (MSYS2/MinGW64)   |
| tmux (optional) | any             | Required only for `tmux_demo.sh`         |

### Installation

**Linux (Ubuntu / Debian)**
```bash
sudo apt update && sudo apt install -y build-essential cmake libssl-dev
```

**macOS (Homebrew)**
```bash
brew install cmake openssl
export PKG_CONFIG_PATH="$(brew --prefix openssl)/lib/pkgconfig"
```

**Windows (MSYS2 / MinGW64)**
```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl
```

---

## Project Structure

```
ECDH_MITM/
|
+-- CMakeLists.txt              Build configuration
+-- README.md                   This document
+-- data/                       Runtime-generated files (CA keys, TOFU store)
|
+-- scripts/
|   +-- demo.sh                 Automated sequential demo (all 3 acts)
|   +-- tmux_demo.sh            Interactive split-pane demo using tmux
|
+-- src/
    +-- alice.cpp               Alice executable entry point
    +-- bob.cpp                 Bob executable entry point
    +-- oscar.cpp               Oscar executable entry point
    |
    +-- crypto/
    |   +-- ecc_math.cpp/h      P-256 field and group arithmetic (from scratch)
    |   +-- ecdh_core.cpp/h     ECDH key generation, shared secret, HKDF
    |   +-- aes_gcm.cpp/h       AES-256-GCM authenticated encryption (OpenSSL)
    |   +-- cert_auth.cpp/h     ECDSA certificates, CA operations, TOFU store
    |
    +-- protocol/
    |   +-- tcp_channel.cpp/h   Framed TCP transport (length-prefixed messages)
    |   +-- handshake.cpp/h     ECDH key exchange protocol (Acts 1/2/3)
    |   +-- messenger.cpp/h     Encrypted send/receive and interactive chat loop
    |
    +-- ui/
        +-- terminal.h          ANSI colour, ASCII boxes, spinners, animations
        +-- terminal.cpp        Compilation unit stub
```

---

## Building the Project

```bash
# Clone or extract the project, then:
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Compiled binaries are placed in `build/bin/`:

```
build/bin/alice     (alice.exe on Windows)
build/bin/bob       (bob.exe   on Windows)
build/bin/oscar     (oscar.exe on Windows)
```

To verify the build:
```bash
ls build/bin/
```

---

## Running the Demo

### Option A — Automated Demo (Recommended for First Run)

Runs all three acts automatically with explanatory output and pacing:

```bash
bash scripts/demo.sh build
```

### Option B — Interactive Split-Pane (tmux)

Opens each process in its own terminal pane for side-by-side live observation:

```bash
bash scripts/tmux_demo.sh build
# Select: 1 (Act 1), 2 (Act 2), 3 (Act 3), or 'a' (all acts)
```

### Option C — Manual (Three Separate Terminals)

This option gives the most visibility into each party's output.

#### Act 1 — Honest ECDH

Open two terminals and run in this exact order:

```bash
# Terminal 1 — Bob must start first (he is the listener)
./build/bin/bob

# Terminal 2 — Alice connects to Bob
./build/bin/alice
```

**Expected outcome:** Both terminals show the same fingerprint. A shared secret is established. An AES-256-GCM encrypted chat session opens.

---

#### Act 2 — Man-in-the-Middle Attack

Open three terminals and run in this exact order:

```bash
# Terminal 1 — Bob listens on port 9003
./build/bin/bob

# Terminal 2 — Oscar listens on port 9001 (for Alice) and connects to port 9003 (to Bob)
./build/bin/oscar

# Terminal 3 — Alice connects to port 9001 (hits Oscar, not Bob)
./build/bin/alice
```

**Expected outcome:** Oscar's terminal shows two different session keys and displays every message from both Alice and Bob in plaintext. Alice and Bob each see the other's fingerprint as Oscar's fingerprint — they are unaware.

---

#### Act 3 — Certificate Authentication (Defence)

```bash
# Terminal 1 — Bob with certificate verification enabled
./build/bin/bob --auth

# Terminal 2 — Oscar attempts authenticated MITM (will fail)
./build/bin/oscar --auth

# Terminal 3 — Alice with certificate verification enabled
./build/bin/alice --auth
```

**Expected outcome:** Oscar cannot produce a certificate signed by the trusted Certificate Authority. Both Alice and Bob detect the invalid signature during the handshake and abort the connection. Oscar's terminal shows both handshake failures.

---

## The Three Acts Explained

### Act 1 — Honest ECDH (~3 minutes)

Alice and Bob each generate a P-256 keypair independently. They exchange their public keys over TCP. Each party computes the shared secret as the x-coordinate of `private_key * peer_public_key`. Both arrive at the same scalar value through the mathematics of elliptic curve groups. They then derive a symmetric AES-256 session key using HKDF-SHA-256 and enter an encrypted chat.

Key observation: the public keys travel in plaintext over the network — this is expected and safe. The private keys never leave their respective processes. Wireshark shows only ciphertext after the handshake.

### Act 2 — MITM Attack (~4 minutes)

Oscar positions himself between Alice and Bob. He performs two independent ECDH handshakes:

- **Alice ↔ Oscar** using keypair A — establishes `shared_A`
- **Oscar ↔ Bob** using keypair B — establishes `shared_B`

Alice encrypts her messages with `shared_A` (thinking it is shared with Bob). Oscar decrypts with `shared_A`, reads the plaintext, re-encrypts with `shared_B`, and forwards to Bob — and vice versa.

Neither Alice nor Bob has any indication of Oscar's presence except for the fingerprint mismatch. If Alice and Bob compared their fingerprints through an out-of-band channel (a phone call, for example), they would detect the attack. In practice, most users never perform this check.

**Root cause:** Unauthenticated ECDH provides no binding between a public key and an identity. Any party that can intercept the initial exchange can substitute their own public key.

### Act 3 — Certificate Defence (~5 minutes)

A Certificate Authority (CA) is introduced. The CA holds a P-256 keypair. Before the demo, Alice and Bob each receive a certificate: an ECDSA signature by the CA over `SHA-256(identity || public_key)`. Both Alice and Bob pre-share the CA's public key.

During the authenticated handshake:
1. Each party sends its certificate alongside its public key
2. The receiver verifies the ECDSA signature against the known CA public key
3. The receiver also checks that the certificate's embedded public key matches what was transmitted

Oscar cannot produce a valid certificate for his own public keys because he does not possess the CA's private key. Attempting to submit a self-signed certificate causes both Alice and Bob to abort immediately.

Additional defences demonstrated:
- **TOFU (Trust On First Use):** On first connection, the peer's fingerprint is stored. Future connections with a different fingerprint trigger a warning analogous to SSH's "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED."
- **Key pinning:** The certificate's public key must match the transmitted key exactly, preventing certificate reuse attacks.

---

## Architecture and Implementation

### Layer 1 — Cryptographic Core (`src/crypto/`)

#### `ecc_math` — P-256 from Scratch

Implements all field and group arithmetic for the NIST P-256 curve (secp256r1):

```
Curve equation:  y^2 = x^3 + ax + b  (mod p)

p  = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFF
a  = p - 3
b  = 5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B
Gx = 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296
Gy = 4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5
n  = FFFFFFFF 00000000 FFFFFFFF FFFFFFFF BCE6FAAD A7179E84 F3B9CAC2 FC632551
```

256-bit integers are stored as `std::array<uint64_t, 4>` in little-endian limb order. Modular multiplication uses the NIST P-256 fast reduction algorithm (FIPS 186-4, Appendix D.1.2.3). Scalar multiplication uses the double-and-add algorithm.

#### `ecdh_core` — Key Exchange

- `ecdh_generate_keypair()` — samples a random scalar `k` in `[1, n-1]` using OpenSSL's CSPRNG; computes `Q = k * G`
- `ecdh_shared_secret()` — computes `S = private * peer_public`; returns the x-coordinate as 32 bytes
- `ecdh_derive_key()` — applies HKDF-SHA-256 to produce a fixed-length symmetric key
- `ecdh_fingerprint()` — computes the first 20 bytes of SHA-256 of the serialised public key, formatted as colon-separated hex pairs

#### `aes_gcm` — Authenticated Encryption

Uses the OpenSSL EVP interface for AES-256-GCM. Each message uses a fresh 12-byte random IV. The 16-byte GCM authentication tag is appended to the ciphertext. A tag mismatch during decryption raises an exception, signalling tampering or key mismatch.

Wire format: `[ 4-byte IV length | IV (12 bytes) | ciphertext | auth tag (16 bytes) ]`

#### `cert_auth` — Certificate Authority

Implements a simplified certificate scheme suitable for demonstration:

- **Format:** `identity (string) || public_key (65 bytes uncompressed) || ECDSA signature (DER)`
- **Signing:** ECDSA-P256 over `SHA-256(identity || public_key)` using OpenSSL EVP `DigestSign`
- **Verification:** `EVP_DigestVerify` against the known CA public key
- **CA persistence:** The CA's private key scalar is stored in `data/ca_key.hex` in hex; it is regenerated if not present
- **TOFU store:** Identity-to-fingerprint mappings are written to `data/tofu.json` as plain text

### Layer 2 — Protocol (`src/protocol/`)

#### `tcp_channel` — Framed Transport

TCP is a byte stream. Every application message is prefixed with a 4-byte little-endian length field. `recv_msg()` reads the header, allocates a buffer, and calls `recv()` in a loop until the full payload arrives. This correctly handles TCP segmentation and Nagle buffering. Compatible with Linux, macOS, and Windows (Winsock2).

#### `handshake` — Key Exchange Protocol

**Unauthenticated (Acts 1 and 2):**
```
Initiator -> Responder:  "HELLO:<identity>:" + ec_point_serialize(pub)   [65 bytes]
Responder -> Initiator:  "HELLO:<identity>:" + ec_point_serialize(pub)   [65 bytes]
Both parties compute:    shared_secret = ECDH(own_private, peer_public)
Both parties compute:    session_key   = HKDF-SHA256(shared_secret, label)
```

**Authenticated (Act 3):**
```
Initiator -> Responder:  "HELLO_AUTH:<id>:" + [4B publen][4B certlen][pub][cert]
Responder -> Initiator:  "HELLO_AUTH:<id>:" + [4B publen][4B certlen][pub][cert]
Each party:              verify ECDSA cert signature against CA public key
Each party:              assert cert.public_key == transmitted public key
Both parties compute:    session_key = HKDF-SHA256(ECDH(...), auth-label)
```

#### `messenger` — Encrypted Chat

`send()` encrypts the plaintext string with AES-256-GCM and transmits the packed result. `recv()` receives a packed frame and decrypts it; a GCM tag failure throws `std::runtime_error`. `chat_loop()` spawns a receive thread and runs a send loop on `stdin`, allowing simultaneous bidirectional messaging.

### Layer 3 — Executables

| Executable | Listens | Connects | Role in Act 2         |
|------------|---------|----------|-----------------------|
| `alice`    | —       | :9001    | Sends to Oscar unknowingly |
| `bob`      | :9003   | —        | Receives from Oscar unknowingly |
| `oscar`    | :9001   | :9003    | Intercepts both sides |

---

## Cryptographic Algorithms

| Algorithm        | Purpose                        | Implementation        |
|------------------|--------------------------------|-----------------------|
| P-256 (secp256r1)| Elliptic curve group           | From scratch          |
| ECDH             | Key agreement                  | From scratch          |
| HKDF-SHA-256     | Key derivation                 | From scratch          |
| AES-256-GCM      | Authenticated encryption       | OpenSSL EVP           |
| ECDSA-P256       | Certificate signing/verification| OpenSSL EVP DigestSign|
| SHA-256          | Hashing (fingerprint, HKDF)    | OpenSSL SHA256        |

---

## Network Protocol

All communication is over localhost TCP. Ports used:

| Port | Owner  | Description                              |
|------|--------|------------------------------------------|
| 9001 | Bob/Oscar | Alice always connects here           |
| 9003 | Bob    | Bob always listens here                  |

In Act 2, Oscar intercepts port 9001 (Alice's destination) and connects forward to port 9003 (Bob's listener). Bob never knows that the connection originates from Oscar rather than Alice.

---

## Security Analysis

### What This Demo Shows

- **Unauthenticated ECDH is entirely vulnerable to MITM.** An attacker who can intercept the initial handshake can substitute their own public keys, establishing two independent encrypted sessions while appearing transparent to both parties.

- **Certificate authentication eliminates the substitution attack.** Because a trusted CA signs each public key before the session, an attacker cannot substitute their own key without also holding the CA's private key.

- **AES-256-GCM provides authenticated encryption.** Any tampering with ciphertext in transit causes decryption to fail with an authentication error.

### What This Demo Does Not Implement

- **Constant-time arithmetic.** The from-scratch P-256 implementation is not protected against timing side-channel attacks and is not suitable for production use.
- **Certificate revocation.** There is no CRL or OCSP mechanism.
- **Forward secrecy ephemeral scheduling.** Both Alice and Bob use long-lived keypairs for simplicity. Production protocols (TLS 1.3, Signal) use fresh ephemeral keys per session.
- **Full X.509 PKI.** The certificate format is simplified for readability. Real deployments use DER-encoded X.509 with ASN.1 structures.

---

## Troubleshooting

**"Failed to bind on port 9001 or 9003"**
A previous run left a process still bound. Find and kill it:
```bash
# Linux / macOS
lsof -i :9001
kill <PID>

# Windows
netstat -ano | findstr 9001
taskkill /PID <PID> /F
```

**"Could not connect after 30 attempts"**
Alice could not reach the expected port. Ensure Bob (for Act 1/3) or Oscar (for Act 2) was started first and is showing "Listening on port..." before starting Alice.

**"OpenSSL not found" during cmake**
```bash
# Linux
sudo apt install libssl-dev

# macOS
cmake -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl)

# Windows (MSYS2)
pacman -S mingw-w64-x86_64-openssl
```

**"CERTIFICATE VERIFICATION FAILED" in Act 1 or 2**
The `--auth` flag was passed to a binary that was not expecting it, or Act 3 binaries are mixed with Act 1/2 binaries. Restart all three terminals without `--auth` for Acts 1 and 2.

**Garbled symbols in the terminal**
The terminal does not support ANSI escape codes. On Windows, run in Windows Terminal or enable virtual terminal processing:
```cmd
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```
On older cmd.exe, use MSYS2's mintty terminal instead.

---

## References

1. NIST FIPS 186-4 — *Digital Signature Standard*, Appendix D.1.2.3 (P-256 fast reduction)
2. RFC 6090 — *Fundamental Elliptic Curve Cryptography Algorithms*
3. RFC 5869 — *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*
4. RFC 5116 — *An Interface and Algorithms for Authenticated Encryption*
5. RFC 4492 — *Elliptic Curve Cryptography (ECC) Cipher Suites for TLS*
6. Bernstein & Lange — *SafeCurves: choosing safe curves for elliptic-curve cryptography* (https://safecurves.cr.yp.to)
7. Menezes, van Oorschot, Vanstone — *Handbook of Applied Cryptography*, Chapter 11

---

*This project is intended for educational purposes. The cryptographic implementations are written for clarity and correctness, not for production security.*