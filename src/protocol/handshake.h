#pragma once
#include "tcp_channel.h"
#include "../crypto/ecdh_core.h"
#include "../crypto/cert_auth.h"
#include <string>
#include <vector>
#include <optional>

// ─────────────────────────────────────────────────────────────────────────────
// Handshake protocol
//
// ACT 1 & 2 (unauthenticated):
//   → Alice sends: "HELLO:Alice" + public_key_bytes (65)
//   ← Bob   sends: "HELLO:Bob"   + public_key_bytes (65)
//   Both derive shared secret and session key.
//
// ACT 3 (authenticated):
//   → Alice sends: "HELLO_AUTH:Alice" + public_key_bytes (65) + cert_bytes
//   ← Bob   sends: "HELLO_AUTH:Bob"   + public_key_bytes (65) + cert_bytes
//   Both verify the certificate against the CA public key.
//   If verification fails → abort with error.
// ─────────────────────────────────────────────────────────────────────────────

struct SessionKey {
    std::vector<uint8_t> key;         // 32-byte AES-256 key
    std::string          peer_identity;
    std::string          peer_fingerprint;
    bool                 authenticated;
};

// Perform unauthenticated ECDH handshake (Act 1/2)
// Returns session key if successful
SessionKey handshake_unauthenticated(
    TCPChannel& chan,
    const ECDHKeyPair& our_kp,
    const std::string& our_identity,
    bool verbose = true
);

// Perform authenticated ECDH handshake (Act 3)
// ca_public_key = the trusted CA's public key (both parties have this pre-shared)
SessionKey handshake_authenticated(
    TCPChannel& chan,
    const ECDHKeyPair& our_kp,
    const Certificate& our_cert,
    const std::string& our_identity,
    const ECPoint& ca_public_key,
    bool verbose = true
);
