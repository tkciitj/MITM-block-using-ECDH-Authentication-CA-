#pragma once
#include "ecc_math.h"
#include <vector>
#include <string>

// ─────────────────────────────────────────────────────────────────────────────
// ECDHKeyPair — private scalar + public point
// ─────────────────────────────────────────────────────────────────────────────
struct ECDHKeyPair {
    U256    private_key;         // random scalar k ∈ [1, n-1]
    ECPoint public_key;          // Q = k * G  (point on P-256)
    std::string fingerprint;     // SHA-256(public_key_bytes)[0:20] as hex
};

// ─────────────────────────────────────────────────────────────────────────────
// ECDH functions
// ─────────────────────────────────────────────────────────────────────────────

// Generate a fresh keypair. Prints generation steps if verbose=true.
ECDHKeyPair ecdh_generate_keypair(bool verbose = false);

// Derive the shared secret from our private key and their public key.
// Returns the x-coordinate of (private * their_public) as 32 bytes.
// Both parties compute the same value: Alice's result = Bob's result.
std::vector<uint8_t> ecdh_shared_secret(
    const U256&    our_private,
    const ECPoint& their_public,
    bool verbose = false
);

// HKDF-SHA256: expand the raw shared secret into a symmetric key.
// label = context string ("alice-bob-session-key" etc.)
std::vector<uint8_t> ecdh_derive_key(
    const std::vector<uint8_t>& shared_secret,
    const std::string& label,
    size_t key_len = 32
);

// Compute key fingerprint: first 20 bytes of SHA-256(serialized public key)
// formatted as 10 pairs of hex bytes separated by colons (like SSH does).
// e.g. "A1:B2:C3:D4:E5:F6:07:18:29:3A"
std::string ecdh_fingerprint(const ECPoint& public_key);

// Verify a public key is valid (on the curve, not the identity)
bool ecdh_validate_public_key(const ECPoint& pub);
