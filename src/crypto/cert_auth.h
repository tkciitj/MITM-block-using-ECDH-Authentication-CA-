#pragma once
#include "ecc_math.h"
#include <string>
#include <vector>
#include <map>

// ─────────────────────────────────────────────────────────────────────────────
// Certificate & Authentication
//
// In Act 3 we defeat the MITM by adding authentication.
// We simulate a simple Certificate Authority (CA) that signs public keys.
// Oscar cannot forge a valid certificate because he doesn't have the CA's
// private key.
//
// Certificate format (simplified, not X.509):
//   - identity     : "Alice" or "Bob"
//   - public_key   : 65-byte serialized EC point
//   - signature    : ECDSA signature over SHA256(identity || public_key)
//   - fingerprint  : first 20 bytes of SHA256(public_key)
// ─────────────────────────────────────────────────────────────────────────────

struct Certificate {
    std::string          identity;
    std::vector<uint8_t> public_key_bytes;  // 65 bytes uncompressed
    std::vector<uint8_t> signature;         // ECDSA-P256 signature (DER encoded)
    std::string          fingerprint;
};

struct CAKeyPair {
    U256    private_key;
    ECPoint public_key;
};

// ── Certificate Authority operations ─────────────────────────────────────────

// Generate a CA keypair (or load from file if it exists)
CAKeyPair ca_generate(const std::string& ca_file = "");

// Issue a certificate: CA signs the identity's public key
Certificate ca_issue(const CAKeyPair& ca, const std::string& identity,
                     const ECPoint& subject_key);

// Verify a certificate against a known CA public key.
// Returns true only if the signature is valid.
bool ca_verify(const Certificate& cert, const ECPoint& ca_public_key);

// Serialize / deserialize certificate for transmission
std::vector<uint8_t> cert_serialize  (const Certificate& cert);
Certificate          cert_deserialize(const std::vector<uint8_t>& data);

// ── TOFU (Trust On First Use) store ──────────────────────────────────────────
// Stores identity → fingerprint mapping persistently.
// Once Alice trusts Bob's fingerprint, any future connection with a different
// fingerprint triggers a warning (like SSH's "WARNING: REMOTE HOST IDENTIFICATION
// HAS CHANGED" message).

class TOFUStore {
public:
    explicit TOFUStore(const std::string& filepath);

    // Returns true if this is a new identity (first time seen)
    // Returns false and verifies if identity was seen before
    // Throws if the fingerprint changed (potential MITM)
    bool check_and_store(const std::string& identity, const std::string& fingerprint);

    void save();
    void load();

private:
    std::string filepath_;
    std::map<std::string, std::string> store_;  // identity → fingerprint
};
