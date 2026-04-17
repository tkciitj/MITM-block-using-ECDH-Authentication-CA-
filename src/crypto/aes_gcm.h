#pragma once
#include <vector>
#include <string>
#include <cstdint>

// ─────────────────────────────────────────────────────────────────────────────
// AES-256-GCM authenticated encryption.
// GCM = Galois/Counter Mode. Provides both confidentiality AND integrity.
// The auth_tag (16 bytes) detects any tampering with the ciphertext.
// ─────────────────────────────────────────────────────────────────────────────

struct AESGCMResult {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;        // 12-byte random IV (nonce)
    std::vector<uint8_t> auth_tag;  // 16-byte authentication tag
};

// Encrypt plaintext with a 32-byte key. Generates a fresh random IV.
AESGCMResult aes_gcm_encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& plaintext
);

// Decrypt and verify. Throws if tag verification fails (tampered data).
std::vector<uint8_t> aes_gcm_decrypt(
    const std::vector<uint8_t>& key,
    const AESGCMResult& result
);

// Serialize an AESGCMResult to bytes for transmission:
// [4 bytes: ct_len] [ciphertext] [12 bytes: iv] [16 bytes: tag]
std::vector<uint8_t> aes_gcm_pack(const AESGCMResult& r);
AESGCMResult         aes_gcm_unpack(const std::vector<uint8_t>& data);
