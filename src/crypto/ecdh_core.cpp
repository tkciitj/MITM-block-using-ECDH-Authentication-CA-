#include "ecdh_core.h"
#include "../ui/terminal.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdexcept>
#include <cstring>
#include <sstream>
#include <iomanip>

ECDHKeyPair ecdh_generate_keypair(bool verbose) {
    ECDHKeyPair kp;

    if (verbose) {
        T::spinner("Generating random private scalar on P-256...", 600);
    }

    // Step 1: random private key k ∈ [1, n-1]
    kp.private_key = ec_random_scalar();

    if (verbose) {
        std::cout << "\n";
        T::kv("Private key (k)", u256_to_hex(kp.private_key).substr(0,32) + "...",
              T::DIM, T::CRYPTO);
        T::spinner("Computing public key Q = k × G (scalar multiplication on P-256)...", 800);
    }

    // Step 2: public key Q = k * G
    kp.public_key = ec_mul(kp.private_key, ec_generator());

    // Step 3: compute fingerprint
    kp.fingerprint = ecdh_fingerprint(kp.public_key);

    if (verbose) {
        std::cout << "\n";
        T::kv("Public key Qx", u256_to_hex(kp.public_key.x).substr(0,32) + "...",
              T::DIM, T::CYAN);
        T::kv("Public key Qy", u256_to_hex(kp.public_key.y).substr(0,32) + "...",
              T::DIM, T::CYAN);
        T::kv("Fingerprint",   kp.fingerprint, T::DIM, T::YELLOW);
    }

    return kp;
}

std::vector<uint8_t> ecdh_shared_secret(
    const U256& our_private,
    const ECPoint& their_public,
    bool verbose)
{
    if (!ecdh_validate_public_key(their_public))
        throw std::runtime_error("Invalid public key received — possible attack!");

    if (verbose) {
        T::spinner("Computing shared secret S = k × Q_peer (P-256 scalar mul)...", 700);
    }

    // The shared secret is the x-coordinate of k_self * Q_peer
    // Both parties compute the same point: k_A * Q_B = k_A*(k_B*G) = k_B*(k_A*G) = k_B * Q_A
    ECPoint shared_point = ec_mul(our_private, their_public);

    if (verbose) {
        std::cout << "\n";
        T::kv("Shared point x", u256_to_hex(shared_point.x).substr(0,32) + "...",
              T::DIM, T::CRYPTO);
    }

    return u256_to_vec(shared_point.x);
}

std::vector<uint8_t> ecdh_derive_key(
    const std::vector<uint8_t>& shared_secret,
    const std::string& label,
    size_t key_len)
{
    // HKDF-SHA256
    // Step 1: Extract — HMAC-SHA256(salt=0x00...00, ikm=shared_secret)
    std::vector<uint8_t> salt(32, 0x00);
    std::vector<uint8_t> prk(32);
    unsigned int prk_len = 32;
    HMAC(EVP_sha256(), salt.data(), (int)salt.size(),
         shared_secret.data(), (int)shared_secret.size(),
         prk.data(), &prk_len);

    // Step 2: Expand — HMAC-SHA256(prk, label || 0x01)
    std::vector<uint8_t> info(label.begin(), label.end());
    info.push_back(0x01);
    std::vector<uint8_t> okm(32);
    unsigned int okm_len = 32;
    HMAC(EVP_sha256(), prk.data(), (int)prk.size(),
         info.data(), (int)info.size(),
         okm.data(), &okm_len);

    okm.resize(key_len);
    return okm;
}

std::string ecdh_fingerprint(const ECPoint& public_key) {
    auto serialized = ec_point_serialize(public_key);

    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(serialized.data(), serialized.size(), hash);

    // Format as "XX:XX:XX:..." (first 10 bytes = 20 hex chars + 9 colons)
    std::ostringstream oss;
    for (int i = 0; i < 10; i++) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return oss.str();
}

bool ecdh_validate_public_key(const ECPoint& pub) {
    if (pub.infinity) return false;
    return ec_on_curve(pub);
}
