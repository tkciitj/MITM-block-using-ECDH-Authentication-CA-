#include "cert_auth.h"
#include "ecdh_core.h"
#include "../ui/terminal.h"
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <iomanip>

// ── ECDSA signing using OpenSSL ───────────────────────────────────────────────
// We use OpenSSL for ECDSA because implementing it from scratch would require
// a secure nonce generation strategy (RFC 6979 deterministic ECDSA) to be safe.
// The ECDH math is our from-scratch work; ECDSA is the authentication layer.

static std::vector<uint8_t> ecdsa_sign(const U256& private_key,
                                        const std::vector<uint8_t>& message) {
    // Hash the message first
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(message.data(), message.size(), hash);

    // Convert our U256 private key to OpenSSL BIGNUM
    auto priv_bytes = u256_to_vec(private_key);
    BIGNUM* bn_priv = BN_bin2bn(priv_bytes.data(), 32, nullptr);

    // Create EC_KEY on P-256
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key || EC_KEY_set_private_key(key, bn_priv) != 1) {
        BN_free(bn_priv);
        throw std::runtime_error("ECDSA key setup failed");
    }

    // Sign
    ECDSA_SIG* sig = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, key);
    if (!sig) {
        EC_KEY_free(key); BN_free(bn_priv);
        throw std::runtime_error("ECDSA_do_sign failed");
    }

    // DER encode the signature
    int der_len = i2d_ECDSA_SIG(sig, nullptr);
    std::vector<uint8_t> der(der_len);
    uint8_t* p = der.data();
    i2d_ECDSA_SIG(sig, &p);

    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
    BN_free(bn_priv);
    return der;
}

static bool ecdsa_verify(const ECPoint& public_key,
                          const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(message.data(), message.size(), hash);

    // Build OpenSSL EC_KEY from our point
    EC_KEY* key   = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_GROUP* grp = const_cast<EC_GROUP*>(EC_KEY_get0_group(key));

    auto pub_bytes = ec_point_serialize(public_key);
    EC_POINT* pt   = EC_POINT_new(grp);
    if (!EC_POINT_oct2point(grp, pt, pub_bytes.data(), pub_bytes.size(), nullptr)) {
        EC_KEY_free(key); EC_POINT_free(pt);
        return false;
    }
    EC_KEY_set_public_key(key, pt);

    // Decode DER signature
    const uint8_t* p = signature.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, (long)signature.size());
    if (!sig) { EC_KEY_free(key); EC_POINT_free(pt); return false; }

    int result = ECDSA_do_verify(hash, SHA256_DIGEST_LENGTH, sig, key);

    ECDSA_SIG_free(sig);
    EC_KEY_free(key);
    EC_POINT_free(pt);
    return result == 1;
}

// ── CA operations ─────────────────────────────────────────────────────────────

CAKeyPair ca_generate(const std::string& ca_file) {
    CAKeyPair ca;
    if (!ca_file.empty()) {
        std::ifstream f(ca_file);
        if (f.good()) {
            std::string hex;
            std::getline(f, hex);
            if (hex.size() == 64) {
                ca.private_key = u256_from_hex(hex);
                ca.public_key  = ec_mul(ca.private_key, ec_generator());
                return ca;
            }
        }
    }
    ca.private_key = ec_random_scalar();
    ca.public_key  = ec_mul(ca.private_key, ec_generator());
    if (!ca_file.empty()) {
        std::ofstream f(ca_file);
        f << u256_to_hex(ca.private_key) << "\n";
    }
    return ca;
}

Certificate ca_issue(const CAKeyPair& ca,
                     const std::string& identity,
                     const ECPoint& subject_key) {
    Certificate cert;
    cert.identity         = identity;
    cert.public_key_bytes = ec_point_serialize(subject_key);
    cert.fingerprint      = ecdh_fingerprint(subject_key);

    // Message to sign: identity bytes || public key bytes
    std::vector<uint8_t> msg(identity.begin(), identity.end());
    msg.insert(msg.end(), cert.public_key_bytes.begin(), cert.public_key_bytes.end());

    cert.signature = ecdsa_sign(ca.private_key, msg);
    return cert;
}

bool ca_verify(const Certificate& cert, const ECPoint& ca_public_key) {
    std::vector<uint8_t> msg(cert.identity.begin(), cert.identity.end());
    msg.insert(msg.end(), cert.public_key_bytes.begin(), cert.public_key_bytes.end());
    return ecdsa_verify(ca_public_key, msg, cert.signature);
}

std::vector<uint8_t> cert_serialize(const Certificate& cert) {
    // Format: [1 byte id_len][identity][65 bytes pubkey][2 bytes sig_len][sig][20 bytes fingerprint as string]
    std::vector<uint8_t> out;
    out.push_back((uint8_t)cert.identity.size());
    out.insert(out.end(), cert.identity.begin(), cert.identity.end());
    out.insert(out.end(), cert.public_key_bytes.begin(), cert.public_key_bytes.end());
    uint16_t sig_len = (uint16_t)cert.signature.size();
    out.push_back(sig_len & 0xFF);
    out.push_back(sig_len >> 8);
    out.insert(out.end(), cert.signature.begin(), cert.signature.end());
    out.insert(out.end(), cert.fingerprint.begin(), cert.fingerprint.end());
    return out;
}

Certificate cert_deserialize(const std::vector<uint8_t>& data) {
    Certificate cert;
    size_t pos = 0;
    uint8_t id_len = data[pos++];
    cert.identity.assign(data.begin()+pos, data.begin()+pos+id_len);
    pos += id_len;
    cert.public_key_bytes.assign(data.begin()+pos, data.begin()+pos+65);
    pos += 65;
    uint16_t sig_len = data[pos] | ((uint16_t)data[pos+1] << 8);
    pos += 2;
    cert.signature.assign(data.begin()+pos, data.begin()+pos+sig_len);
    pos += sig_len;
    cert.fingerprint.assign(data.begin()+pos, data.end());
    return cert;
}

// ── TOFU Store ────────────────────────────────────────────────────────────────

TOFUStore::TOFUStore(const std::string& filepath) : filepath_(filepath) {
    load();
}

bool TOFUStore::check_and_store(const std::string& identity,
                                 const std::string& fingerprint) {
    auto it = store_.find(identity);
    if (it == store_.end()) {
        store_[identity] = fingerprint;
        save();
        return true;  // first time — trusted
    }
    if (it->second != fingerprint) {
        throw std::runtime_error(
            "TOFU WARNING: Fingerprint for '" + identity +
            "' has CHANGED!\n"
            "  Stored  : " + it->second + "\n"
            "  Received: " + fingerprint + "\n"
            "  This may indicate a MAN-IN-THE-MIDDLE ATTACK."
        );
    }
    return false;  // already known, matches
}

void TOFUStore::save() {
    if (filepath_.empty()) return;
    std::ofstream f(filepath_);
    for (auto& [id, fp] : store_)
        f << id << " " << fp << "\n";
}

void TOFUStore::load() {
    if (filepath_.empty()) return;
    std::ifstream f(filepath_);
    std::string id, fp;
    while (f >> id >> fp) store_[id] = fp;
}
