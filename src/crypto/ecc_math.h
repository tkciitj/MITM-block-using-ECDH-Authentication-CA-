#pragma once
#include <cstdint>
#include <array>
#include <string>
#include <vector>

// ─────────────────────────────────────────────────────────────────────────────
// P-256 (secp256r1 / NIST P-256) elliptic curve arithmetic — from scratch.
//
// CURVE EQUATION: y² ≡ x³ + ax + b  (mod p)
//
// P-256 parameters (all values are 256-bit integers, stored as 4 × uint64_t):
//   p  = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
//   a  = FFFFFFFC  (= p - 3, chosen for efficient Montgomery reduction)
//   b  = 5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
//   Gx = 6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
//   Gy = 4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
//   n  = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
//
// We represent 256-bit integers as std::array<uint64_t, 4> in LITTLE-ENDIAN
// order (index 0 = least significant 64-bit limb).
// ─────────────────────────────────────────────────────────────────────────────

using U256 = std::array<uint64_t, 4>;  // 256-bit integer, little-endian limbs

// ── P-256 domain parameters ───────────────────────────────────────────────────
namespace P256 {
    // Field prime p
    constexpr U256 P = {
        0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL,
        0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
    };
    // Curve order n
    constexpr U256 N = {
        0xF3B9CAC2FC632551ULL, 0xBCE6FAADA7179E84ULL,
        0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL
    };
    // a = p - 3
    constexpr U256 A = {
        0xFFFFFFFFFFFFFFFCULL, 0x00000000FFFFFFFFULL,
        0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
    };
    // b
    constexpr U256 B = {
        0x3BCE3C3E27D2604BULL, 0x651D06B0CC53B0F6ULL,
        0xB3EBBD55769886BCULL, 0x5AC635D8AA3A93E7ULL
    };
    // Generator Gx
    constexpr U256 GX = {
        0xF4A13945D898C296ULL, 0x77037D812DEB33A0ULL,
        0xF8BCE6E563A440F2ULL, 0x6B17D1F2E12C4247ULL
    };
    // Generator Gy
    constexpr U256 GY = {
        0xCBB6406837BF51F5ULL, 0x2BCE33576B315ECEULL,
        0x8EE7EB4A7C0F9E16ULL, 0x4FE342E2FE1A7F9BULL
    };
}

// ── Affine point on the curve ─────────────────────────────────────────────────
struct ECPoint {
    U256 x{}, y{};
    bool infinity = true;   // true = point at infinity (identity element)

    bool operator==(const ECPoint& o) const {
        return infinity == o.infinity && (infinity || (x == o.x && y == o.y));
    }
    bool operator!=(const ECPoint& o) const { return !(*this == o); }
};

// ── 256-bit modular arithmetic ────────────────────────────────────────────────
// All operations work on U256 values and reduce modulo a given modulus.

// Compare: returns -1, 0, +1
int  u256_cmp(const U256& a, const U256& b);

// a + b mod m
U256 u256_add_mod(const U256& a, const U256& b, const U256& m);

// a - b mod m  (assumes a,b < m)
U256 u256_sub_mod(const U256& a, const U256& b, const U256& m);

// a * b mod m  (uses schoolbook multiplication + Barrett reduction for P-256)
U256 u256_mul_mod(const U256& a, const U256& b, const U256& m);

// a^(-1) mod m  (extended Euclidean algorithm)
U256 u256_inv_mod(const U256& a, const U256& m);

// Modular exponentiation: base^exp mod m (for square roots etc.)
U256 u256_pow_mod(const U256& base, const U256& exp, const U256& m);

// Convert between U256 and big-endian bytes (32 bytes)
U256             u256_from_bytes(const uint8_t* b);
void             u256_to_bytes  (const U256& v, uint8_t* out);
std::vector<uint8_t> u256_to_vec(const U256& v);
std::string      u256_to_hex    (const U256& v);
U256             u256_from_hex  (const std::string& hex);

// ── Elliptic curve group operations ──────────────────────────────────────────

// Point doubling: 2P
ECPoint ec_double(const ECPoint& P);

// Point addition: P + Q
ECPoint ec_add(const ECPoint& P, const ECPoint& Q);

// Scalar multiplication: k * P  (double-and-add algorithm)
// This is the core operation of ECDH.
ECPoint ec_mul(const U256& k, const ECPoint& P);

// Return the P-256 generator point G
ECPoint ec_generator();

// Check whether a point lies on the P-256 curve
bool ec_on_curve(const ECPoint& P);

// Serialize/deserialize a point to/from 65 bytes (uncompressed: 04 || x || y)
std::vector<uint8_t> ec_point_serialize  (const ECPoint& P);
ECPoint              ec_point_deserialize(const std::vector<uint8_t>& data);

// Generate a random 256-bit scalar in [1, n-1]
// Uses OpenSSL's CSPRNG — the only OpenSSL call in the crypto layer
U256 ec_random_scalar();
