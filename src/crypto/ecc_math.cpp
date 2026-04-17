#include "ecc_math.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

// ================= U256 UTILITIES (RESTORED) =================

U256 u256_from_bytes(const uint8_t* b) {
    U256 v{};
    for (int i = 0; i < 32; i++) {
        int limb = 3 - i/8;
        int shift = (7 - i%8) * 8;
        v[limb] |= (uint64_t)b[i] << shift;
    }
    return v;
}

void u256_to_bytes(const U256& v, uint8_t* out) {
    for (int i = 0; i < 32; i++) {
        int limb = 3 - i/8;
        int shift = (7 - i%8) * 8;
        out[i] = (uint8_t)(v[limb] >> shift);
    }
}

std::vector<uint8_t> u256_to_vec(const U256& v) {
    std::vector<uint8_t> out(32);
    u256_to_bytes(v, out.data());
    return out;
}

std::string u256_to_hex(const U256& v) {
    auto b = u256_to_vec(v);
    std::ostringstream oss;
    for (auto byte : b)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    return oss.str();
}

U256 u256_from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes(32);
    for (int i = 0; i < 32; i++) {
        bytes[i] = (uint8_t)std::stoul(hex.substr(i*2, 2), nullptr, 16);
    }
    return u256_from_bytes(bytes.data());
}

// ================= OpenSSL Helpers =================

static BIGNUM* u256_to_bn(const U256& v) {
    auto bytes = u256_to_vec(v);
    return BN_bin2bn(bytes.data(), 32, nullptr);
}

static U256 bn_to_u256(const BIGNUM* bn) {
    uint8_t buf[32]{};
    BN_bn2binpad(bn, buf, 32);
    return u256_from_bytes(buf);
}

// ================= ECC CORE =================

U256 ec_random_scalar() {
    uint8_t buf[32];
    do {
        if (RAND_bytes(buf, 32) != 1)
            throw std::runtime_error("RAND_bytes failed");
    } while (buf[0] == 0);
    return u256_from_bytes(buf);
}

ECPoint ec_generator() {
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_POINT* G = EC_GROUP_get0_generator(grp);

    BIGNUM *x = BN_new(), *y = BN_new();
    EC_POINT_get_affine_coordinates(grp, G, x, y, nullptr);

    ECPoint P{bn_to_u256(x), bn_to_u256(y), false};

    BN_free(x); BN_free(y);
    EC_GROUP_free(grp);
    return P;
}

ECPoint ec_mul(const U256& k, const ECPoint& P) {
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    EC_POINT* point = EC_POINT_new(grp);
    EC_POINT* result = EC_POINT_new(grp);

    BIGNUM* bn_k = u256_to_bn(k);
    BIGNUM* x = u256_to_bn(P.x);
    BIGNUM* y = u256_to_bn(P.y);

    EC_POINT_set_affine_coordinates(grp, point, x, y, nullptr);

    EC_POINT_mul(grp, result, nullptr, point, bn_k, nullptr);

    BIGNUM *rx = BN_new(), *ry = BN_new();
    EC_POINT_get_affine_coordinates(grp, result, rx, ry, nullptr);

    ECPoint out{bn_to_u256(rx), bn_to_u256(ry), false};

    BN_free(bn_k); BN_free(x); BN_free(y);
    BN_free(rx); BN_free(ry);
    EC_POINT_free(point); EC_POINT_free(result);
    EC_GROUP_free(grp);

    return out;
}

ECPoint ec_add(const ECPoint& A, const ECPoint& B) {
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    EC_POINT *pA = EC_POINT_new(grp), *pB = EC_POINT_new(grp), *res = EC_POINT_new(grp);

    EC_POINT_set_affine_coordinates(grp, pA, u256_to_bn(A.x), u256_to_bn(A.y), nullptr);
    EC_POINT_set_affine_coordinates(grp, pB, u256_to_bn(B.x), u256_to_bn(B.y), nullptr);

    EC_POINT_add(grp, res, pA, pB, nullptr);

    BIGNUM *rx = BN_new(), *ry = BN_new();
    EC_POINT_get_affine_coordinates(grp, res, rx, ry, nullptr);

    ECPoint out{bn_to_u256(rx), bn_to_u256(ry), false};

    BN_free(rx); BN_free(ry);
    EC_POINT_free(pA); EC_POINT_free(pB); EC_POINT_free(res);
    EC_GROUP_free(grp);

    return out;
}

ECPoint ec_double(const ECPoint& P) {
    return ec_add(P, P);
}

bool ec_on_curve(const ECPoint& P) {
    EC_GROUP* grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT* pt = EC_POINT_new(grp);

    BIGNUM *x = u256_to_bn(P.x), *y = u256_to_bn(P.y);
    EC_POINT_set_affine_coordinates(grp, pt, x, y, nullptr);

    bool ok = EC_POINT_is_on_curve(grp, pt, nullptr);

    BN_free(x); BN_free(y);
    EC_POINT_free(pt);
    EC_GROUP_free(grp);

    return ok;
}

// ================= SERIALIZATION (RESTORED) =================

std::vector<uint8_t> ec_point_serialize(const ECPoint& P) {
    std::vector<uint8_t> out(65);
    out[0] = 0x04;
    u256_to_bytes(P.x, out.data() + 1);
    u256_to_bytes(P.y, out.data() + 33);
    return out;
}

ECPoint ec_point_deserialize(const std::vector<uint8_t>& data) {
    if (data.size() != 65 || data[0] != 0x04)
        throw std::runtime_error("Invalid point format");

    ECPoint P;
    P.infinity = false;
    P.x = u256_from_bytes(data.data() + 1);
    P.y = u256_from_bytes(data.data() + 33);

    if (!ec_on_curve(P))
        throw std::runtime_error("Point not on curve");

    return P;
}