#include "aes_gcm.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

AESGCMResult aes_gcm_encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& plaintext)
{
    if (key.size() != 32) throw std::runtime_error("AES-256 requires 32-byte key");

    AESGCMResult result;

    // Generate fresh 12-byte random IV (NIST recommended size for GCM)
    result.iv.resize(12);
    if (RAND_bytes(result.iv.data(), 12) != 1)
        throw std::runtime_error("RAND_bytes failed for IV");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    // Initialize AES-256-GCM encryption
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    // Set key and IV
    if (!EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex (key/iv) failed");
    }

    result.ciphertext.resize(plaintext.size());
    int out_len = 0;

    if (!EVP_EncryptUpdate(ctx, result.ciphertext.data(), &out_len,
                           plaintext.data(), (int)plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    int final_len = 0;
    if (!EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + out_len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    result.ciphertext.resize(out_len + final_len);

    // Extract authentication tag (16 bytes)
    result.auth_tag.resize(16);
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.auth_tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

std::vector<uint8_t> aes_gcm_decrypt(
    const std::vector<uint8_t>& key,
    const AESGCMResult& r)
{
    if (key.size() != 32) throw std::runtime_error("AES-256 requires 32-byte key");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) ||
        !EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), r.iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    // Set expected authentication tag BEFORE decrypting
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                              (void*)r.auth_tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");
    }

    std::vector<uint8_t> plaintext(r.ciphertext.size());
    int out_len = 0;

    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                           r.ciphertext.data(), (int)r.ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    int final_len = 0;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    // EVP_DecryptFinal_ex returns <= 0 if the auth tag doesn't match
    if (ret <= 0)
        throw std::runtime_error("AES-GCM authentication FAILED — message tampered!");

    plaintext.resize(out_len + final_len);
    return plaintext;
}

std::vector<uint8_t> aes_gcm_pack(const AESGCMResult& r) {
    // Format: [4 bytes ct_len LE][ciphertext][12 bytes iv][16 bytes tag]
    std::vector<uint8_t> out;
    uint32_t ct_len = (uint32_t)r.ciphertext.size();
    out.push_back(ct_len & 0xFF);
    out.push_back((ct_len >> 8) & 0xFF);
    out.push_back((ct_len >> 16) & 0xFF);
    out.push_back((ct_len >> 24) & 0xFF);
    out.insert(out.end(), r.ciphertext.begin(), r.ciphertext.end());
    out.insert(out.end(), r.iv.begin(), r.iv.end());
    out.insert(out.end(), r.auth_tag.begin(), r.auth_tag.end());
    return out;
}

AESGCMResult aes_gcm_unpack(const std::vector<uint8_t>& data) {
    if (data.size() < 32) throw std::runtime_error("Packed AES-GCM data too short");
    AESGCMResult r;
    uint32_t ct_len = data[0] | ((uint32_t)data[1]<<8) | ((uint32_t)data[2]<<16) | ((uint32_t)data[3]<<24);
    if (4 + ct_len + 12 + 16 > data.size()) throw std::runtime_error("Malformed packed data");
    r.ciphertext.assign(data.begin()+4, data.begin()+4+ct_len);
    r.iv.assign(data.begin()+4+ct_len, data.begin()+4+ct_len+12);
    r.auth_tag.assign(data.begin()+4+ct_len+12, data.begin()+4+ct_len+28);
    return r;
}
