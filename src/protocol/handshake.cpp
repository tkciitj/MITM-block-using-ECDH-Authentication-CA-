#include "handshake.h"
#include "../ui/terminal.h"
#include "../crypto/aes_gcm.h"
#include <stdexcept>
#include <algorithm>

// ─────────────────────────────────────────────────────────────────────────────
// WIRE FORMAT — unauthenticated HELLO:
//
//   [1 byte : identity_len]
//   [identity_len bytes : identity string e.g. "Alice"]
//   [65 bytes : uncompressed EC public key (0x04 || x || y)]
//
// WHY THIS FORMAT:
//   The original code used colon-delimited parsing ("HELLO:Alice:<pubkey>")
//   but searched for the second ':' only in the first 30 bytes of the message.
//   Since "HELLO:Alice:" is 12 chars, the next 18 bytes are BINARY public key
//   data. Any byte valued 0x3A (':') in those 18 bytes was misidentified as
//   the delimiter, causing ec_point_deserialize to receive garbage bytes and
//   throw "Connection closed during recv".
//
//   A length-prefixed format has zero ambiguity — the identity length is
//   explicit, so we always know exactly where the binary key starts.
//
// WIRE FORMAT — authenticated HELLO_AUTH:
//
//   [1 byte : identity_len]
//   [identity_len bytes : identity string]
//   [65 bytes : EC public key]
//   [4 bytes LE : cert_len]
//   [cert_len bytes : serialized certificate]
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// SESSION KEY LABEL — BUG FIX #2
//
// Original code:
//   Alice builds label: "Alice-Bob-session"
//   Bob   builds label: "Bob-Alice-session"
//   These are DIFFERENT strings → HKDF produces DIFFERENT 32-byte keys.
//   Every encrypted message was unreadable by the other side.
//
// Fix: always sort the two identities alphabetically before building the label.
//   "Alice" < "Bob" → both sides produce "Alice-Bob-session" consistently.
// ─────────────────────────────────────────────────────────────────────────────
static std::string make_session_label(const std::string& id1,
                                       const std::string& id2,
                                       bool authenticated) {
    std::string a = id1, b = id2;
    if (a > b) std::swap(a, b);
    return a + "-" + b + (authenticated ? "-auth-session" : "-session");
}

// ─────────────────────────────────────────────────────────────────────────────
// handshake_unauthenticated
// ─────────────────────────────────────────────────────────────────────────────
SessionKey handshake_unauthenticated(
    TCPChannel& chan,
    const ECDHKeyPair& our_kp,
    const std::string& our_identity,
    bool verbose)
{
    if (verbose) {
        T::sep();
        T::info("Starting ECDH key exchange (unauthenticated)");
    }

    // ── Build and send our HELLO ──────────────────────────────────────────────
    auto pub_bytes = ec_point_serialize(our_kp.public_key);  // always 65 bytes

    std::vector<uint8_t> msg;
    uint8_t id_len = (uint8_t)our_identity.size();
    msg.push_back(id_len);
    msg.insert(msg.end(), our_identity.begin(), our_identity.end());
    msg.insert(msg.end(), pub_bytes.begin(), pub_bytes.end());

    if (verbose) T::packet_anim(our_identity, "peer");
    chan.send_msg(msg);

    // ── Receive and parse peer's HELLO ────────────────────────────────────────
    auto peer_msg = chan.recv_msg();

    if (peer_msg.size() < 1 + 1 + 65)
        throw std::runtime_error("HELLO message too short");

    size_t pos = 0;
    uint8_t peer_id_len = peer_msg[pos++];

    if (pos + peer_id_len + 65 > peer_msg.size())
        throw std::runtime_error("HELLO message truncated — identity/key boundary wrong");

    std::string peer_identity(peer_msg.begin() + pos,
                               peer_msg.begin() + pos + peer_id_len);
    pos += peer_id_len;

    // Read exactly 65 bytes of public key — no colon scanning, no guessing
    std::vector<uint8_t> peer_pub_bytes(peer_msg.begin() + pos,
                                         peer_msg.begin() + pos + 65);

    if (verbose) T::packet_anim("peer", our_identity);

    ECPoint peer_pub = ec_point_deserialize(peer_pub_bytes);
    std::string peer_fp = ecdh_fingerprint(peer_pub);

    if (verbose) {
        T::kv("Peer identity",    peer_identity,      T::DIM, T::CYAN);
        T::kv("Peer fingerprint", peer_fp,             T::DIM, T::YELLOW);
        T::kv("Our fingerprint",  our_kp.fingerprint, T::DIM, T::YELLOW);
    }

    // ── Derive shared secret ──────────────────────────────────────────────────
    auto raw_secret = ecdh_shared_secret(our_kp.private_key, peer_pub, verbose);

    // Canonical label: alphabetically sorted identities — BOTH SIDES MATCH
    std::string label = make_session_label(our_identity, peer_identity, false);
    auto session_key  = ecdh_derive_key(raw_secret, label);

    if (verbose) {
        T::kv("HKDF label",  label,                               T::DIM, T::DIM);
        T::kv("Session key", T::to_hex(session_key, 16) + "...", T::DIM, T::CRYPTO);
        T::secure_established();
    }

    return SessionKey{session_key, peer_identity, peer_fp, false};
}

// ─────────────────────────────────────────────────────────────────────────────
// handshake_authenticated
// ─────────────────────────────────────────────────────────────────────────────
SessionKey handshake_authenticated(
    TCPChannel& chan,
    const ECDHKeyPair& our_kp,
    const Certificate& our_cert,
    const std::string& our_identity,
    const ECPoint& ca_public_key,
    bool verbose)
{
    if (verbose) {
        T::sep();
        T::info("Starting authenticated ECDH handshake (Act 3)");
    }

    // ── Build and send HELLO_AUTH ─────────────────────────────────────────────
    auto pub_bytes  = ec_point_serialize(our_kp.public_key);
    auto cert_bytes = cert_serialize(our_cert);

    std::vector<uint8_t> msg;
    uint8_t id_len = (uint8_t)our_identity.size();
    msg.push_back(id_len);
    msg.insert(msg.end(), our_identity.begin(), our_identity.end());
    msg.insert(msg.end(), pub_bytes.begin(), pub_bytes.end());

    uint32_t cert_len = (uint32_t)cert_bytes.size();
    for (int i = 0; i < 4; i++) msg.push_back((cert_len >> (i*8)) & 0xFF);
    msg.insert(msg.end(), cert_bytes.begin(), cert_bytes.end());

    if (verbose) {
        T::info("Sending certificate to peer...");
        T::packet_anim(our_identity, "peer");
    }
    chan.send_msg(msg);

    // ── Receive and parse peer's HELLO_AUTH ───────────────────────────────────
    auto peer_msg = chan.recv_msg();

    if (peer_msg.size() < 1 + 1 + 65 + 4)
        throw std::runtime_error("HELLO_AUTH message too short");

    size_t pos = 0;
    uint8_t peer_id_len = peer_msg[pos++];

    if (pos + peer_id_len + 65 + 4 > peer_msg.size())
        throw std::runtime_error("HELLO_AUTH message truncated");

    std::string peer_identity(peer_msg.begin() + pos,
                               peer_msg.begin() + pos + peer_id_len);
    pos += peer_id_len;

    std::vector<uint8_t> peer_pub_bytes(peer_msg.begin() + pos,
                                         peer_msg.begin() + pos + 65);
    pos += 65;

    uint32_t p_cert_len = peer_msg[pos]
                        | ((uint32_t)peer_msg[pos+1] << 8)
                        | ((uint32_t)peer_msg[pos+2] << 16)
                        | ((uint32_t)peer_msg[pos+3] << 24);
    pos += 4;

    if (pos + p_cert_len > peer_msg.size())
        throw std::runtime_error("HELLO_AUTH: cert_len exceeds message size");

    std::vector<uint8_t> peer_cert_bytes(peer_msg.begin() + pos,
                                          peer_msg.begin() + pos + p_cert_len);

    if (verbose) {
        T::packet_anim("peer", our_identity);
        T::info("Verifying peer certificate against CA...");
    }

    // ── Verify certificate ────────────────────────────────────────────────────
    Certificate peer_cert = cert_deserialize(peer_cert_bytes);
    bool cert_ok = ca_verify(peer_cert, ca_public_key);

    if (!cert_ok) {
        T::attack_detected();
        throw std::runtime_error(
            "CERTIFICATE VERIFICATION FAILED for '" + peer_identity + "'!\n"
            "  The peer's public key is NOT signed by the trusted CA.\n"
            "  Oscar cannot forge a valid certificate — connection ABORTED.\n"
            "  This is Act 3: authentication defeats the MITM attack."
        );
    }

    if (verbose) {
        T::ok("Certificate signature verified against CA public key");
        T::kv("Peer identity",    peer_cert.identity,    T::DIM, T::GREEN);
        T::kv("Peer fingerprint", peer_cert.fingerprint, T::DIM, T::YELLOW);
    }

    ECPoint peer_pub = ec_point_deserialize(peer_pub_bytes);

    auto cert_pub_point = ec_point_deserialize(peer_cert.public_key_bytes);
    if (cert_pub_point != peer_pub)
        throw std::runtime_error(
            "Certificate key does not match transmitted key — MITM substitution detected!");

    // ── Derive shared secret and session key ──────────────────────────────────
    auto raw_secret  = ecdh_shared_secret(our_kp.private_key, peer_pub, verbose);
    std::string label = make_session_label(our_identity, peer_identity, true);
    auto session_key  = ecdh_derive_key(raw_secret, label);

    if (verbose) {
        T::kv("HKDF label",  label,                               T::DIM, T::DIM);
        T::kv("Session key", T::to_hex(session_key, 16) + "...", T::DIM, T::CRYPTO);
        T::secure_established();
    }

    return SessionKey{session_key, peer_identity, peer_cert.fingerprint, true};
}