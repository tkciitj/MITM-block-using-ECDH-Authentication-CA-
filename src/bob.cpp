// ─────────────────────────────────────────────────────────────────────────────
// bob.cpp — Bob's side of the ECDH-MITM demo
//
// Usage:
//   bob [--auth]   Act 1/2 (unauthenticated) or Act 3 (authenticated)
//
// Bob listens on port 9003.
// In Act 1: Alice connects directly to Bob (port 9003).
// In Act 2: Oscar connects to Bob (port 9003) on behalf of Alice.
// In Act 3: Authenticated — Oscar is rejected.
//
// CRITICAL ORDER: Bob must call chan.listen() BEFORE generating the keypair.
// Reason: Alice connects and then immediately blocks in recv_msg() waiting for
// Bob's hello. If Bob generates his keypair (which takes ~1-2s with spinners)
// BEFORE accepting Alice's connection, Alice's recv could time out.
// By accepting first, the TCP connection is established immediately, and Bob
// can then take as long as needed to generate keys before sending his hello —
// because now there is no timeout on the data socket.
// ─────────────────────────────────────────────────────────────────────────────
#include "crypto/ecdh_core.h"
#include "crypto/cert_auth.h"
#include "crypto/aes_gcm.h"
#include "protocol/tcp_channel.h"
#include "protocol/handshake.h"
#include "protocol/messenger.h"
#include "ui/terminal.h"

#include <iostream>
#include <fstream>
#include <string>

static const uint16_t BOB_PORT = 9003;

int main(int argc, char** argv) {
    T::enable_vt();

    bool authenticated = false;
    for (int i = 1; i < argc; i++)
        if (std::string(argv[i]) == "--auth") authenticated = true;

    // ── Banner ────────────────────────────────────────────────────────────────
    T::role_banner(
        "BOB  (receiver)",
        authenticated ? "Act 3: Authenticated ECDH" : "Act 1/2: Unauthenticated ECDH",
        T::BOB
    );

    if (!authenticated) {
        T::section("Act 1/2 — ECDH Key Exchange", T::BOB);
        std::cout << T::DIM
                  << "\n  Bob listens on port " << BOB_PORT << ".\n"
                  << "  In Act 1: Alice connects here directly.\n"
                  << "  In Act 2: Oscar (MITM) connects here, relaying Alice's session.\n"
                  << T::RESET << "\n";
    } else {
        T::section("Act 3 — Authenticated ECDH (MITM Defeated)", T::GREEN);
        std::cout << T::DIM
                  << "\n  Bob will verify the peer's certificate before trusting their key.\n"
                  << "  Oscar cannot forge a valid CA-signed certificate — attack fails.\n"
                  << T::RESET << "\n";
    }

    // ── STEP 1: Accept connection FIRST ───────────────────────────────────────
    // IMPORTANT: We listen and accept BEFORE generating the keypair.
    // This ensures the TCP handshake completes immediately when Alice connects.
    // Alice will block in recv_msg() waiting for our hello — but since there is
    // no timeout on the data socket, she waits indefinitely. We then generate
    // our key and send the hello at our own pace.
    T::section("Listening on port " + std::to_string(BOB_PORT), T::BOB);
    T::spinner("Waiting for connection...", 300);

    TCPChannel chan;
    if (!chan.listen(BOB_PORT, 120)) {
        T::warn("Failed to bind on port " + std::to_string(BOB_PORT) +
                ". Is another process using it?");
        return 1;
    }
    T::ok("Connection accepted from " + chan.peer_addr());

    // ── STEP 2: Generate keypair AFTER accepting ───────────────────────────────
    // Now that Alice is connected and waiting, we generate our keypair.
    // Alice is blocked in recv_msg() with no timeout — she waits as long as needed.
    T::section("Generating Bob's P-256 Keypair", T::BOB);
    auto kp = ecdh_generate_keypair(true);

    std::cout << "\n";
    T::kv("Bob public key x", u256_to_hex(kp.public_key.x).substr(0,32) + "...", T::DIM, T::CYAN);
    T::kv("Bob public key y", u256_to_hex(kp.public_key.y).substr(0,32) + "...", T::DIM, T::CYAN);
    T::kv("Bob fingerprint",  kp.fingerprint, T::DIM, T::YELLOW);

    if (!ec_on_curve(kp.public_key)) {
        T::warn("Generated public key is NOT on the curve! Bug in ecc_math.cpp");
        return 1;
    }
    T::ok("Public key validated — lies on P-256 curve");

    // ── STEP 3: CA cert (Act 3 only) ──────────────────────────────────────────
    Certificate bob_cert;
    ECPoint ca_pub{};
    std::string ca_file     = std::string(DATA_DIR) + "/ca_key.hex";
    std::string ca_pub_file = std::string(DATA_DIR) + "/ca_pub.hex";

    if (authenticated) {
        T::section("Loading CA and obtaining Bob's Certificate", T::GREEN);
        T::spinner("Loading CA keypair from " + ca_file, 400);
        auto ca = ca_generate(ca_file);
        ca_pub  = ca.public_key;

        std::ifstream cpf(ca_pub_file);
        if (cpf.is_open()) {
            std::string xhex, yhex;
            cpf >> xhex >> yhex;
            ca_pub.x        = u256_from_hex(xhex);
            ca_pub.y        = u256_from_hex(yhex);
            ca_pub.infinity = false;
        }

        T::spinner("CA signing Bob's public key...", 500);
        bob_cert = ca_issue(ca, "Bob", kp.public_key);
        T::ok("Bob's certificate issued by CA");
        T::kv("Cert fingerprint", bob_cert.fingerprint, T::DIM, T::GREEN);
    }

    // ── STEP 4: Handshake ─────────────────────────────────────────────────────
    T::section("ECDH Handshake", T::BOB);
    SessionKey sk;

    try {
        if (!authenticated) {
            sk = handshake_unauthenticated(chan, kp, "Bob", true);
        } else {
            sk = handshake_authenticated(chan, kp, bob_cert, "Bob", ca_pub, true);
        }
    } catch (const std::exception& e) {
        std::cout << "\n" << T::RED << T::BOLD << "  HANDSHAKE FAILED:\n  "
                  << e.what() << T::RESET << "\n";
        return 1;
    }

    // ── STEP 5: Show fingerprint ───────────────────────────────────────────────
    T::section("Security Verification", T::BOB);
    std::cout << "\n";
    T::kv("Bob's fingerprint",   kp.fingerprint,      T::DIM, T::YELLOW);
    T::kv("Peer's fingerprint",  sk.peer_fingerprint, T::DIM, T::YELLOW);

    if (!authenticated) {
        std::cout << "\n  " << T::DIM
                  << "In Act 1: Bob sees Alice's real fingerprint.\n"
                  << "In Act 2: Bob sees Oscar's fingerprint (not Alice's!).\n"
                  << "          Compare manually — mismatch = MITM.\n"
                  << T::RESET << "\n";
    } else {
        T::ok("Certificate-based authentication — fingerprint guaranteed by CA");
    }

    // ── STEP 6: Encrypted chat ────────────────────────────────────────────────
    T::section("Encrypted Chat — AES-256-GCM", T::BOB);
    std::cout << T::DIM
              << "  Messages are encrypted before leaving Bob's machine.\n"
              << "  Oscar (if present) sees only ciphertext.\n\n" << T::RESET;

    Messenger m(chan, sk.key, "Bob", sk.peer_identity);
    m.chat_loop();

    std::cout << T::DIM << "\n  Bob session ended.\n" << T::RESET;
    return 0;
}