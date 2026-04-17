// ─────────────────────────────────────────────────────────────────────────────
// alice.cpp — Alice's side of the ECDH demo
//
// Usage:
//   alice.exe          Act 1/2: unauthenticated ECDH
//   alice.exe --auth   Act 3:   authenticated ECDH
//
// Alice connects to port 9003 (Bob direct in Act 1/3, Oscar in Act 2).
//
// ORDER OF OPERATIONS (important for correct timing):
//   1. Generate keypair first (before connecting) — so Alice is ready
//      to send immediately after the TCP connection is established.
//   2. Connect with retry loop — Bob may still be starting up.
//   3. Send our hello immediately after connecting.
//   4. recv_msg() blocks indefinitely (no timeout) waiting for Bob's hello.
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

static const uint16_t PEER_PORT = 9001;

int main(int argc, char** argv) {
    T::enable_vt();

    bool authenticated = false;
    for (int i = 1; i < argc; i++)
        if (std::string(argv[i]) == "--auth") authenticated = true;

    // ── Banner ────────────────────────────────────────────────────────────────
    T::role_banner(
        "ALICE  (sender)",
        authenticated ? "Act 3: Authenticated ECDH" : "Act 1/2: Unauthenticated ECDH",
        T::ALICE
    );

    if (!authenticated) {
        T::section("Act 1/2 — ECDH Key Exchange", T::ALICE);
        std::cout << T::DIM
                  << "\n  Alice connects to port " << PEER_PORT << ".\n"
                  << "  Act 1: Bob listens there directly (run bob.exe first).\n"
                  << "  Act 2: Oscar listens there (run oscar.exe first, then bob.exe).\n"
                  << T::RESET << "\n";
    } else {
        T::section("Act 3 — Authenticated ECDH (MITM defeated)", T::GREEN);
        std::cout << T::DIM
                  << "\n  Alice verifies Bob's certificate before trusting his key.\n"
                  << "  Oscar cannot forge a valid CA-signed certificate.\n"
                  << T::RESET << "\n";
    }

    // ── STEP 1: Generate keypair BEFORE connecting ────────────────────────────
    // Alice generates her key first so she is fully prepared to send her hello
    // the moment the TCP connection is accepted by Bob. This way the only
    // time Bob has to wait for Alice's hello is the ~0ms it takes to send().
    T::section("Generating Alice's P-256 keypair", T::ALICE);
    auto kp = ecdh_generate_keypair(true);

    std::cout << "\n";
    T::kv("Alice public key x", u256_to_hex(kp.public_key.x).substr(0,32) + "...", T::DIM, T::CYAN);
    T::kv("Alice public key y", u256_to_hex(kp.public_key.y).substr(0,32) + "...", T::DIM, T::CYAN);
    T::kv("Alice fingerprint",  kp.fingerprint, T::DIM, T::YELLOW);

    if (!ec_on_curve(kp.public_key)) {
        T::warn("Generated public key is NOT on the curve! Bug in ecc_math.cpp");
        return 1;
    }
    T::ok("Public key validated — lies on P-256 curve");

    // ── STEP 2: Load/create CA cert (Act 3 only) ──────────────────────────────
    Certificate alice_cert;
    ECPoint ca_pub{};
    std::string ca_file     = std::string(DATA_DIR) + "/ca_key.hex";
    std::string ca_pub_file = std::string(DATA_DIR) + "/ca_pub.hex";

    if (authenticated) {
        T::section("Loading CA and obtaining Alice's certificate", T::GREEN);
        T::spinner("Loading CA keypair from " + ca_file, 400);
        auto ca = ca_generate(ca_file);
        ca_pub  = ca.public_key;

        std::ofstream cpf(ca_pub_file);
        cpf << u256_to_hex(ca_pub.x) << "\n" << u256_to_hex(ca_pub.y) << "\n";

        T::spinner("CA signing Alice's public key...", 500);
        alice_cert = ca_issue(ca, "Alice", kp.public_key);
        T::ok("Alice's certificate issued by CA");
        T::kv("Cert fingerprint", alice_cert.fingerprint, T::DIM, T::GREEN);
    }

    // ── STEP 3: Connect to peer ───────────────────────────────────────────────
    // Retry loop: Bob may still be starting up when Alice runs.
    // We try every 1 second for up to 30 attempts (30 seconds total).
    // No timeout is set on the socket — once connected, recv blocks forever.
    T::section("Connecting to peer on port " + std::to_string(PEER_PORT), T::ALICE);

    TCPChannel chan;
    int retries = 0;
    bool connected = false;

    std::cout << "  " << T::DIM << "Attempting connection (will retry for up to 30s)...\n"
              << T::RESET;

    while (retries < 30) {
        if (chan.connect("127.0.0.1", PEER_PORT)) {
            connected = true;
            break;
        }
        retries++;
        std::cout << "\r  " << T::DIM << "Waiting for peer... (" << retries << "/30)  "
                  << T::RESET << std::flush;
        T::sleep_ms(1000);
    }

    if (!connected) {
        std::cout << "\n";
        T::warn("Could not connect after 30 attempts.");
        T::warn("Make sure bob.exe (Act 1/3) or oscar.exe (Act 2) is running first.");
        return 1;
    }

    std::cout << "\n";
    T::ok("Connected to " + chan.peer_addr());

    // ── STEP 4: Handshake ─────────────────────────────────────────────────────
    T::section("ECDH Handshake", T::ALICE);
    SessionKey sk;

    try {
        if (!authenticated) {
            sk = handshake_unauthenticated(chan, kp, "Alice", true);
        } else {
            sk = handshake_authenticated(chan, kp, alice_cert, "Alice", ca_pub, true);
        }
    } catch (const std::exception& e) {
        std::cout << "\n" << T::RED << T::BOLD << "  HANDSHAKE FAILED:\n  "
                  << e.what() << T::RESET << "\n";
        return 1;
    }

    // ── STEP 5: Show fingerprint comparison ───────────────────────────────────
    T::section("Security Verification", T::ALICE);
    std::cout << "\n";
    T::kv("Alice's fingerprint", kp.fingerprint,      T::DIM, T::YELLOW);
    T::kv("Bob's fingerprint",   sk.peer_fingerprint, T::DIM, T::YELLOW);

    if (!authenticated) {
        std::cout << "\n  " << T::DIM
                  << "Act 1 (no Oscar): both fingerprints match what Bob shows.\n"
                  << "Act 2 (with Oscar): Alice sees Oscar's fingerprint, NOT Bob's.\n"
                  << "  Compare manually — a mismatch means MITM attack.\n"
                  << T::RESET << "\n";
    } else {
        T::ok("Certificate-based authentication — fingerprint guaranteed by CA");
    }

    // ── STEP 6: Encrypted chat ────────────────────────────────────────────────
    T::section("Encrypted Chat — AES-256-GCM", T::ALICE);
    std::cout << T::DIM
              << "  Messages are encrypted before leaving Alice's machine.\n"
              << "  Oscar (if present) sees only ciphertext.\n\n" << T::RESET;

    Messenger m(chan, sk.key, "Alice", sk.peer_identity);
    m.chat_loop();

    std::cout << T::DIM << "\n  Alice session ended.\n" << T::RESET;
    return 0;
}