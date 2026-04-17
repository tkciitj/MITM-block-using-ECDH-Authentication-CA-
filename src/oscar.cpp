// =============================================================================
// oscar.cpp -- Oscar's side of the ECDH-MITM demo (the attacker)
//
// Oscar performs a Man-in-the-Middle attack on ECDH:
//
//   Alice --[9001]--> Oscar --[9003]--> Bob
//
// Oscar listens on port 9001 (impersonating Bob to Alice).
// Oscar connects to port 9003 (impersonating Alice to Bob).
//
// Oscar performs two separate ECDH handshakes:
//   - With Alice: Oscar's ephemeral keypair A  ->  shared_A
//   - With Bob:   Oscar's ephemeral keypair B  ->  shared_B
//
// Oscar then relays and DECRYPTS all messages between Alice and Bob.
//
// In Act 3, Oscar attempts to forge a certificate -- rejected.
// =============================================================================
#include "crypto/ecdh_core.h"
#include "crypto/cert_auth.h"
#include "crypto/aes_gcm.h"
#include "protocol/tcp_channel.h"
#include "protocol/handshake.h"
#include "protocol/messenger.h"
#include "ui/terminal.h"

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>

static const uint16_t OSCAR_LISTENS = 9001;   // Alice connects here
static const uint16_t BOB_PORT      = 9003;   // Bob listens here

// =============================================================================
// Oscar's ASCII banner
// =============================================================================
static void print_oscar_banner() {
    std::cout << "\n";
    std::cout << T::OSCAR << T::BOLD;
    std::cout << "  +============================================================+\n";
    std::cout << "  |                                                            |\n";
    std::cout << "  |    ####   ####   ####     ##     ######           |\n";
    std::cout << "  |   ##  ## ##     ##      ##  ##   ##  ##                   |\n";
    std::cout << "  |   ##  ##  ###   ##      ######   ####                     |\n";
    std::cout << "  |   ##  ##    ##  ##      ##  ##   ##  ##                   |\n";
    std::cout << "  |    ####  ####    ####   ##   ##  ##  ##                   |\n";
    std::cout << "  |                                                            |\n";
    std::cout << "  |           THE MAN-IN-THE-MIDDLE  (Act 2)                  |\n";
    std::cout << "  |                                                            |\n";
    std::cout << "  |  Alice --[9001]--> Oscar --[9003]--> Bob                  |\n";
    std::cout << "  |         intercept <----------------  relay                |\n";
    std::cout << "  |                                                            |\n";
    std::cout << "  +============================================================+\n";
    std::cout << T::RESET << "\n";
}

// =============================================================================
// Wiretap display -- shows direction, ciphertext on wire, plaintext Oscar reads
// =============================================================================
static void wiretap_anim(const std::string& direction,
                          const std::string& plaintext,
                          const std::string& ciphertext_hex) {
    T::sleep_ms(100);
    if (direction == "A->O") {
        std::cout << "\n  " << T::ALICE << "Alice" << T::RESET
                  << T::WIRE  << " -->" << T::RESET
                  << T::OSCAR << " Oscar" << T::RESET
                  << T::WIRE  << " -->" << T::RESET
                  << T::BOB   << " Bob"  << T::RESET << "\n";
    } else {
        std::cout << "\n  " << T::ALICE << "Alice" << T::RESET
                  << T::WIRE  << " <--" << T::RESET
                  << T::OSCAR << " Oscar" << T::RESET
                  << T::WIRE  << " <--" << T::RESET
                  << T::BOB   << " Bob"  << T::RESET << "\n";
    }
    std::cout << "  " << T::DIM    << "  [on wire, enc]: " << T::RESET
              << T::WIRE << ciphertext_hex.substr(0, 48) << "..." << T::RESET << "\n";
    std::cout << "  " << T::DANGER << "  [Oscar reads ]: " << T::RESET
              << T::YELLOW << plaintext << T::RESET << "\n";
    T::sleep_ms(200);
}

// =============================================================================
// main
// =============================================================================
int main(int argc, char** argv) {
    T::enable_vt();

    bool attempted_auth = false;
    for (int i = 1; i < argc; i++)
        if (std::string(argv[i]) == "--auth") attempted_auth = true;

    print_oscar_banner();

    if (attempted_auth) {
        T::section("Act 3 -- Oscar Attempts Authenticated MITM", T::OSCAR);
        std::cout << T::DIM
                  << "\n  Oscar will attempt to forge certificates.\n"
                  << "  Without the CA's private key, his certificates will fail\n"
                  << "  verification. Both Alice and Bob will abort the connection.\n"
                  << T::RESET << "\n";
    } else {
        T::section("Act 2 -- Unauthenticated ECDH MITM", T::OSCAR);
        std::cout << T::DIM
                  << "\n  Oscar intercepts the key exchange between Alice and Bob.\n"
                  << "  He performs two separate ECDH handshakes (one per side).\n"
                  << "  All 'encrypted' messages pass through Oscar in plaintext.\n"
                  << T::RESET << "\n";
    }

    // ── Step 1: Generate two ephemeral keypairs ────────────────────────────────
    T::section("Oscar Generates Two Ephemeral Keypairs", T::OSCAR);
    std::cout << T::DIM
              << "  One keypair per side. Alice and Bob each see a different key.\n\n"
              << T::RESET;

    T::info("Keypair A (presented to Alice, Oscar pretends to be Bob):");
    auto kp_alice = ecdh_generate_keypair(false);
    T::kv("  KP-A fingerprint", kp_alice.fingerprint, T::DIM, T::OSCAR);

    T::info("Keypair B (presented to Bob, Oscar pretends to be Alice):");
    auto kp_bob = ecdh_generate_keypair(false);
    T::kv("  KP-B fingerprint", kp_bob.fingerprint, T::DIM, T::OSCAR);

    std::cout << "\n";
    T::warn("Both Alice and Bob think they are talking directly to each other.");
    T::warn("Neither sees the other's real fingerprint.");

    // ── Step 2: Connect to Bob ────────────────────────────────────────────────
    T::section("Oscar Connects to Bob on Port " + std::to_string(BOB_PORT), T::OSCAR);

    TCPChannel chan_bob;
    int retries = 0;
    while (!chan_bob.connect("127.0.0.1", BOB_PORT, 5)) {
        retries++;
        if (retries > 8) {
            T::warn("Could not reach Bob on port " + std::to_string(BOB_PORT)
                    + ". Is bob.exe running?");
            return 1;
        }
        std::cout << T::DIM << "  Retrying (" << retries << "/8)...\n" << T::RESET;
        T::sleep_ms(800);
    }
    T::ok("Connected to Bob at " + chan_bob.peer_addr());

    // ── Step 3: Listen for Alice ──────────────────────────────────────────────
    T::section("Oscar Listens for Alice on Port " + std::to_string(OSCAR_LISTENS), T::OSCAR);
    T::spinner("Waiting for Alice to connect...", 300);

    TCPChannel chan_alice;
    if (!chan_alice.listen(OSCAR_LISTENS, 60)) {
        T::warn("Failed to bind on port " + std::to_string(OSCAR_LISTENS));
        return 1;
    }
    T::ok("Alice connected from " + chan_alice.peer_addr());

    // ── Step 4: Dual ECDH handshake ───────────────────────────────────────────
    T::section("Performing Dual ECDH Handshake (The Core Attack)", T::OSCAR);

    SessionKey sk_alice, sk_bob;

    if (!attempted_auth) {
        std::string alice_err, bob_err;

        std::thread t_alice([&]() {
            try {
                std::cout << T::OSCAR << "\n  [Side-A]" << T::RESET
                          << " ECDH with Alice (Oscar poses as Bob)...\n";
                sk_alice = handshake_unauthenticated(chan_alice, kp_alice, "Bob", true);
            } catch (const std::exception& e) { alice_err = e.what(); }
        });

        std::thread t_bob([&]() {
            try {
                std::cout << T::OSCAR << "  [Side-B]" << T::RESET
                          << " ECDH with Bob   (Oscar poses as Alice)...\n";
                sk_bob = handshake_unauthenticated(chan_bob, kp_bob, "Alice", false);
            } catch (const std::exception& e) { bob_err = e.what(); }
        });

        t_alice.join();
        t_bob.join();

        if (!alice_err.empty()) { T::warn("Alice-side failed: " + alice_err); return 1; }
        if (!bob_err.empty())   { T::warn("Bob-side failed: "   + bob_err);   return 1; }

    } else {
        // Act 3 -- Oscar tries with forged certs
        T::warn("Oscar is attempting to forge certificates...");
        T::spinner("Generating self-signed cert (no CA private key)...", 800);

        auto fake_ca      = ca_generate();
        Certificate fake_cert_a = ca_issue(fake_ca, "Bob",   kp_alice.public_key);
        Certificate fake_cert_b = ca_issue(fake_ca, "Alice", kp_bob.public_key);

        T::warn("Fake certs created -- but signed with Oscar's own CA, NOT the trusted CA.");
        std::cout << T::DIM
                  << "  Alice and Bob pre-share the REAL CA public key.\n"
                  << "  Oscar's forged signature will fail verification on both sides.\n"
                  << T::RESET << "\n";

        ECPoint dummy_ca_pub{};   // zero point -- verification will fail

        try {
            T::info("Attempting handshake with Alice (cert verification will fail)...");
            sk_alice = handshake_authenticated(chan_alice, kp_alice, fake_cert_a,
                                               "Bob", dummy_ca_pub, true);
        } catch (const std::exception& e) {
            std::cout << "\n  " << T::OSCAR << T::BOLD
                      << "[Side-A RESULT]: " << T::RESET
                      << T::RED << e.what() << T::RESET << "\n\n";
        }

        try {
            T::info("Attempting handshake with Bob (cert verification will fail)...");
            sk_bob = handshake_authenticated(chan_bob, kp_bob, fake_cert_b,
                                             "Alice", dummy_ca_pub, true);
        } catch (const std::exception& e) {
            std::cout << "\n  " << T::OSCAR << T::BOLD
                      << "[Side-B RESULT]: " << T::RESET
                      << T::RED << e.what() << T::RESET << "\n\n";
        }

        T::section("Act 3 Result -- Oscar Defeated", T::GREEN);
        std::cout << "\n";
        T::ok("Certificate authentication stopped Oscar's attack.");
        T::ok("Alice rejected Oscar's cert -- CA signature invalid.");
        T::ok("Bob rejected Oscar's cert   -- CA signature invalid.");
        T::ok("No shared secret established with Oscar. No plaintext leaked.");
        std::cout << "\n";

        std::cout << T::CYAN << T::BOLD;
        std::cout << "  +----------------------------------------------------------+\n";
        std::cout << "  |  ECDH alone: MITM possible (Act 2)                       |\n";
        std::cout << "  |  ECDH + Certificates: MITM impossible (Act 3)            |\n";
        std::cout << "  |  This is the foundation of TLS, Signal, SSH host keys.   |\n";
        std::cout << "  +----------------------------------------------------------+\n";
        std::cout << T::RESET << "\n";
        return 0;
    }

    // ── Step 5: Show dual session keys ────────────────────────────────────────
    T::section("Oscar's Dual Session Keys -- Attack Succeeded", T::OSCAR);
    std::cout << "\n";
    T::kv("Session key (Alice <-> Oscar)", T::to_hex(sk_alice.key, 16) + "...", T::DIM, T::OSCAR);
    T::kv("Session key (Oscar <-> Bob)",   T::to_hex(sk_bob.key,   16) + "...", T::DIM, T::OSCAR);
    std::cout << "\n";
    T::warn("Alice believes she has a direct end-to-end key with Bob. She does NOT.");
    T::warn("Bob believes he has a direct end-to-end key with Alice. He does NOT.");
    T::warn("Oscar decrypts each side, reads the plaintext, and re-encrypts for the other.");

    // ── Step 6: Relay and log all messages ────────────────────────────────────
    T::section("Relaying Messages -- Oscar Reads Everything", T::OSCAR);
    std::cout << T::DIM
              << "  Every message will be decrypted and shown below in plaintext.\n"
              << "  Oscar is the invisible third party in every exchange.\n\n"
              << T::RESET;

    std::atomic<bool> running{true};

    // Alice -> Bob relay
    auto relay_a_to_b = [&]() {
        while (running) {
            try {
                auto packed   = chan_alice.recv_msg();
                auto enc      = aes_gcm_unpack(packed);
                auto pt_bytes = aes_gcm_decrypt(sk_alice.key, enc);
                std::string plaintext(pt_bytes.begin(), pt_bytes.end());
                std::string hex_prev = T::to_hex(
                    std::vector<uint8_t>(packed.begin(), packed.end()), 16);
                wiretap_anim("A->O", plaintext, hex_prev);
                auto re_enc  = aes_gcm_encrypt(sk_bob.key, pt_bytes);
                auto re_pack = aes_gcm_pack(re_enc);
                chan_bob.send_msg(re_pack);
            } catch (...) { running = false; }
        }
    };

    // Bob -> Alice relay
    auto relay_b_to_a = [&]() {
        while (running) {
            try {
                auto packed   = chan_bob.recv_msg();
                auto enc      = aes_gcm_unpack(packed);
                auto pt_bytes = aes_gcm_decrypt(sk_bob.key, enc);
                std::string plaintext(pt_bytes.begin(), pt_bytes.end());
                std::string hex_prev = T::to_hex(
                    std::vector<uint8_t>(packed.begin(), packed.end()), 16);
                wiretap_anim("B->O", plaintext, hex_prev);
                auto re_enc  = aes_gcm_encrypt(sk_alice.key, pt_bytes);
                auto re_pack = aes_gcm_pack(re_enc);
                chan_alice.send_msg(re_pack);
            } catch (...) { running = false; }
        }
    };

    std::thread t1(relay_a_to_b);
    std::thread t2(relay_b_to_a);
    t1.join();
    t2.join();

    T::section("Oscar Session Ended", T::OSCAR);
    std::cout << T::DIM
              << "\n  All messages were intercepted, read, and relayed by Oscar.\n"
              << "  Alice and Bob communicated normally -- completely unaware.\n"
              << T::RESET << "\n";
    return 0;
}