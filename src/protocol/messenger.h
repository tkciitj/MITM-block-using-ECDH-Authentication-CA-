#pragma once
#include "tcp_channel.h"
#include "../crypto/aes_gcm.h"
#include <string>
#include <vector>
#include <functional>

// ─────────────────────────────────────────────────────────────────────────────
// Messenger — encrypted message send/receive over an established session.
// Uses AES-256-GCM with a fresh random IV per message.
// ─────────────────────────────────────────────────────────────────────────────

class Messenger {
public:
    Messenger(TCPChannel& chan,
              const std::vector<uint8_t>& session_key,
              const std::string& our_name,
              const std::string& peer_name);

    // Send a plaintext string — encrypts and transmits
    bool send(const std::string& plaintext);

    // Receive and decrypt — returns plaintext
    // Throws on decryption failure (auth tag mismatch = tampered)
    std::string recv();

    // Interactive chat loop — reads from stdin, sends, receives in parallel
    // on_recv is called when a message arrives
    void chat_loop(std::function<void(const std::string&)> on_recv = nullptr);

private:
    TCPChannel&           chan_;
    std::vector<uint8_t>  key_;
    std::string           our_name_;
    std::string           peer_name_;
    uint64_t              send_counter_ = 0;
    uint64_t              recv_counter_ = 0;
};
