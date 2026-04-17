#include "messenger.h"
#include "../ui/terminal.h"
#include <iostream>
#include <thread>
#include <atomic>
#include <stdexcept>

Messenger::Messenger(TCPChannel& chan,
                     const std::vector<uint8_t>& session_key,
                     const std::string& our_name,
                     const std::string& peer_name)
    : chan_(chan), key_(session_key),
      our_name_(our_name), peer_name_(peer_name) {}

bool Messenger::send(const std::string& plaintext) {
    std::vector<uint8_t> pt(plaintext.begin(), plaintext.end());
    auto enc = aes_gcm_encrypt(key_, pt);
    auto packed = aes_gcm_pack(enc);
    return chan_.send_msg(packed);
}

std::string Messenger::recv() {
    auto packed = chan_.recv_msg();
    auto enc    = aes_gcm_unpack(packed);
    auto pt     = aes_gcm_decrypt(key_, enc);
    return std::string(pt.begin(), pt.end());
}

void Messenger::chat_loop(std::function<void(const std::string&)> on_recv) {
    T::sep();
    std::cout << T::DIM << "  Type messages and press Enter. Ctrl+C to exit.\n"
              << "  Messages are encrypted with AES-256-GCM.\n" << T::RESET;
    T::sep();

    std::atomic<bool> running{true};

    // Receive thread — continuously listens for incoming messages
    std::thread recv_thread([&]() {
        while (running) {
            try {
                std::string msg = recv();
                const char* nc = (peer_name_ == "Alice") ? T::ALICE :
                                 (peer_name_ == "Bob")   ? T::BOB   : T::OSCAR;
                std::cout << "\r  " << nc << peer_name_ << T::RESET
                          << T::DIM << ": " << T::RESET
                          << T::WHITE << msg << T::RESET << "\n  > " << std::flush;
                if (on_recv) on_recv(msg);
            } catch (...) {
                running = false;
            }
        }
    });

    // Send loop — reads from stdin
    const char* oc = (our_name_ == "Alice") ? T::ALICE :
                     (our_name_ == "Bob")   ? T::BOB   : T::OSCAR;
    while (running) {
        std::cout << "  " << oc << our_name_ << T::RESET << T::DIM << " > " << T::RESET;
        std::string line;
        if (!std::getline(std::cin, line) || !running) break;
        if (line.empty()) continue;
        if (line == "/quit" || line == "/exit") break;
        if (!send(line)) { std::cout << T::RED << "  Send failed.\n" << T::RESET; break; }
    }

    running = false;
    chan_.close();
    if (recv_thread.joinable()) recv_thread.join();
}
