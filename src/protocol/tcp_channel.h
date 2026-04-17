#pragma once
#include <string>
#include <vector>
#include <cstdint>

// ─────────────────────────────────────────────────────────────────────────────
// TCP channel with framed read/write.
// Each message is prefixed with a 4-byte little-endian length field.
// This handles TCP's stream nature — recv() may return partial data.
// ─────────────────────────────────────────────────────────────────────────────

class TCPChannel {
public:
    TCPChannel();
    ~TCPChannel();

    // Server: bind and wait for one connection
    bool listen(uint16_t port, int timeout_s = 30);

    // Client: connect to server
    bool connect(const std::string& host, uint16_t port, int timeout_s = 10);

    // Send framed message (4-byte length prefix + data)
    bool send_msg(const std::vector<uint8_t>& data);
    bool send_msg(const std::string& s);

    // Receive framed message. Blocks until full message arrives.
    std::vector<uint8_t> recv_msg();

    bool is_connected() const { return connected_; }
    void close();

    // Peer address for display
    std::string peer_addr() const { return peer_addr_; }

private:
    int  sock_fd_   = -1;
    int  listen_fd_ = -1;
    bool connected_ = false;
    std::string peer_addr_;

    bool recv_exact(uint8_t* buf, size_t n);
};
