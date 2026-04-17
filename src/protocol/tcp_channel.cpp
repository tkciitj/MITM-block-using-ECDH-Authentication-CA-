#include "tcp_channel.h"
#include <stdexcept>
#include <cstring>
#include <iostream>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  using sock_t = SOCKET;
  #define INVALID_SOCK INVALID_SOCKET
  #define CLOSE_SOCK(s) closesocket(s)
  #define SOCK_ERR WSAGetLastError()
  static bool wsa_init_done = false;
  static void wsa_init() {
      if (!wsa_init_done) {
          WSADATA d; WSAStartup(MAKEWORD(2,2), &d);
          wsa_init_done = true;
      }
  }
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <errno.h>
  using sock_t = int;
  #define INVALID_SOCK (-1)
  #define CLOSE_SOCK(s) ::close(s)
  #define SOCK_ERR errno
  static void wsa_init() {}
#endif

TCPChannel::TCPChannel() { wsa_init(); }
TCPChannel::~TCPChannel() { close(); }

bool TCPChannel::listen(uint16_t port, int timeout_s) {
    wsa_init();
    listen_fd_ = (int)::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ == (int)INVALID_SOCK) return false;

    int opt = 1;
    setsockopt((sock_t)listen_fd_, SOL_SOCKET, SO_REUSEADDR,
               (const char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (::bind((sock_t)listen_fd_, (sockaddr*)&addr, sizeof(addr)) < 0)
        return false;
    if (::listen((sock_t)listen_fd_, 1) < 0)
        return false;

    // Timeout applies only to the accept() call itself.
    struct timeval tv{};
    tv.tv_sec = timeout_s;
    setsockopt((sock_t)listen_fd_, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&tv, sizeof(tv));

    sockaddr_in peer{};
#ifdef _WIN32
    int peer_len = sizeof(peer);
#else
    socklen_t peer_len = sizeof(peer);
#endif
    sock_t client = ::accept((sock_t)listen_fd_, (sockaddr*)&peer, &peer_len);
    if (client == INVALID_SOCK) return false;

    sock_fd_   = (int)client;
    connected_ = true;

    // CRITICAL FIX: set NO timeout on the accepted data socket.
    // The old code accidentally inherited or left a timeout, causing recv_msg()
    // in the handshake and chat to fail after a few seconds.
    struct timeval no_timeout{};
    no_timeout.tv_sec  = 0;
    no_timeout.tv_usec = 0;
    setsockopt((sock_t)sock_fd_, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&no_timeout, sizeof(no_timeout));
    setsockopt((sock_t)sock_fd_, SOL_SOCKET, SO_SNDTIMEO,
               (const char*)&no_timeout, sizeof(no_timeout));

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
    peer_addr_ = std::string(ip) + ":" + std::to_string(ntohs(peer.sin_port));
    return true;
}

bool TCPChannel::connect(const std::string& host, uint16_t port, int timeout_s) {
    wsa_init();
    sock_fd_ = (int)::socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd_ == (int)INVALID_SOCK) return false;

    // CRITICAL FIX: do NOT set SO_RCVTIMEO here.
    // The old code set SO_RCVTIMEO = timeout_s (5 seconds) which then applied
    // to EVERY recv() call on this socket forever — including the handshake recv
    // and all chat messages. If Bob took more than 5 seconds to generate his key
    // and respond, Alice's recv timed out with "Connection closed during recv".
    // timeout_s is kept in the signature for API compatibility but not used.
    (void)timeout_s;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    if (::connect((sock_t)sock_fd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        CLOSE_SOCK((sock_t)sock_fd_);
        sock_fd_ = -1;
        return false;
    }

    // Explicitly zero out timeouts on the connected socket — infinite wait.
    struct timeval no_timeout{};
    no_timeout.tv_sec  = 0;
    no_timeout.tv_usec = 0;
    setsockopt((sock_t)sock_fd_, SOL_SOCKET, SO_RCVTIMEO,
               (const char*)&no_timeout, sizeof(no_timeout));
    setsockopt((sock_t)sock_fd_, SOL_SOCKET, SO_SNDTIMEO,
               (const char*)&no_timeout, sizeof(no_timeout));

    connected_ = true;
    peer_addr_ = host + ":" + std::to_string(port);
    return true;
}

bool TCPChannel::send_msg(const std::vector<uint8_t>& data) {
    if (!connected_) return false;
    uint32_t len = (uint32_t)data.size();
    uint8_t hdr[4] = {
        (uint8_t)(len & 0xFF), (uint8_t)((len>>8) & 0xFF),
        (uint8_t)((len>>16) & 0xFF), (uint8_t)((len>>24) & 0xFF)
    };
    if (::send((sock_t)sock_fd_, (const char*)hdr, 4, 0) != 4) return false;
    if (data.empty()) return true;
    int sent = ::send((sock_t)sock_fd_, (const char*)data.data(), (int)len, 0);
    return sent == (int)len;
}

bool TCPChannel::send_msg(const std::string& s) {
    return send_msg(std::vector<uint8_t>(s.begin(), s.end()));
}

bool TCPChannel::recv_exact(uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = ::recv((sock_t)sock_fd_, (char*)buf + got, (int)(n - got), 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

std::vector<uint8_t> TCPChannel::recv_msg() {
    uint8_t hdr[4];
    if (!recv_exact(hdr, 4))
        throw std::runtime_error("Connection closed during recv");
    uint32_t len = hdr[0] | ((uint32_t)hdr[1]<<8)
                           | ((uint32_t)hdr[2]<<16)
                           | ((uint32_t)hdr[3]<<24);
    if (len == 0) return {};
    if (len > 10*1024*1024)
        throw std::runtime_error("Message too large");
    std::vector<uint8_t> buf(len);
    if (!recv_exact(buf.data(), len))
        throw std::runtime_error("Connection closed mid-message");
    return buf;
}

void TCPChannel::close() {
    if (sock_fd_   != -1) { CLOSE_SOCK((sock_t)sock_fd_);   sock_fd_   = -1; }
    if (listen_fd_ != -1) { CLOSE_SOCK((sock_t)listen_fd_); listen_fd_ = -1; }
    connected_ = false;
}