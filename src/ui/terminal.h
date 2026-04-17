#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <thread>
#include <chrono>
#include <cstring>

// =============================================================================
// Terminal -- ANSI color, ASCII box-drawing, animated output, spinners, banners.
// Uses only 7-bit ASCII printable characters for maximum cross-platform
// compatibility (Windows cmd, MSYS2, macOS Terminal, Linux xterm, PuTTY).
// =============================================================================

namespace T {

    // ── ANSI color codes ──────────────────────────────────────────────────────
    constexpr const char* RESET    = "\033[0m";
    constexpr const char* BOLD     = "\033[1m";
    constexpr const char* DIM      = "\033[2m";
    constexpr const char* ITALIC   = "\033[3m";
    constexpr const char* RED      = "\033[91m";
    constexpr const char* GREEN    = "\033[92m";
    constexpr const char* YELLOW   = "\033[93m";
    constexpr const char* BLUE     = "\033[94m";
    constexpr const char* MAGENTA  = "\033[95m";
    constexpr const char* CYAN     = "\033[96m";
    constexpr const char* WHITE    = "\033[97m";
    constexpr const char* BG_RED   = "\033[41m";
    constexpr const char* BG_GREEN = "\033[42m";
    constexpr const char* BG_BLUE  = "\033[44m";
    constexpr const char* BG_DARK  = "\033[40m";

    // Role colors
    constexpr const char* ALICE  = "\033[94m";   // Blue
    constexpr const char* BOB    = "\033[92m";   // Green
    constexpr const char* OSCAR  = "\033[91m";   // Red
    constexpr const char* CRYPTO = "\033[95m";   // Magenta
    constexpr const char* WIRE   = "\033[93m";   // Yellow
    constexpr const char* SAFE   = "\033[92m";
    constexpr const char* DANGER = "\033[91m";

    // ── Platform setup ────────────────────────────────────────────────────────
    inline void enable_vt() {
#ifdef _WIN32
        // Enable ANSI escape sequences on Windows 10+
        system("");
#endif
    }

    // ── Timing ────────────────────────────────────────────────────────────────
    inline void sleep_ms(int ms) {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

    // ── Typewriter effect ─────────────────────────────────────────────────────
    inline void typewrite(const std::string& s, int delay_ms = 14) {
        for (char c : s) {
            std::cout << c << std::flush;
            if (c != ' ' && c != '\n')
                sleep_ms(delay_ms);
        }
    }

    // ── Spinner (ASCII frames only) ───────────────────────────────────────────
    // Uses | / - \ instead of Braille dots for cross-platform compatibility.
    inline void spinner(const std::string& label, int ms) {
        const char* frames[] = {"|", "/", "-", "\\"};
        int n = 4, elapsed = 0, interval = 80;
        int i = 0;
        while (elapsed < ms) {
            std::cout << "\r  " << CYAN << "[" << frames[i % n] << "]" << RESET
                      << "  " << label << "   " << std::flush;
            sleep_ms(interval);
            elapsed += interval;
            i++;
        }
        std::cout << "\r  " << GREEN << "[+]" << RESET
                  << "  " << label << "   \n";
    }

    // ── Section header (pure ASCII box) ──────────────────────────────────────
    // Uses + - | characters instead of Unicode box-drawing.
    inline void section(const std::string& title, const char* color = CYAN) {
        int w = 58;
        std::string bar(w, '-');
        std::string top = "+" + bar + "+";
        int pad  = (w - (int)title.size()) / 2;
        int rpad = w - pad - (int)title.size();
        std::string mid  = "|" + std::string(pad, ' ') + title
                         + std::string(rpad, ' ') + "|";
        std::string bot  = "+" + bar + "+";
        std::cout << "\n" << color << BOLD;
        std::cout << "  " << top << "\n";
        std::cout << "  " << mid << "\n";
        std::cout << "  " << bot << "\n";
        std::cout << RESET;
    }

    // ── Thin separator ────────────────────────────────────────────────────────
    inline void sep(const char* color = DIM) {
        std::cout << color << "  " << std::string(60, '-') << RESET << "\n";
    }

    // ── Key-value row ─────────────────────────────────────────────────────────
    inline void kv(const std::string& key, const std::string& val,
                   const char* kc = DIM, const char* vc = WHITE) {
        std::cout << "  " << kc << std::setw(24) << std::left << key
                  << RESET << vc << val << RESET << "\n";
    }

    // ── Hex block dump ────────────────────────────────────────────────────────
    inline void hex_block(const std::string& label,
                          const std::vector<uint8_t>& data,
                          const char* color = CRYPTO) {
        std::cout << "  " << DIM << label << ":\n" << RESET;
        for (size_t i = 0; i < data.size(); i++) {
            if (i % 16 == 0)
                std::cout << "    " << DIM
                          << std::hex << std::setw(4) << std::setfill('0') << i
                          << std::dec << std::setfill(' ') << "  " << RESET << color;
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << (int)data[i] << " ";
            if ((i + 1) % 16 == 0 || i + 1 == data.size())
                std::cout << RESET << "\n";
        }
    }

    // ── Wire message display ──────────────────────────────────────────────────
    // Uses ASCII arrows --> and <-- instead of Unicode arrows.
    inline void on_wire(const std::string& from, const std::string& to,
                        const std::string& content, bool encrypted = true) {
        const char* fc = (from == "Alice") ? ALICE : (from == "Bob") ? BOB : OSCAR;
        const char* tc = (to   == "Alice") ? ALICE : (to   == "Bob") ? BOB : OSCAR;
        std::cout << "\n  " << fc << from << RESET
                  << WIRE << " ----------> " << RESET
                  << tc << to << RESET << "\n";
        if (encrypted)
            std::cout << "  " << DIM << "  [enc]: " << content << "\n" << RESET;
        else
            std::cout << "  " << YELLOW << "  [plain]: " << content << "\n" << RESET;
    }

    // ── Packet animation (ASCII dots) ─────────────────────────────────────────
    inline void packet_anim(const std::string& from, const std::string& to,
                            int steps = 24) {
        const char* fc = (from == "Alice") ? ALICE : (from == "Bob") ? BOB : OSCAR;
        const char* tc = (to   == "Alice") ? ALICE : (to   == "Bob") ? BOB : OSCAR;
        std::cout << "  " << fc << from << RESET << " ";
        for (int i = 0; i < steps; i++) {
            std::cout << WIRE << "." << RESET << std::flush;
            sleep_ms(22);
        }
        std::cout << " " << tc << to << RESET << "\n";
    }

    // ── Role banner (ASCII box) ───────────────────────────────────────────────
    inline void role_banner(const std::string& role, const std::string& desc,
                             const char* color) {
        std::string bar(42, '=');
        std::cout << color << BOLD;
        std::cout << "\n  +" << bar << "+\n";
        std::cout << "  |  " << std::left << std::setw(40) << role << "|\n";
        std::cout << "  |  " << DIM << std::setw(40) << std::left << desc
                  << color << BOLD << "|\n";
        std::cout << "  +" << bar << "+\n" << RESET;
    }

    // ── Fingerprint comparison ────────────────────────────────────────────────
    inline void compare(const std::string& label,
                        const std::string& v1, const std::string& v2,
                        const std::string& n1 = "Alice",
                        const std::string& n2 = "Bob") {
        bool match = (v1 == v2);
        std::cout << "  " << DIM << label << RESET << "\n";
        std::cout << "    " << ALICE << n1 << ": " << RESET << v1 << "\n";
        std::cout << "    " << BOB   << n2 << ": " << RESET << v2 << "\n";
        if (match)
            std::cout << "  " << BG_GREEN << BOLD
                      << "  [MATCH]  Shared secret established successfully  "
                      << RESET << "\n";
        else
            std::cout << "  " << BG_RED << BOLD
                      << "  [MISMATCH]  Keys differ -- possible MITM attack  "
                      << RESET << "\n";
    }

    // ── Progress bar ──────────────────────────────────────────────────────────
    inline void progress(const std::string& label, int pct,
                         const char* color = GREEN) {
        int filled = pct / 2;
        std::cout << "  " << DIM << label << " [" << RESET << color;
        for (int i = 0; i < 50; i++)
            std::cout << (i < filled ? "#" : ".");
        std::cout << RESET << DIM << "] " << RESET
                  << BOLD << pct << "%" << RESET << "\n";
    }

    // ── Hex conversion helpers ────────────────────────────────────────────────
    inline std::string to_hex(const std::vector<uint8_t>& v, size_t max = 32) {
        std::ostringstream oss;
        for (size_t i = 0; i < std::min(v.size(), max); i++)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)v[i];
        if (v.size() > max) oss << "...";
        return oss.str();
    }

    inline std::string to_hex(const std::string& s, size_t max = 32) {
        std::vector<uint8_t> v(s.begin(), s.end());
        return to_hex(v, max);
    }

    // ── Warning box ───────────────────────────────────────────────────────────
    inline void warn(const std::string& msg) {
        std::cout << "\n  " << BG_RED << BOLD << " WARNING " << RESET
                  << RED << "  " << msg << RESET << "\n";
    }

    // ── Success line ──────────────────────────────────────────────────────────
    inline void ok(const std::string& msg) {
        std::cout << "  " << GREEN << BOLD << " [OK] " << RESET
                  << GREEN << msg << RESET << "\n";
    }

    // ── Info line ─────────────────────────────────────────────────────────────
    inline void info(const std::string& msg) {
        std::cout << "  " << CYAN << "[*] " << RESET << msg << "\n";
    }

    // ── MITM attack detected flash ────────────────────────────────────────────
    inline void attack_detected() {
        sleep_ms(300);
        for (int i = 0; i < 3; i++) {
            std::cout << "\r  " << BG_RED << BOLD
                      << "  !!! MITM ATTACK DETECTED -- KEY MISMATCH !!!  "
                      << RESET << std::flush;
            sleep_ms(350);
            std::cout << "\r  " << std::string(52, ' ') << std::flush;
            sleep_ms(200);
        }
        std::cout << "\r  " << BG_RED << BOLD
                  << "  !!! MITM ATTACK DETECTED -- KEY MISMATCH !!!  "
                  << RESET << "\n";
    }

    // ── Secure channel established animation ──────────────────────────────────
    inline void secure_established() {
        const char* msg = "  SECURE CHANNEL ESTABLISHED  ";
        int len = (int)strlen(msg);
        sleep_ms(200);
        for (int i = 0; i < len; i++) {
            std::cout << BG_GREEN << BOLD << msg[i] << RESET << std::flush;
            sleep_ms(28);
        }
        std::cout << "\n";
    }

    // ── Double-line major section (for act separators) ────────────────────────
    inline void act_banner(const std::string& title, const char* color) {
        int w = 58;
        std::string bar(w, '=');
        int pad  = (w - (int)title.size()) / 2;
        int rpad = w - pad - (int)title.size();
        std::cout << "\n" << color << BOLD;
        std::cout << "  " << "+" << bar << "+" << "\n";
        std::cout << "  " << "+" << bar << "+" << "\n";
        std::cout << "  ||" << std::string(pad - 1, ' ') << title
                  << std::string(rpad - 1, ' ') << "||\n";
        std::cout << "  " << "+" << bar << "+" << "\n";
        std::cout << "  " << "+" << bar << "+" << "\n";
        std::cout << RESET << "\n";
    }

} // namespace T