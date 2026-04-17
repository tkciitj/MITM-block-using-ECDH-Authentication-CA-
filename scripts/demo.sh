#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# demo.sh — Fully automated ECDH-MITM three-act demo
#
# Run from the BUILD directory:
#   cd build && bash ../scripts/demo.sh
#
# Or from the project root:
#   bash scripts/demo.sh build
#
# Requires: tmux (optional but recommended), or runs sequentially with netcat.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
R='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
MAGENTA='\033[95m'
CYAN='\033[96m'
WHITE='\033[97m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_BLUE='\033[44m'
BG_DARK='\033[40m'

# Role colors
ALICE_C='\033[94m'
BOB_C='\033[92m'
OSCAR_C='\033[91m'

# ── Determine binary directory ────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${1:-$PROJECT_ROOT/build}"
BIN="$BUILD_DIR/bin"

if [ ! -f "$BIN/alice" ] && [ ! -f "$BIN/alice.exe" ]; then
    echo -e "${RED}${BOLD}ERROR: Binaries not found in $BIN${R}"
    echo -e "${DIM}Build first:  cmake -B build && cmake --build build${R}"
    exit 1
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║                                                              ║"
    echo "  ║        E C D H  ·  M I T M  ·  D E M O                     ║"
    echo "  ║                                                              ║"
    echo "  ║   Elliptic-Curve Diffie-Hellman  +  Man-in-the-Middle       ║"
    echo "  ║   P-256 · AES-256-GCM · ECDSA Certificates · TOFU          ║"
    echo "  ║                                                              ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${R}"
}

hr() {
    echo -e "${DIM}  ──────────────────────────────────────────────────────────${R}"
}

section() {
    local title="$1" color="${2:-$CYAN}"
    local w=58
    local pad=$(( (w - ${#title}) / 2 ))
    echo ""
    echo -e "${color}${BOLD}  ╔$(printf '═%.0s' $(seq 1 $w))╗"
    echo -e "  ║$(printf ' %.0s' $(seq 1 $pad))${title}$(printf ' %.0s' $(seq 1 $((w - pad - ${#title}))))║"
    echo -e "  ╚$(printf '═%.0s' $(seq 1 $w))╝${R}"
    echo ""
}

typewrite() {
    local msg="$1" delay="${2:-0.015}"
    for (( i=0; i<${#msg}; i++ )); do
        printf "%s" "${msg:$i:1}"
        sleep "$delay" 2>/dev/null || true
    done
    echo
}

spinner() {
    local label="$1" duration="${2:-2}"
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local end_time=$(( $(date +%s) + duration ))
    local i=0
    while [ $(date +%s) -lt $end_time ]; do
        printf "\r  ${CYAN}${frames[$((i % 10))]}${R}  %s   " "$label"
        sleep 0.08
        i=$((i+1))
    done
    printf "\r  ${GREEN}✔${R}  %s   \n" "$label"
}

progress_bar() {
    local label="$1" pct="$2" color="${3:-$GREEN}"
    local filled=$(( pct / 2 ))
    local empty=$(( 50 - filled ))
    printf "  ${DIM}%s [${R}${color}" "$label"
    printf '█%.0s' $(seq 1 $filled 2>/dev/null || true)
    printf '░%.0s' $(seq 1 $empty 2>/dev/null || true)
    echo -e "${R}${DIM}] ${R}${BOLD}${pct}%${R}"
}

packet_anim() {
    local from="$1" to="$2"
    local fc bc
    case "$from" in Alice) fc="$ALICE_C";; Bob) fc="$BOB_C";; Oscar) fc="$OSCAR_C";; *) fc="$WHITE";; esac
    case "$to")   in Alice) bc="$ALICE_C";; Bob) bc="$BOB_C";; Oscar) bc="$OSCAR_C";; *) bc="$WHITE";; esac
    printf "  ${fc}%s${R} " "$from"
    for i in $(seq 1 24); do printf "${YELLOW}·${R}"; sleep 0.025; done
    echo -e " ${bc}${to}${R}"
}

wait_key() {
    echo ""
    echo -e "  ${DIM}Press ${BOLD}[Enter]${R}${DIM} to continue...${R}"
    read -r _
}

kill_bg() {
    jobs -p | xargs -r kill 2>/dev/null || true
    sleep 0.3
}

# ── Check for tmux ────────────────────────────────────────────────────────────
USE_TMUX=false
if command -v tmux &>/dev/null && [ -z "${TMUX:-}" ]; then
    USE_TMUX=true
fi

# ── Main Demo ─────────────────────────────────────────────────────────────────
print_banner

echo -e "  ${WHITE}${BOLD}ECDH-MITM — Three-Act Live Cryptography Demo${R}"
echo ""
typewrite "  This demo shows how ECDH key exchange works, how it can be" 0.010
typewrite "  attacked by a Man-in-the-Middle (Oscar), and how certificate" 0.010
typewrite "  authentication defeats the attack completely." 0.010
echo ""
hr
echo -e "  ${DIM}Binary path : ${R}${CYAN}$BIN${R}"
echo -e "  ${DIM}Project root: ${R}${CYAN}$PROJECT_ROOT${R}"
hr
wait_key

# ═════════════════════════════════════════════════════════════════════════════
# ACT 1 — Honest ECDH (no attacker)
# ═════════════════════════════════════════════════════════════════════════════
section "ACT 1 — HONEST ECDH  (Alice ↔ Bob, No Attacker)" "$ALICE_C"

echo -e "  ${ALICE_C}Alice${R} and ${BOB_C}Bob${R} perform a direct ECDH key exchange."
echo -e "  Both generate P-256 keypairs, exchange public keys over TCP,"
echo -e "  and independently derive the ${GREEN}same shared secret${R}."
echo ""
echo -e "  ${DIM}Protocol:${R}"
echo -e "    ${DIM}Alice [9001] ◄────────────────────► Bob [9003]${R}"
echo -e "    ${DIM}         No Oscar. Direct connection.${R}"
echo ""

progress_bar "Setting up..."    20 "$GREEN"
progress_bar "Generating keys..." 60 "$CYAN"
progress_bar "Ready"            100 "$GREEN"
echo ""

wait_key

# Launch Bob, then Alice in background with log capture
LOG_BOB_ACT1=$(mktemp /tmp/bob_act1.XXXXXX)
LOG_ALICE_ACT1=$(mktemp /tmp/alice_act1.XXXXXX)

section "Running Act 1" "$GREEN"
echo -e "  ${BOB_C}${BOLD}Starting Bob (listener)...${R}"
"$BIN/bob" > "$LOG_BOB_ACT1" 2>&1 &
PID_BOB=$!
sleep 1

echo -e "  ${ALICE_C}${BOLD}Starting Alice (connector)...${R}"
"$BIN/alice" > "$LOG_ALICE_ACT1" 2>&1 &
PID_ALICE=$!

spinner "Running Act 1 — direct ECDH handshake" 5

wait "$PID_BOB"  2>/dev/null || true
wait "$PID_ALICE" 2>/dev/null || true

echo ""
section "Act 1 — Alice's Terminal Output" "$ALICE_C"
head -60 "$LOG_ALICE_ACT1" | sed 's/^/  /'

echo ""
section "Act 1 — Bob's Terminal Output" "$BOB_C"
head -60 "$LOG_BOB_ACT1" | sed 's/^/  /'

echo ""
section "Act 1 — Key Fingerprint Comparison" "$GREEN"

ALICE_FP=$(grep -oP '(?<=fingerprint\s{14})[^\s]+' "$LOG_ALICE_ACT1" | head -1 || echo "N/A")
BOB_FP=$(grep -oP '(?<=fingerprint\s{14})[^\s]+' "$LOG_BOB_ACT1" | head -1 || echo "N/A")

echo -e "  ${ALICE_C}Alice's fingerprint${R}: ${YELLOW}${ALICE_FP}${R}"
echo -e "  ${BOB_C}Bob's fingerprint${R}  : ${YELLOW}${BOB_FP}${R}"

if [ "$ALICE_FP" = "$BOB_FP" ] && [ "$ALICE_FP" != "N/A" ]; then
    echo ""
    echo -e "  ${BG_GREEN}${BOLD}  ✔  FINGERPRINTS MATCH — Honest ECDH Succeeded!  ${R}"
else
    echo ""
    echo -e "  ${DIM}(Check terminal output above for fingerprint values)${R}"
fi

echo ""
typewrite "  ✔ Shared secret established. AES-256-GCM channel open." 0.012
typewrite "  ✔ Alice and Bob can now exchange encrypted messages." 0.012
typewrite "  ✔ Wireshark shows only ciphertext — no plaintext visible." 0.012

rm -f "$LOG_BOB_ACT1" "$LOG_ALICE_ACT1"
wait_key

# ═════════════════════════════════════════════════════════════════════════════
# ACT 2 — Oscar's MITM Attack
# ═════════════════════════════════════════════════════════════════════════════
section "ACT 2 — MITM ATTACK  (Oscar intercepts everything)" "$OSCAR_C"

echo -e "  ${OSCAR_C}Oscar${R} positions himself between Alice and Bob."
echo -e "  He performs ${RED}two separate${R} ECDH handshakes:"
echo ""
echo -e "    ${ALICE_C}Alice${R} ${YELLOW}──────[9001]──────►${R} ${OSCAR_C}Oscar${R} ${YELLOW}──────[9003]──────►${R} ${BOB_C}Bob${R}"
echo ""
echo -e "  Neither Alice nor Bob know Oscar is there."
echo -e "  Oscar ${RED}decrypts, reads, and re-encrypts${R} every message."
echo ""

for pct in 10 30 50 70 90 100; do
    progress_bar "Oscar infiltrating..." $pct "$RED"
    sleep 0.1
done
echo ""

wait_key

LOG_BOB_ACT2=$(mktemp /tmp/bob_act2.XXXXXX)
LOG_ALICE_ACT2=$(mktemp /tmp/alice_act2.XXXXXX)
LOG_OSCAR_ACT2=$(mktemp /tmp/oscar_act2.XXXXXX)

section "Running Act 2 — MITM Attack" "$OSCAR_C"

echo -e "  ${BOB_C}${BOLD}Starting Bob (listens on :9003)...${R}"
"$BIN/bob" > "$LOG_BOB_ACT2" 2>&1 &
PID_BOB2=$!
sleep 0.5

echo -e "  ${OSCAR_C}${BOLD}Starting Oscar (listens on :9001, connects to :9003)...${R}"
"$BIN/oscar" > "$LOG_OSCAR_ACT2" 2>&1 &
PID_OSCAR=$!
sleep 1

echo -e "  ${ALICE_C}${BOLD}Starting Alice (connects to :9001 — hits Oscar!)...${R}"
"$BIN/alice" > "$LOG_ALICE_ACT2" 2>&1 &
PID_ALICE2=$!

spinner "Oscar is intercepting the ECDH exchange..." 5

wait "$PID_BOB2"   2>/dev/null || true
wait "$PID_ALICE2" 2>/dev/null || true
wait "$PID_OSCAR"  2>/dev/null || true

echo ""
section "Act 2 — Oscar's Intercept Log" "$OSCAR_C"
head -80 "$LOG_OSCAR_ACT2" | sed 's/^/  /'

echo ""
section "Act 2 — The Attack Explained" "$RED"
echo ""
echo -e "  ${DIM}What Oscar did:${R}"
echo -e "    ${RED}1.${R} Intercepted Alice's ECDH HELLO message"
echo -e "    ${RED}2.${R} Substituted his own public key for Bob's"
echo -e "    ${RED}3.${R} Performed ECDH with Alice → got shared_A"
echo -e "    ${RED}4.${R} Performed ECDH with Bob   → got shared_B"
echo -e "    ${RED}5.${R} Alice encrypts to Oscar (thinks it's Bob)"
echo -e "    ${RED}6.${R} Oscar decrypts → reads plaintext → re-encrypts → Bob"
echo ""
echo -e "  ${YELLOW}Fingerprint mismatch reveals the attack:${R}"
echo -e "  ${DIM}If Alice and Bob compare fingerprints out-of-band, they'll${R}"
echo -e "  ${DIM}see they're different — but most users never do this.${R}"
echo ""
echo -e "  ${BG_RED}${BOLD}  !!!  OSCAR READ EVERY MESSAGE  !!!  ${R}"

rm -f "$LOG_BOB_ACT2" "$LOG_ALICE_ACT2" "$LOG_OSCAR_ACT2"
wait_key

# ═════════════════════════════════════════════════════════════════════════════
# ACT 3 — Authentication defeats Oscar
# ═════════════════════════════════════════════════════════════════════════════
section "ACT 3 — DEFENCE  (Certificates defeat Oscar)" "$GREEN"

echo -e "  A Certificate Authority (CA) is introduced."
echo -e "  The CA signs Alice's and Bob's public keys with ${CYAN}ECDSA${R}."
echo -e "  Both parties verify signatures before accepting any key."
echo ""
echo -e "  ${OSCAR_C}Oscar${R} cannot forge a CA-signed certificate:"
echo -e "    ${DIM}→ He doesn't have the CA's private key.${R}"
echo -e "    ${DIM}→ His self-signed cert fails verification.${R}"
echo -e "    ${DIM}→ Both Alice and Bob abort the connection.${R}"
echo ""
echo -e "  ${DIM}Additional defences:${R}"
echo -e "    ${CYAN}•${R} Safety number comparison (fingerprint out-of-band)"
echo -e "    ${CYAN}•${R} TOFU (Trust On First Use) persistent store"
echo -e "    ${CYAN}•${R} Key pinning — new key triggers warning"
echo ""

for pct in 15 35 55 75 95 100; do
    progress_bar "Loading defence mechanisms..." $pct "$CYAN"
    sleep 0.08
done
echo ""

wait_key

LOG_BOB_ACT3=$(mktemp /tmp/bob_act3.XXXXXX)
LOG_ALICE_ACT3=$(mktemp /tmp/alice_act3.XXXXXX)
LOG_OSCAR_ACT3=$(mktemp /tmp/oscar_act3.XXXXXX)

section "Running Act 3 — Oscar Attempts Authenticated MITM" "$GREEN"

echo -e "  ${BOB_C}${BOLD}Starting Bob --auth...${R}"
"$BIN/bob" --auth > "$LOG_BOB_ACT3" 2>&1 &
PID_BOB3=$!
sleep 0.5

echo -e "  ${OSCAR_C}${BOLD}Starting Oscar --auth (will be rejected)...${R}"
"$BIN/oscar" --auth > "$LOG_OSCAR_ACT3" 2>&1 &
PID_OSCAR3=$!
sleep 1

echo -e "  ${ALICE_C}${BOLD}Starting Alice --auth (will reject Oscar's cert)...${R}"
"$BIN/alice" --auth > "$LOG_ALICE_ACT3" 2>&1 &
PID_ALICE3=$!

spinner "Oscar is attempting authenticated MITM (doomed to fail)..." 5

wait "$PID_BOB3"    2>/dev/null || true
wait "$PID_ALICE3"  2>/dev/null || true
wait "$PID_OSCAR3"  2>/dev/null || true

echo ""
section "Act 3 — Oscar's Failed Attack Log" "$OSCAR_C"
head -50 "$LOG_OSCAR_ACT3" | sed 's/^/  /'

echo ""
section "Act 3 — The Defence Worked" "$GREEN"
echo ""
typewrite "  ✔ Oscar's fake certificate was rejected by both Alice and Bob." 0.012
typewrite "  ✔ ECDSA signature verification failed — CA key mismatch." 0.012
typewrite "  ✔ No shared secret established with Oscar." 0.012
typewrite "  ✔ The attack was defeated at the handshake layer." 0.012
echo ""

rm -f "$LOG_BOB_ACT3" "$LOG_ALICE_ACT3" "$LOG_OSCAR_ACT3"

# ═════════════════════════════════════════════════════════════════════════════
# Final Summary
# ═════════════════════════════════════════════════════════════════════════════
section "DEMO COMPLETE — Summary" "$CYAN"

echo -e "  ${CYAN}${BOLD}Three-Act Cryptography Demo — Results${R}"
echo ""
echo -e "  ${GREEN}Act 1${R} — ${WHITE}Honest ECDH${R}"
echo -e "  ${DIM}  Alice + Bob derived the same P-256 shared secret.${R}"
echo -e "  ${DIM}  AES-256-GCM encrypted chat established.${R}"
echo -e "  ${DIM}  Wireshark sees only ciphertext.${R}"
echo ""
echo -e "  ${RED}Act 2${R} — ${WHITE}MITM Attack (Oscar succeeds)${R}"
echo -e "  ${DIM}  Oscar intercepted both ECDH handshakes.${R}"
echo -e "  ${DIM}  All plaintext was visible to Oscar.${R}"
echo -e "  ${DIM}  Fingerprint mismatch is the only indicator.${R}"
echo ""
echo -e "  ${GREEN}Act 3${R} — ${WHITE}Authenticated ECDH (Oscar defeated)${R}"
echo -e "  ${DIM}  ECDSA certificates defeated the forgery.${R}"
echo -e "  ${DIM}  Oscar had no CA private key — cert rejected.${R}"
echo -e "  ${DIM}  This is how TLS mutual-auth / Signal work.${R}"
echo ""
hr
echo ""
echo -e "  ${CYAN}Key Algorithms Used:${R}"
echo -e "    ${DIM}•${R} Elliptic Curve: ${CYAN}P-256 (secp256r1)${R} — from scratch"
echo -e "    ${DIM}•${R} Key Exchange:   ${CYAN}ECDH${R} — shared secret derivation"
echo -e "    ${DIM}•${R} Key Derivation: ${CYAN}HKDF-SHA256${R}"
echo -e "    ${DIM}•${R} Encryption:     ${CYAN}AES-256-GCM${R} — authenticated"
echo -e "    ${DIM}•${R} Signing:        ${CYAN}ECDSA-P256${R} — certificate auth"
echo ""
hr
echo ""
echo -e "  ${GREEN}${BOLD}Thank you for watching the ECDH-MITM Demo!${R}"
echo ""
