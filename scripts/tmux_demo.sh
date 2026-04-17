#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# tmux_demo.sh — Visual split-pane demo using tmux
#
# Launches all three processes in separate panes so you can watch the
# handshake happen live in parallel windows.
#
# Usage:
#   bash scripts/tmux_demo.sh [build_dir] [act]
#   act: 1, 2, or 3  (default: prompts you)
#
# Requirements: tmux
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${1:-$PROJECT_ROOT/build}"
BIN="$BUILD_DIR/bin"
ACT="${2:-}"

if ! command -v tmux &>/dev/null; then
    echo "tmux not found. Install it:  sudo apt install tmux  or  brew install tmux"
    echo "Falling back to sequential demo..."
    exec bash "$SCRIPT_DIR/demo.sh" "$BUILD_DIR"
fi

if [ ! -f "$BIN/alice" ] && [ ! -f "$BIN/alice.exe" ]; then
    echo "Binaries not found in $BIN"
    echo "Build first: cmake -B build && cmake --build build"
    exit 1
fi

# ── Act selection ─────────────────────────────────────────────────────────────
if [ -z "$ACT" ]; then
    clear
    echo ""
    echo "  ╔══════════════════════════════════════════════════════════════╗"
    echo "  ║       ECDH-MITM DEMO — Select an Act                        ║"
    echo "  ╠══════════════════════════════════════════════════════════════╣"
    echo "  ║                                                              ║"
    echo "  ║  [1] Act 1 — Honest ECDH  (Alice ↔ Bob directly)           ║"
    echo "  ║  [2] Act 2 — MITM Attack  (Oscar intercepts everything)     ║"
    echo "  ║  [3] Act 3 — Auth Defence (Certificates defeat Oscar)       ║"
    echo "  ║  [a] All acts sequentially                                   ║"
    echo "  ║                                                              ║"
    echo "  ╚══════════════════════════════════════════════════════════════╝"
    echo ""
    read -rp "  Your choice [1/2/3/a]: " ACT
fi

SESSION="ecdh_mitm"

# Kill any existing session
tmux kill-session -t "$SESSION" 2>/dev/null || true

run_act1() {
    # Layout: left=Alice, right=Bob
    tmux new-session  -d -s "$SESSION" -x 220 -y 50
    tmux rename-window -t "$SESSION:0" "Act 1 — Honest ECDH"

    tmux split-window -h -t "$SESSION"

    # Left pane = Alice, Right pane = Bob
    # Bob starts first (listener)
    tmux send-keys -t "$SESSION:0.1" \
        "echo -e '\033[92m\033[1m  ═══ BOB (receiver) — port 9003 ═══\033[0m' && sleep 0.5 && '$BIN/bob'" Enter

    sleep 1

    tmux send-keys -t "$SESSION:0.0" \
        "echo -e '\033[94m\033[1m  ═══ ALICE (sender) — port 9001→9003 ═══\033[0m' && sleep 0.3 && '$BIN/alice'" Enter

    tmux attach-session -t "$SESSION"
}

run_act2() {
    # Layout: top-left=Alice, bottom-left=Oscar, right=Bob
    tmux new-session  -d -s "$SESSION" -x 220 -y 55
    tmux rename-window -t "$SESSION:0" "Act 2 — MITM Attack"

    # Split into left/right
    tmux split-window -h -t "$SESSION"
    # Split left pane top/bottom
    tmux split-window -v -t "$SESSION:0.0"

    # Pane 0 = Alice (top-left), Pane 1 = Oscar (bottom-left), Pane 2 = Bob (right)
    # Bob starts first
    tmux send-keys -t "$SESSION:0.2" \
        "echo -e '\033[92m\033[1m  ═══ BOB — port 9003 ═══\033[0m' && sleep 0.3 && '$BIN/bob'" Enter

    sleep 0.8

    # Oscar starts second (connects to Bob, listens for Alice)
    tmux send-keys -t "$SESSION:0.1" \
        "echo -e '\033[91m\033[1m  ═══ OSCAR (MITM) — :9001→:9003 ═══\033[0m' && sleep 0.5 && '$BIN/oscar'" Enter

    sleep 1.2

    # Alice starts last (connects to Oscar thinking it's Bob)
    tmux send-keys -t "$SESSION:0.0" \
        "echo -e '\033[94m\033[1m  ═══ ALICE — port 9001 ═══\033[0m' && sleep 0.3 && '$BIN/alice'" Enter

    tmux attach-session -t "$SESSION"
}

run_act3() {
    # Same layout as Act 2
    tmux new-session  -d -s "$SESSION" -x 220 -y 55
    tmux rename-window -t "$SESSION:0" "Act 3 — Defence"

    tmux split-window -h -t "$SESSION"
    tmux split-window -v -t "$SESSION:0.0"

    # Bob --auth
    tmux send-keys -t "$SESSION:0.2" \
        "echo -e '\033[92m\033[1m  ═══ BOB --auth — port 9003 ═══\033[0m' && sleep 0.3 && '$BIN/bob' --auth" Enter

    sleep 0.8

    # Oscar --auth (will fail)
    tmux send-keys -t "$SESSION:0.1" \
        "echo -e '\033[91m\033[1m  ═══ OSCAR --auth (attack) — :9001→:9003 ═══\033[0m' && sleep 0.5 && '$BIN/oscar' --auth" Enter

    sleep 1.2

    # Alice --auth
    tmux send-keys -t "$SESSION:0.0" \
        "echo -e '\033[94m\033[1m  ═══ ALICE --auth — port 9001 ═══\033[0m' && sleep 0.3 && '$BIN/alice' --auth" Enter

    tmux attach-session -t "$SESSION"
}

run_all() {
    for a in 1 2 3; do
        ACT=$a
        case "$a" in
            1) run_act1 ;;
            2) run_act2 ;;
            3) run_act3 ;;
        esac
        echo ""
        read -rp "  Press Enter for next act..."
        tmux kill-session -t "$SESSION" 2>/dev/null || true
    done
}

case "$ACT" in
    1) run_act1 ;;
    2) run_act2 ;;
    3) run_act3 ;;
    a|A|all) run_all ;;
    *) echo "Invalid choice '$ACT'. Use 1, 2, 3, or a." ; exit 1 ;;
esac
