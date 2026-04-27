#!/bin/bash
# OMNIA-OS Zero-Spoofing Demo Runner
# iDARIA Foundation — Turin R&D Hub
#
# Runs the complete investor demo in one command:
#   1. Starts the Python verifier
#   2. Waits until it's ready
#   3. Runs all 5 tamper tests
#   4. Opens the dashboard in browser
#
# Usage: bash scripts/demo.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
VERIFIER_DIR="$ROOT_DIR/verifier"
DASHBOARD="$ROOT_DIR/dashboard/index.html"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║    OMNIA-OS Zero-Spoofing Demo v1.0                  ║"
echo "║    iDARIA Foundation — Turin, Italy                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Step 1: Install dependencies if needed
echo "► Checking Python dependencies..."
cd "$VERIFIER_DIR"
pip install -r requirements.txt -q --break-system-packages 2>/dev/null \
  || pip install -r requirements.txt -q

# Step 2: Kill any existing verifier on port 5000
echo "► Cleaning up port 5000..."
lsof -ti:5000 | xargs kill -9 2>/dev/null || true

# Step 3: Start verifier in background
echo "► Starting attestation verifier on http://localhost:5000 ..."
python verifier.py &
VERIFIER_PID=$!
trap "kill $VERIFIER_PID 2>/dev/null; echo ''; echo 'Verifier stopped.'" EXIT

# Step 4: Wait until verifier is ready (up to 10 seconds)
echo "► Waiting for verifier to be ready..."
for i in $(seq 1 20); do
    if curl -s http://localhost:5000/health > /dev/null 2>&1; then
        echo "   ✓ Verifier is ready."
        break
    fi
    sleep 0.5
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Running T1-T5 Tamper Test Suite"
echo "═══════════════════════════════════════════════════════"
echo ""

# Step 5: Run the test suite
python test_suite.py

# Step 6: Open dashboard in browser
echo ""
echo "► Opening demo dashboard in browser..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$DASHBOARD"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open "$DASHBOARD" 2>/dev/null || echo "   Open dashboard manually: $DASHBOARD"
elif [[ "$OSTYPE" == "msys"* ]]; then
    start "$DASHBOARD"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Demo running! Press Ctrl+C to stop."
echo "  Dashboard: $DASHBOARD"
echo "  Verifier:  http://localhost:5000"
echo "═══════════════════════════════════════════════════════"
echo ""

# Keep running until Ctrl+C
wait $VERIFIER_PID
