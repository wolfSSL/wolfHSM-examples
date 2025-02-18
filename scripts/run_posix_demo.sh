#!/bin/bash
# This script demonstrates how to use the wolfHSM POSIX TCP example.
#
# The script performs the following steps:
# 1. Builds both server and client components using the provided wolfSSL and wolfHSM
# 2. Starts the server and waits for it to be ready to accept connections
# 3. Runs the client examples against the server
# 4. Handles cleanup of processes properly
#
# Environment variables:
# - WOLFSSL_DIR: Path to wolfSSL installation (required)
# - WOLFHSM_DIR: Path to wolfHSM installation (required)
#
# Exit codes:
# - 0: Success
# - 1: Error (build failure, server startup failure, or client error)
set -e

# Set default paths relative to script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
: "${WOLFSSL_DIR:="$REPO_ROOT/../wolfssl"}"
: "${WOLFHSM_DIR:="$REPO_ROOT/../wolfhsm"}"

# Check required environment variables
if [ ! -d "$WOLFSSL_DIR" ] || [ ! -d "$WOLFHSM_DIR" ]; then
    echo "Error: WOLFSSL_DIR and WOLFHSM_DIR must point to valid directories"
    echo "Current values:"
    echo "  WOLFSSL_DIR=$WOLFSSL_DIR"
    echo "  WOLFHSM_DIR=$WOLFHSM_DIR"
    echo "You can override these by setting the environment variables"
    exit 1
fi

# Configuration
SERVER_DIR="."
CLIENT_DIR="../wh_client_tcp"
SERVER_BIN="./Build/wh_server_tcp.elf"
CLIENT_BIN="../wh_client_tcp/Build/wh_client_tcp.elf"
TIMEOUT_SECS=30  # Increased timeout for wolfCrypt initialization

# Cleanup function
cleanup() {
    echo "Cleaning up processes..."
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
    if [ ! -z "$CLIENT_PID" ]; then
        kill $CLIENT_PID 2>/dev/null || true
    fi
}

# Set up cleanup trap
trap cleanup EXIT

# Verify binaries exist
if [ ! -f "$SERVER_BIN" ]; then
    echo "Error: Server binary not found at $SERVER_BIN"
    exit 1
fi

if [ ! -f "$CLIENT_BIN" ]; then
    echo "Error: Client binary not found at $CLIENT_BIN"
    exit 1
fi

# Start server and redirect output to log file
echo "Starting server..."
SERVER_FULL_PATH="$(pwd)/$SERVER_BIN"
if [ ! -x "$SERVER_FULL_PATH" ]; then
    echo "Error: Server binary not found or not executable at $SERVER_FULL_PATH"
    exit 1
fi

echo "Running server from: $SERVER_FULL_PATH"
echo "Initializing wolfCrypt and starting server..."
"$SERVER_FULL_PATH" > "$SERVER_BIN.log" 2>&1 &
SERVER_PID=$!

# Give wolfCrypt time to initialize
sleep 2
echo "Server PID: $SERVER_PID"

# Check if server process is still running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Error: Server process died during startup"
    if [ -f "$SERVER_BIN.log" ]; then
        echo "Server log contents:"
        cat "$SERVER_BIN.log"
    fi
    exit 1
fi

# Wait for server to be ready
echo "Waiting for server to start..."
COUNTER=0

# Wait for server to be ready
while ! grep -q "Waiting for connection" "$SERVER_BIN.log" 2>/dev/null && [ $COUNTER -lt $TIMEOUT_SECS ]; do
    # Show server output for debugging
    if [ -f "$SERVER_BIN.log" ]; then
        echo "Server output (waiting for startup):"
        cat "$SERVER_BIN.log"
    fi
    # Check for initialization errors
    if grep -q "Failed to\|Error:\|Failed to initialize\|Failed to wc_InitRng_ex\|Failed to wolfCrypt_Cleanup\|Failed to wc_FreeRng" "$SERVER_BIN.log" 2>/dev/null; then
        echo "Server initialization failed:"
        cat "$SERVER_BIN.log"
        exit 1
    fi
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "Error: Server process died"
        exit 1
    fi
    sleep 1
    COUNTER=$((COUNTER + 1))
done

if [ $COUNTER -ge $TIMEOUT_SECS ]; then
    echo "Error: Server failed to start within $TIMEOUT_SECS seconds"
    echo "Server log contents:"
    cat "$SERVER_DIR/$SERVER_BIN.log"
    exit 1
fi

# Run client
echo "Running client..."
"$CLIENT_DIR/$CLIENT_BIN"
CLIENT_EXIT=$?

if [ $CLIENT_EXIT -ne 0 ]; then
    echo "Error: Client failed with exit code $CLIENT_EXIT"
    exit 1
fi

# Check server is still running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Error: Server died unexpectedly"
    exit 1
fi

echo "Demo completed successfully!"
exit 0
