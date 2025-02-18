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

# Configuration
SERVER_DIR="posix/tcp/wh_server_tcp"
CLIENT_DIR="posix/tcp/wh_client_tcp"
SERVER_BIN="Build/wh_server_tcp.elf"
CLIENT_BIN="Build/wh_client_tcp.elf"
TIMEOUT_SECS=5

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

# Build server
echo "Building server..."
cd "$SERVER_DIR"
make clean && make WOLFSSL_DIR=${WOLFSSL_DIR} WOLFHSM_DIR=${WOLFHSM_DIR}
if [ ! -f "$SERVER_BIN" ]; then
    echo "Error: Server build failed"
    exit 1
fi
cd ../../../

# Build client
echo "Building client..."
cd "$CLIENT_DIR"
make clean && make WOLFSSL_DIR=${WOLFSSL_DIR} WOLFHSM_DIR=${WOLFHSM_DIR}
if [ ! -f "$CLIENT_BIN" ]; then
    echo "Error: Client build failed"
    exit 1
fi
cd ../../../

# Start server and redirect output to log file
echo "Starting server..."
SERVER_FULL_PATH="$(pwd)/$SERVER_DIR/$SERVER_BIN"
if [ ! -x "$SERVER_FULL_PATH" ]; then
    echo "Error: Server binary not found or not executable at $SERVER_FULL_PATH"
    exit 1
fi

echo "Running server from: $SERVER_FULL_PATH"
"$SERVER_FULL_PATH" > "$SERVER_DIR/$SERVER_BIN.log" 2>&1 &
SERVER_PID=$!

# Give the server a moment to write initial output
sleep 1
echo "Server PID: $SERVER_PID"

# Wait for server to be ready
echo "Waiting for server to start..."
COUNTER=0

# Wait for server to be ready
while ! grep -q "Waiting for connection\|Server connected" "$SERVER_DIR/$SERVER_BIN.log" 2>/dev/null && [ $COUNTER -lt $TIMEOUT_SECS ]; do
    # Check for initialization errors
    if grep -q "Failed to" "$SERVER_DIR/$SERVER_BIN.log" 2>/dev/null; then
        echo "Server initialization failed:"
        cat "$SERVER_DIR/$SERVER_BIN.log"
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
