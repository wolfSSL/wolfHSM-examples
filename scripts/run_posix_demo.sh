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
SERVER_DIR="posix/tcp/wh_server_tcp"
CLIENT_DIR="posix/tcp/wh_client_tcp"
SERVER_BIN="${SERVER_DIR}/Build/wh_server_tcp.elf"
CLIENT_BIN="${CLIENT_DIR}/Build/wh_client_tcp.elf"
TIMEOUT_SECS=60  # Increased timeout for wolfCrypt initialization

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

# Verify server binary exists
SERVER_FULL_PATH="$REPO_ROOT/$SERVER_DIR/Build/wh_server_tcp.elf"
if [ ! -f "$SERVER_FULL_PATH" ]; then
    echo "Error: Server binary not found at $SERVER_FULL_PATH"
    ls -la "$REPO_ROOT/$SERVER_DIR"
    ls -la "$REPO_ROOT/$SERVER_DIR/Build/" 2>/dev/null || true
    exit 1
fi

echo "Running server from: $SERVER_FULL_PATH"
echo "Initializing wolfCrypt and starting server..."

# Create log directory and start server
cd "$REPO_ROOT" || exit 1
mkdir -p "$SERVER_DIR/Build"
cd "$SERVER_DIR/Build" || exit 1

# Start server with debug output
echo "Starting server in directory: $(pwd)"
echo "Server binary permissions:"
ls -l "$SERVER_FULL_PATH"
echo "Server binary dependencies:"
ldd "$SERVER_FULL_PATH"
echo "Environment variables:"
env | grep -E "WOLF|PATH"

# Start server with debug output
echo "Running server command: $SERVER_FULL_PATH"
echo "Server working directory: $(pwd)"
echo "Server environment:"
env | grep -E "WOLF|LD|PATH"

# Create log file with proper permissions
touch server.log
chmod 666 server.log

# Start server with debug output
"$SERVER_FULL_PATH" > server.log 2>&1 &
SERVER_PID=$!

# Wait a moment for the process to start
sleep 2

# Check if server process is still running and show process info
if kill -0 $SERVER_PID 2>/dev/null; then
    echo "Server process info:"
    ps -p $SERVER_PID -f
    echo "Server log file:"
    ls -l server.log
    echo "Initial server output:"
    cat server.log
fi

# Check if server process is still running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Error: Server failed to start"
    if [ -f server.log ]; then
        echo "Server log contents:"
        cat server.log
    fi
    exit 1
fi

# Print initial server output for debugging
if [ -f server.log ]; then
    echo "Initial server output:"
    cat server.log
fi

cd - >/dev/null || exit 1

# Initialize counter and wait for log file to be created
COUNTER=0
LOG_FILE="$REPO_ROOT/$SERVER_DIR/Build/server.log"
while [ ! -f "$LOG_FILE" ] && [ $COUNTER -lt $TIMEOUT_SECS ]; do
    sleep 1
    COUNTER=$((COUNTER + 1))
done

if [ ! -f "$LOG_FILE" ]; then
    echo "Error: Server log file not created within $TIMEOUT_SECS seconds at $LOG_FILE"
    exit 1
fi

# Reset counter for server startup wait
COUNTER=0
echo "Server PID: $SERVER_PID"

# Check if server process is still running and wait for initialization
echo "Waiting for server to initialize..."
while ! grep -q "Waiting for connection\|Server connected" "$LOG_FILE" 2>/dev/null && [ $COUNTER -lt $TIMEOUT_SECS ]; do
    echo "Checking server status... $COUNTER/$TIMEOUT_SECS seconds"

    # Check if server process is still running
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo -e "\nError: Server process died during startup"
        if [ -f "$(dirname "$SERVER_FULL_PATH")/server.log" ]; then
            echo "Server log contents:"
            cat "$(dirname "$SERVER_FULL_PATH")/server.log"
        fi
        exit 1
    fi

    # Check for initialization errors
    if grep -q "Failed to\|Error:\|Failed to initialize\|Failed to wc_InitRng_ex\|Failed to wolfCrypt_Cleanup\|Failed to wc_FreeRng" "$LOG_FILE" 2>/dev/null; then
        echo -e "\nServer initialization failed:"
        cat "$LOG_FILE"
        exit 1
    fi

    # Show current server output
    if [ -f "$LOG_FILE" ] && [ $((COUNTER % 10)) -eq 0 ]; then
        echo -e "\nCurrent server output at $COUNTER seconds:"
        tail -n 5 "$LOG_FILE"
        echo "..."
    fi

    sleep 1
    COUNTER=$((COUNTER + 1))
done

if [ $COUNTER -ge $TIMEOUT_SECS ]; then
    echo -e "\nError: Server failed to initialize within $TIMEOUT_SECS seconds"
    echo "Server log contents:"
    cat "$LOG_FILE"
    exit 1
fi

echo -e "\nServer initialized successfully!"

# Wait for server to be ready
echo "Waiting for server to start..."
COUNTER=0

# Wait for server to be ready
while ! grep -q "Server connected\|Waiting for connection" "$LOG_FILE" 2>/dev/null && [ $COUNTER -lt $TIMEOUT_SECS ]; do
    # Show server output for debugging
    if [ -f "$LOG_FILE" ]; then
        echo "Server output (waiting for startup):"
        cat "$LOG_FILE"
    fi
    # Check for initialization errors
    if grep -q "Failed to\|Error:\|Failed to initialize\|Failed to wc_InitRng_ex\|Failed to wolfCrypt_Cleanup\|Failed to wc_FreeRng" "$LOG_FILE" 2>/dev/null; then
        echo "Server initialization failed:"
        cat "$LOG_FILE"
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
    cat "$LOG_FILE"
    exit 1
fi

# Run client
echo "Running client..."
if ! "$CLIENT_DIR/$CLIENT_BIN"; then
    echo "Error: Client failed to run"
    echo "Server log contents:"
    cat "$LOG_FILE"
    exit 1
fi

# Check server is still running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Error: Server died unexpectedly"
    exit 1
fi

echo "Demo completed successfully!"
exit 0
