#!/bin/bash
set -e

# Configuration
SERVER_DIR="posix/tcp/wh_server_tcp"
CLIENT_DIR="posix/tcp/wh_client_tcp"
SERVER_BIN="Build/wh_server_tcp.elf"
CLIENT_BIN="Build/wh_client_tcp.elf"
TIMEOUT_SECS=1

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

# Start server
echo "Starting server..."
"$SERVER_DIR/$SERVER_BIN" &
SERVER_PID=$!

# Wait for server to be ready
echo "Waiting for server to start..."
COUNTER=0
# Redirect server output to log file
"$SERVER_DIR/$SERVER_BIN" > "$SERVER_DIR/$SERVER_BIN.log" 2>&1 &
SERVER_PID=$!

# Wait for server to be ready
while ! grep -q "Waiting for connection" "$SERVER_DIR/$SERVER_BIN.log" 2>/dev/null && [ $COUNTER -lt $TIMEOUT_SECS ]; do
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        echo "Error: Server process died"
        exit 1
    fi
    sleep 1
    COUNTER=$((COUNTER + 1))
done

if [ $COUNTER -ge $TIMEOUT_SECS ]; then
    echo "Error: Server failed to start within $TIMEOUT_SECS seconds"
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
