#!/bin/bash
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
HOST=127.0.0.1
PORT=6432
DB=pgdog
USER_A=tls_user_a
USER_B=tls_user_b
USER_C=tls_user_c
USER_D=tls_user_d

run_psql() {
    psql "host=$HOST port=$PORT dbname=$DB user=$1 sslmode=require sslcert=$DIR/$2.crt sslkey=$DIR/$2.key" -c "SELECT 1" > /dev/null 2>&1
}

# TLS without offering a client certificate.
run_psql_no_cert() {
    PGPASSWORD=pgdog psql "host=$HOST port=$PORT dbname=$DB user=$1 sslmode=require" -c "SELECT 1" > /dev/null 2>&1
}

# Direct TLS (no SSLRequest), libpq 17+.
run_psql_direct() {
    psql "host=$HOST port=$PORT dbname=$DB user=$1 sslmode=require sslnegotiation=direct sslcert=$DIR/$2.crt sslkey=$DIR/$2.key" -c "SELECT 1" > /dev/null 2>&1
}

# Direct TLS handshake offering the given ALPN protocols (none if empty),
# then a GSSENCRequest. Succeeds if PgDog answers it over TLS.
direct_tls_gssenc() {
    python3 - "$HOST" "$PORT" "$@" <<'PYTHON' > /dev/null 2>&1
import socket, ssl, struct, sys

host, port, alpn = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
if alpn:
    ctx.set_alpn_protocols(alpn)
with ctx.wrap_socket(socket.create_connection((host, port), timeout=5)) as tls:
    tls.sendall(struct.pack("!ii", 8, 80877104))
    sys.exit(0 if tls.recv(1) == b"N" else 1)
PYTHON
}

if [ "${1:-}" = "--source-only" ]; then
    return 0 2>/dev/null || exit 0
fi

PASS=0
FAIL=0

echo "=== TLS client certificate tests ==="

# Test 1: user identity pgdog with pgdog cert (should succeed)
echo -n "$USER_A identity pgdog + pgdog cert: "
if run_psql "$USER_A" client; then
    echo "OK"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected success)"
    FAIL=$((FAIL + 1))
fi

# Test 2: user identity pgdog2 with pgdog2 cert (should succeed)
echo -n "$USER_B identity pgdog2 + pgdog2 cert: "
if run_psql "$USER_B" client2; then
    echo "OK"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected success)"
    FAIL=$((FAIL + 1))
fi

# Test 3: user identity pgdog with pgdog2 cert (should fail)
echo -n "$USER_A identity pgdog + pgdog2 cert: "
if run_psql "$USER_A" client2; then
    echo "FAIL (expected rejection)"
    FAIL=$((FAIL + 1))
else
    echo "OK (rejected)"
    PASS=$((PASS + 1))
fi

# Test 4: user identity pgdog2 with pgdog cert (should fail)
echo -n "$USER_B identity pgdog2 + pgdog cert: "
if run_psql "$USER_B" client; then
    echo "FAIL (expected rejection)"
    FAIL=$((FAIL + 1))
else
    echo "OK (rejected)"
    PASS=$((PASS + 1))
fi

# Test 5: no TLS at all (should fail)
echo -n "no TLS: "
if psql "host=$HOST port=$PORT dbname=$DB user=$USER_A sslmode=disable" -c "SELECT 1" > /dev/null 2>&1; then
    echo "FAIL (expected rejection)"
    FAIL=$((FAIL + 1))
else
    echo "OK (rejected)"
    PASS=$((PASS + 1))
fi

# Test 6: password user opted out of client certs, TLS but no cert (should succeed)
echo -n "$USER_C opted out + no cert: "
if run_psql_no_cert "$USER_C"; then
    echo "OK"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected success)"
    FAIL=$((FAIL + 1))
fi

# Test 7: password user that did not opt out, TLS but no cert (should fail)
echo -n "$USER_D not opted out + no cert: "
if run_psql_no_cert "$USER_D"; then
    echo "FAIL (expected rejection)"
    FAIL=$((FAIL + 1))
else
    echo "OK (rejected)"
    PASS=$((PASS + 1))
fi

echo ""
echo "=== Direct TLS (sslnegotiation=direct) tests ==="

PSQL_MAJOR=$(psql --version | sed -E 's/^[^0-9]*([0-9]+).*/\1/')
if [ "$PSQL_MAJOR" -ge 17 ]; then
    # Test 8: direct TLS with libpq, which offers ALPN "postgresql" (should succeed)
    echo -n "$USER_A direct TLS + pgdog cert: "
    if run_psql_direct "$USER_A" client; then
        echo "OK"
        PASS=$((PASS + 1))
    else
        echo "FAIL (expected success)"
        FAIL=$((FAIL + 1))
    fi

    # Test 9: direct TLS, identity mismatch (should fail)
    echo -n "$USER_A direct TLS + pgdog2 cert: "
    if run_psql_direct "$USER_A" client2; then
        echo "FAIL (expected rejection)"
        FAIL=$((FAIL + 1))
    else
        echo "OK (rejected)"
        PASS=$((PASS + 1))
    fi
else
    echo "psql $PSQL_MAJOR doesn't support sslnegotiation=direct, skipping libpq tests"
fi

# Test 10: direct TLS with ALPN "postgresql" (should succeed)
echo -n "direct TLS + ALPN postgresql: "
if direct_tls_gssenc postgresql; then
    echo "OK"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected success)"
    FAIL=$((FAIL + 1))
fi

# Test 11: direct TLS without ALPN (should fail, like PostgreSQL 17+)
echo -n "direct TLS + no ALPN: "
if direct_tls_gssenc; then
    echo "FAIL (expected rejection)"
    FAIL=$((FAIL + 1))
else
    echo "OK (rejected)"
    PASS=$((PASS + 1))
fi

# Test 12: direct TLS with a different ALPN protocol (should fail)
echo -n "direct TLS + ALPN http/1.1: "
if direct_tls_gssenc http/1.1; then
    echo "FAIL (expected rejection)"
    FAIL=$((FAIL + 1))
else
    echo "OK (rejected)"
    PASS=$((PASS + 1))
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
