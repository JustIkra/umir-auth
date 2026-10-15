#!/bin/sh
set -eu

if [ "${UMIR_PRODUCTION_SMOKE_INSIDE:-}" != 1 ]; then
  if [ "$#" != 2 ]; then
    printf 'usage: %s <owned-production-image> <source-revision>\n' "$0" >&2
    exit 2
  fi
  image=$1
  revision=$2
  actual=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")
  [ "$actual" = "$revision" ] || { printf 'Production image revision mismatch\n' >&2; exit 1; }
  source=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$image")
  [ "$source" = https://github.com/JustIkra/umir-auth ] || { printf 'Production image source mismatch\n' >&2; exit 1; }
  root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
  exec docker run --rm --network none --read-only --user 65532:65532 \
    --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,uid=65532,gid=65532,mode=0700 \
    -e UMIR_PRODUCTION_SMOKE_INSIDE=1 \
    -v "$root/tests/container/production-smoke.sh:/production-smoke.sh:ro" \
    --entrypoint /bin/sh "$image" /production-smoke.sh
fi

umask 077
mkdir /tmp/auth-smoke
cd /tmp/auth-smoke
printf 'synthetic-password' > password
printf 'synthetic-smtp-user' > smtp-user
printf 'synthetic-smtp-password' > smtp-password
printf '%s' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa > gateway-key
printf '%s' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb > serving-key
printf '%s' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc > warehouse-key
cat > config.json <<'JSON'
{
  "privateAddress":"127.0.0.1:18081",
  "stateFile":"/tmp/auth-smoke/auth.json",
  "secretsDir":"/tmp/auth-smoke/secrets",
  "initialUser":{"userID":"11111111-1111-4111-8111-111111111111","login":"ci.operator","displayName":"CI Operator","credentialVersion":"1"},
  "passwordFile":"/tmp/auth-smoke/password",
  "serviceKeyFiles":{"gateway":"/tmp/auth-smoke/gateway-key","serving":"/tmp/auth-smoke/serving-key"},
  "peerKeyFiles":{"warehouse":"/tmp/auth-smoke/warehouse-key","serving":"/tmp/auth-smoke/serving-key","gateway":"/tmp/auth-smoke/gateway-key"},
  "peerURLs":{"warehouse":"http://127.0.0.1:1","serving":"http://127.0.0.1:1","gateway":"http://127.0.0.1:1"},
  "zoneDataFile":"/usr/local/lib/umir/zoneinfo.zip",
  "zoneDataVersion":"ci-go-1.26.9",
  "isolatedHTTP":true,
  "smtp":{"Host":"127.0.0.1","Port":1,"TLSMode":"tls","From":"auth@umir.test","To":"operator@umir.test"},
  "smtpUsernameFile":"/tmp/auth-smoke/smtp-user",
  "smtpPasswordFile":"/tmp/auth-smoke/smtp-password",
  "registrationMail":{"OperatorName":"Quality Lab","OperatorAddress":"Quality Street 1","SenderName":"Quality Lab"},
  "invitationMail":{"frontendOrigin":"http://127.0.0.1:18081","allowLoopbackHTTP":true}
}
JSON
UMIR_AUTH_CONFIG_FILE=/tmp/auth-smoke/config.json /server >/tmp/auth-smoke/server.log 2>&1 &
server_pid=$!
cleanup() {
  if kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid"
    wait "$server_pid"
  fi
}
trap cleanup EXIT
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  kill -0 "$server_pid" 2>/dev/null || { printf 'Production entrypoint exited before readiness\n' >&2; exit 1; }
  if wget -q -T 2 -O /dev/null http://127.0.0.1:18081/healthz && wget -q -T 2 -O /dev/null --header 'X-Umir-Service-Key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' http://127.0.0.1:18081/readyz; then
    ready=1
    break
  fi
  sleep 1
done
[ "$ready" = 1 ] || { printf 'Production health/readiness did not pass\n' >&2; exit 1; }
kill -TERM "$server_pid"
wait "$server_pid"
trap - EXIT
printf 'Production entrypoint, health/readiness and graceful shutdown passed\n'
