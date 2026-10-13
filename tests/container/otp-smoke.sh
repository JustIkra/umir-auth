#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 ]]; then
  printf 'usage: %s <owned-local-test-image>\n' "$0" >&2
  exit 2
fi
image=$1
docker run --rm --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=0700 \
  "$image"
docker run --rm --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=0700 \
  --workdir /module/tests/integration --entrypoint /enrollment.test \
  "$image" -test.run=TestA4 -test.timeout=60s
printf 'A4 synthetic OTP smoke passed: owner store, encrypted replay, real verified SMTP, restart and stable jobs\n'
