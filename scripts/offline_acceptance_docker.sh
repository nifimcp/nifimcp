#!/bin/sh
# Run the offline kit acceptance (A30) in a container with no network and record evidence.
#   scripts/offline_acceptance_docker.sh [IMAGE]
# Default image: the official python:3.12-slim library image, pinned by digest (pulled via mirror.gcr.io
# because Docker Hub rate-limited this environment; the digest is the same content-addressed image).
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMG="${1:-mirror.gcr.io/library/python@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159}"
KIT="$(ls -d "$ROOT"/dist/nifimcp-offline-*-linux-x86_64-cp312 | head -1)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/evidence/offline/$STAMP"
mkdir -p "$OUT"
echo "docker run --rm --network none -v <kit>:/kit:ro $IMG sh /kit/offline_acceptance.sh" > "$OUT/command.txt"
set +e
docker run --rm --network none -v "$KIT":/kit:ro "$IMG" \
    sh -c 'head -1 /etc/os-release; uname -m; python3.12 --version; sh /kit/offline_acceptance.sh' > "$OUT/run.log" 2>&1
rc=$?
set -e
echo "$rc" > "$OUT/exit_code"
cp "$KIT/SHA256SUMS" "$OUT/kit-SHA256SUMS"
cp "$KIT".tar.gz.sha256 "$OUT/"
printf '{"image": "%s", "network": "none", "kit": "%s"}\n' "$IMG" "$(basename "$KIT")" > "$OUT/environment.json"
tail -3 "$OUT/run.log"
echo "evidence: $OUT (exit $rc)"
exit "$rc"
