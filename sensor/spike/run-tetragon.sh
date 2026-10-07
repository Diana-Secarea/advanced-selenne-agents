#!/usr/bin/env bash
# Phase 0 spike: Tetragon in Docker, writing JSON events to $OUT/events.log.
#   sensor/spike/run-tetragon.sh [out-dir] [policies-dir]   stop: docker rm -f selenne-tetragon
# policies-dir defaults to the spike's hand-written ones; for the generated
# ones: sensor/bin/selenne-sensor policies -out <dir>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(realpath -m "${1:-$HERE/out}")"
POLICIES="$(realpath "${2:-$HERE/policies}")"
mkdir -p "$OUT"
docker rm -f selenne-tetragon >/dev/null 2>&1 || true
docker run -d --name selenne-tetragon \
  --pid=host --cgroupns=host --privileged \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro \
  -e NODE_NAME="$(hostname)" \
  -v "$POLICIES:/etc/tetragon/tetragon.tp.d:ro" \
  -v "$OUT:/var/run/tetragon-export" \
  --entrypoint tetragon \
  quay.io/cilium/tetragon:v1.7.1 \
  --export-filename /var/run/tetragon-export/events.log \
  --export-file-perm 644 \
  --export-file-max-size-mb 50 \
  --enable-process-environment-variables \
  --filter-environment-variables OTEL_SERVICE_NAME,OTEL_RESOURCE_ATTRIBUTES \
  --enable-ancestors base,kprobe
echo "tetragon started; events -> $OUT/events.log"
