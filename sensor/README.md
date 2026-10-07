# selenne-sensor

Watches what AI agents do on a Linux host — programs they start, files they
open, connections they make — and sends it to Selenne Agents
(`POST /v1/host-events`), where it shows as activity and feeds the AG-2xx
rules. The kernel side is [Tetragon](https://tetragon.io) (eBPF, pinned
v1.7.1); this Go program turns its export into Selenne's format.

```
Tetragon ── JSON export ──► selenne-sensor ── gzip NDJSON ──► ingest /v1/host-events
 (kernel filters)            picks agents, links events,       (sk_sel_ key)
                             labels, masks, spools, retries
```

## What counts as an agent

Zero-config: any process started with `OTEL_SERVICE_NAME` (or `service.name`
in `OTEL_RESOURCE_ATTRIBUTES`) — the variable an OTel-instrumented agent
already has — named after it, and every process it starts. Tetragon passes
only those two variables (`--filter-environment-variables`), never the rest of
the environment. Infrastructure that sets the variable for its own tracing
(dockerd does) is ignored. Agents without OTel: `agents.match` in sensor.yaml.

## What each event carries

`kind` (exec, exit, open, connect, listen, sensor.heartbeat), `host`, `pid`,
`ppid`, `service_name`, `container_id`, `exec_id`, `proc_start_ns`, `exe`, and
per kind: `argv` (secrets masked), `path`, `daddr`/`dport` with a `scope`
(local, private, public) and a `dest_service` (a port name from
`network.port_labels`, the program seen listening on it, or a well-known port:
`ollama`, `postgres`, `qdrant (container 1c210c6eff01)`). `event_id` is stable
per Tetragon line, so a re-read after a crash never duplicates.

## Run it with Docker

On any Linux host whose kernel has BTF (`ls /sys/kernel/btf/vmlinux`):

```bash
cd sensor
SELENNE_SENSOR_KEY=sk_sel_… docker compose --profile sensor up -d
```

`docker-compose.yml` runs three services: `sensor-policies` renders the
Tetragon policies from `sensor.compose.yaml` and exits, `tetragon` (pinned,
privileged: it loads the eBPF programs) writes events to a shared volume, and
`selenne-sensor` (non-root, 10 MB distroless image) ships the agents' ones.
The host's real name comes from its `/etc/hostname`, mounted read-only.
Selenne Agents' own compose file includes this one, so on the Selenne host
the same command (from the repo root) posts straight to the `ingest`
container — set `SELENNE_SENSOR_KEY` and
`SELENNE_SENSOR_INGEST_URL=http://ingest:4318` in `.env`.

`selenne-sensor dry-run FILE…` shows what would be sent for a Tetragon export
file, without a key — handy to check `sensor.yaml` before shipping anything.

## Build, test, run

```bash
CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(git describe --always)" -o bin/selenne-sensor ./cmd/selenne-sensor
go test ./...

bin/selenne-sensor policies -config sensor.yaml -out /etc/tetragon/tetragon.tp.d
export SELENNE_SENSOR_KEY=sk_sel_…
bin/selenne-sensor run -config sensor.yaml
```

Tetragon needs: `--export-filename <export_file>`,
`--enable-process-environment-variables`,
`--filter-environment-variables OTEL_SERVICE_NAME,OTEL_RESOURCE_ATTRIBUTES`,
and `NODE_NAME` set to the host's name. `spike/run-tetragon.sh` is a working
Docker example.

## Things Tetragon does that the sensor copes with

Found running it on real hosts (`spike/`, `testdata/spike.jsonl`):

- the export is flushed late and out of order — events are held (`hold`) and
  re-sorted; one whose process start has not been read yet waits for it
  (`max_wait`; ~30 s seen on WSL2);
- on hosts where its process cache misses (WSL2's PID namespace), events come
  without process details — the sensor links them by pid and time itself;
- the export file rotates — the tailer drains the old file first, and a
  restart resumes inside a rotated file by inode;
- container ids are truncated to 31 characters — match by prefix;
- command lines carry secrets (an Erlang `-setcookie` on the dev box) —
  `argv` is masked before it leaves the host.

## Layout

```
cmd/selenne-sensor/   run | policies | dry-run | version
internal/config/      sensor.yaml + defaults
internal/tetragon/    event types; tailer (rotation, partial lines, resume)
internal/procs/       process table: agents, ignore list, linking events
internal/labels/      scope + service names
internal/mask/        secrets in command lines
internal/pipeline/    hold / wait / release → host events; file filters
internal/ship/        disk spool + sender (gzip, Retry-After, 401 keeps data)
internal/policy/      renders the Tetragon policies
spike/                Phase 0: hand policies, a fake agent, the Python prototype
```
