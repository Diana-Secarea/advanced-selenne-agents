"""Prototype of the shipper's core logic on a Tetragon export file:
which processes are agents, and which file/connect events are theirs.

    python3 sensor/spike/spike_report.py sensor/spike/out/events.log

Rules being tested (they become the Go shipper):
  * an agent process is one whose exec carries OTEL_SERVICE_NAME (or
    service.name in OTEL_RESOURCE_ATTRIBUTES), minus infrastructure that sets
    it for its own tracing (dockerd, containerd, ...);
  * children inherit the variable, and also count through parent_exec_id;
  * a kprobe event without process details (Tetragon could not enrich it)
    is linked to the latest exec of the same pid that started before it.
"""
import base64
import collections
import json
import sys

IGNORED_SERVICES = {"dockerd", "containerd", "buildkitd", "docker-proxy"}


def service_of(proc):
    env = {v["Key"]: v["Value"] for v in proc.get("environment_variables") or []}
    if env.get("OTEL_SERVICE_NAME"):
        return env["OTEL_SERVICE_NAME"]
    for part in env.get("OTEL_RESOURCE_ATTRIBUTES", "").split(","):
        k, _, v = part.partition("=")
        if k.strip() == "service.name" and v.strip():
            return v.strip()
    return None


def pid_of_exec_id(exec_id):
    try:
        return int(base64.b64decode(exec_id).decode().rsplit(":", 1)[1])
    except Exception:
        return None


events = [json.loads(line) for line in open(sys.argv[1])]
events.sort(key=lambda e: e["time"])                 # the export file is not in order
execs = collections.defaultdict(list)               # pid -> [(start_time, info)]
counts = collections.Counter()
rows = []

for e in events:
    kind = next(k for k in e if k.startswith("process_"))
    counts[kind] += 1
    p = e[kind]["process"]
    if kind == "process_exec":
        parent_pid = pid_of_exec_id(p.get("parent_exec_id", ""))
        service = service_of(p)
        if service in IGNORED_SERVICES:
            service = None
        if service is None and parent_pid in execs:                  # ancestry fallback
            service = execs[parent_pid][-1][1]["service"]
        info = {"service": service, "binary": p.get("binary"), "args": p.get("arguments", ""),
                "exec_id": p["exec_id"], "parent_pid": parent_pid, "docker": p.get("docker")}
        execs[p["pid"]].append((p["start_time"], info))
        if service:
            rows.append((e["time"], service, "exec", p["pid"], f'{p["binary"]} {p.get("arguments", "")}'[:90]))
    elif kind == "process_kprobe":
        k = e[kind]
        cands = [i for t, i in execs.get(p["pid"], []) if t <= e["time"]]
        info = cands[-1] if cands else None
        service = info and info["service"]
        arg = (k.get("args") or [{}])[0]
        if "file_arg" in arg:
            what = ("open", arg["file_arg"]["path"])
        elif "sock_arg" in arg:
            s = arg["sock_arg"]
            what = ("connect", f'{s.get("daddr")}:{s.get("dport")}')
        else:
            what = (k["function_name"], json.dumps(arg)[:60])
        counts[f"{what[0]} ({'agent' if service else 'not agent'})"] += 1
        if service:
            rows.append((e["time"], service, what[0], p["pid"], what[1]))

print("event counts:", dict(counts))
print(f"\n{'time':12} {'service':14} {'kind':8} {'pid':>6}  detail")
for t, service, kind, pid, detail in rows:
    print(f"{t[11:23]:12} {service:14} {kind:8} {pid:>6}  {detail}")
