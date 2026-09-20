#!/usr/bin/env python3
"""Capture Codex Linux sandbox socket capability without model calls or real secrets.

The output directory must not exist. Every endpoint is synthetic and temporary.
A failed broker connection is a compatibility result, not a successful bridge.
"""

import argparse
import datetime
import hashlib
import json
import pathlib
import socket
import subprocess
import tempfile
import threading

ap = argparse.ArgumentParser()
ap.add_argument("--codex", required=True)
ap.add_argument("--out", required=True)
a = ap.parse_args()
out = pathlib.Path(a.out)
out.mkdir(parents=True, mode=0o700, exist_ok=False)
events = []
lock = threading.Lock()
phase = "control"


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def record(event, **kw):
    with lock:
        events.append(dict(time=stamp(), event=event, **kw))


with tempfile.TemporaryDirectory(
    prefix="tc-sandbox-probe-", dir=str(pathlib.Path.home())
) as d:
    p = pathlib.Path(d)
    ws = p / "workspace"
    ws.mkdir()
    listeners = []
    for label, family, address in [
        ("broker", socket.AF_UNIX, str(p / "broker.sock")),
        ("unrelated", socket.AF_UNIX, str(p / "other.sock")),
        ("ipv4", socket.AF_INET, ("127.0.0.1", 0)),
        ("ipv6", socket.AF_INET6, ("::1", 0)),
    ]:
        s = socket.socket(family)
        s.bind(address)
        s.listen()
        listeners.append((label, s))

        def accept(label=label, s=s):
            while True:
                try:
                    c, _ = s.accept()
                    record("listener_connection", listener=label, phase=phase)
                    c.sendall(b"synthetic\n")
                    c.close()
                except OSError:
                    return

        threading.Thread(target=accept, daemon=True).start()
    for label, s in listeners:
        c = socket.socket(s.family)
        c.settimeout(2)
        c.connect(s.getsockname())
        if c.recv(32) != b"synthetic\n":
            raise RuntimeError(f"host control failed for {label}")
        c.close()
    phase = "sandbox"
    token = p / "synthetic-agent-token"
    token.write_text("synthetic-only")
    token.chmod(0o600)
    endpoints = [(label, int(s.family), s.getsockname()) for label, s in listeners]
    probe = (
        """import socket,json,os,urllib.request,urllib.error
endpoints=ENDPOINTS
for label,family,address in endpoints:
 s=None
 try:
  s=socket.socket(family);s.settimeout(2);s.connect(tuple(address) if isinstance(address,list) else address);data=s.recv(32);result={"probe":label,"connected":True}
 except OSError as e:result={"probe":label,"connected":False,"errno":e.errno,"error":str(e)}
 finally:
  if s:s.close()
 print(json.dumps(result),flush=True)
try:
 with open(TOKEN) as token_file: readable=token_file.read()=="synthetic-only"
except OSError: readable=False
print(json.dumps({"probe":"outer_token_readable","readable":readable}),flush=True)
try:
 request=urllib.request.Request("http://tc-broker.invalid/",headers={"x-unix-socket":BROKER})
 response=urllib.request.urlopen(request,timeout=3);print(json.dumps({"probe":"unix_proxy","status":response.status}))
except urllib.error.HTTPError as e:print(json.dumps({"probe":"unix_proxy","status":e.code,"body":e.read(512).decode()}))
except Exception as e:print(json.dumps({"probe":"unix_proxy","error":str(e)}))
""".replace("ENDPOINTS", repr(endpoints))
        .replace("TOKEN", repr(str(token)))
        .replace("BROKER", repr(str(p / "broker.sock")))
    )
    script = ws / "probe.py"
    script.write_text(probe)
    config = (
        'default_permissions="tc"\n[features]\nnetwork_proxy=true\n[permissions.tc]\nextends=":workspace"\n[permissions.tc.network]\nenabled=true\n[permissions.tc.network.unix_sockets]\n'
        + json.dumps(str(p / "broker.sock"))
        + '="allow"\n'
    )
    (p / "config.toml").write_text(config)
    (out / "config.toml").write_text(config)
    (out / "probe.py").write_text(probe)
    version = subprocess.check_output([a.codex, "--version"], text=True).strip()
    record("start", version=version)
    result = subprocess.run(
        [a.codex, "sandbox", "-P", "tc", "-C", str(ws), "python3", str(script)],
        env={"PATH": "/usr/bin:/bin", "HOME": str(p), "CODEX_HOME": str(p)},
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    record("sandbox_exit", returncode=result.returncode)
    (out / "stdout.jsonl").write_text(result.stdout)
    (out / "stderr.log").write_text(result.stderr)
    summary = {
        "version": version,
        "binary": a.codex,
        "binary_sha256": hashlib.sha256(pathlib.Path(a.codex).read_bytes()).hexdigest(),
        "started": next(e["time"] for e in events if e["event"] == "start"),
        "returncode": result.returncode,
        "outcomes": [
            json.loads(line)
            for line in result.stdout.splitlines()
            if line.startswith("{")
        ],
        "events": events,
        "scope": "Actual Codex sandbox CLI; no model, no hook, no broker worker; synthetic token accessibility only",
    }
    summary["broker_socket_supported"] = any(
        result.get("probe") == "broker" and result.get("connected")
        for result in summary["outcomes"]
    )
    summary["sandbox_listener_connections"] = sum(
        event.get("phase") == "sandbox" for event in events
    )
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    (out / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
    print(json.dumps(summary, indent=2))
    for _, s in listeners:
        s.close()
