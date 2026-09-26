#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# ccgui-asm-bridge
# Copyright (C) 2026 SnapKitty Collective
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""PyTorch harness for mcpd-asm (ccgui-asm-bridge).

Spins up the pure-assembly TCP MCP server, runs the full MCP protocol suite
against it, then trains a tiny torch classifier on the *live* server responses
(ok vs. byte-mutated) and verifies the model classifies every live response as
ok. Any failure exits non-zero.
"""
import json
import os
import random
import shutil
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "build", "mcpd")
HOST, PORT = "127.0.0.1", 7341

CHECKS = []
def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))
    return cond

class MCP:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=5)
        self.f = self.s.makefile("r", encoding="utf-8")
        self.n = 0
        self.live_texts = []

    def call(self, method, params=None, nid=None):
        self.n += 1
        rid = self.n if nid is None else nid
        msg = {"jsonrpc": "2.0", "method": method}
        if rid is not None:
            msg["id"] = rid
        if params is not None:
            msg["params"] = params
        self.s.sendall((json.dumps(msg) + "\n").encode())
        if rid is None:
            return None  # notification: no reply
        line = self.f.readline()
        assert line, "server closed connection"
        resp = json.loads(line)
        self.live_texts.append(line.strip())
        return resp

    def close(self):
        self.f.close()
        self.s.close()

def wait_port():
    for _ in range(100):
        try:
            s = socket.create_connection((HOST, PORT), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False

def main():
    random.seed(7)
    # stage a root-local echo binary so bridge.exec has something policy-clean to run
    staged = os.path.join(ROOT, "echo")
    shutil.copy("/bin/echo", staged)
    os.chmod(staged, 0o755)
    # work dir for bridge.write_file/read_file tests
    os.makedirs(os.path.join(ROOT, "work"), exist_ok=True)

    srv = subprocess.Popen([BIN, str(PORT)], cwd=ROOT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_port(), "server did not come up"
        # the accept loop eats our probe connection; give it a beat
        time.sleep(0.2)
        m = MCP()

        r = m.call("initialize", {"protocolVersion": "2024-11-05",
                                  "capabilities": {},
                                  "clientInfo": {"name": "harness", "version": "0.1"}})
        check("initialize.protocolVersion", r.get("result", {}).get("protocolVersion") == "2024-11-05", str(r)[:120])
        check("initialize.id-echo", r.get("id") == 1, str(r)[:80])

        r = m.call("ping")
        check("ping", r.get("result") == {}, str(r)[:80])

        r = m.call("tools/list")
        names = {t["name"] for t in r.get("result", {}).get("tools", [])}
        check("tools/list", names == {"bridge.echo", "bridge.identity",
                                      "bridge.policy_check", "bridge.exec",
                                      "bridge.read_file", "bridge.write_file",
                                      "bridge.list_dir", "bridge.system_info"}, str(names))

        r = m.call("tools/call", {"name": "bridge.echo", "arguments": {"msg": "hello"}})
        check("bridge.echo", r.get("result", {}).get("echo", {}).get("msg") == "hello", str(r)[:120])

        r = m.call("tools/call", {"name": "bridge.identity"})
        ident = r.get("result", {})
        check("bridge.identity", ident.get("name") == "mcpd-asm" and ident.get("arch") == "x86-64"
              and ident.get("root") == ROOT, str(ident)[:120])

        r = m.call("tools/call", {"name": "bridge.policy_check", "arguments": {"path": "/tmp/work/x.txt"}})
        pr = r.get("result", {})
        check("policy.rewrite-tmp", pr.get("verdict") == "rewritten"
              and pr.get("path") == os.path.join(ROOT, "work/x.txt"), str(pr)[:120])

        r = m.call("tools/call", {"name": "bridge.policy_check", "arguments": {"path": "/etc/passwd"}})
        check("policy.block-etc", r.get("result", {}).get("verdict") == "blocked", str(r)[:120])

        r = m.call("tools/call", {"name": "bridge.policy_check",
                                  "arguments": {"path": "~/.ssh/id_rsa"}})
        check("policy.block-ssh", r.get("result", {}).get("verdict") == "blocked", str(r)[:120])

        r = m.call("tools/call", {"name": "bridge.policy_check",
                                  "arguments": {"path": "/tmp/../../etc/shadow"}})
        check("policy.block-traversal", r.get("result", {}).get("verdict") == "blocked", str(r)[:120])

        r = m.call("tools/call", {"name": "bridge.exec",
                                  "arguments": {"command": "echo", "args": ["hello-from-asm"]}})
        er = r.get("result", {})
        check("exec.gated-run", er.get("exit_code") == 0 and "hello-from-asm" in er.get("stdout", ""),
              str(er)[:120])

        r = m.call("tools/call", {"name": "bridge.exec",
                                  "arguments": {"command": "echo", "args": ["/etc/passwd"]}})
        check("exec.blocked-arg", r.get("error", {}).get("code") == 44001, str(r)[:120])

        r = m.call("tools/call", {"name": "bridge.write_file",
                                  "arguments": {"path": "work/harness.txt", "content": "harness-write-ok"}})
        check("write_file", r.get("result", {}).get("bytes") == 16, str(r)[:120])

        r = m.call("tools/call", {"name": "bridge.read_file",
                                  "arguments": {"path": "work/harness.txt"}})
        rr = r.get("result", {})
        check("read_file", rr.get("content") == "harness-write-ok" and rr.get("bytes") == 16,
              str(rr)[:120])

        r = m.call("tools/call", {"name": "bridge.list_dir", "arguments": {"path": "."}})
        lr = r.get("result", {})
        check("list_dir", isinstance(lr.get("entries"), list) and len(lr["entries"]) > 0,
              str(lr)[:120])

        r = m.call("tools/call", {"name": "bridge.system_info", "arguments": {}})
        sr = r.get("result", {})
        check("system_info", sr.get("sysname") == "Linux" and sr.get("machine") == "x86_64",
              str(sr)[:120])

        r = m.call("tools/call", {"name": "bridge.write_file",
                                  "arguments": {"path": "/etc/evil", "content": "x"}})
        check("write_file.blocked", r.get("error", {}).get("code") == 44001, str(r)[:120])

        r = m.call("tools/call", {"name": "bridge.exec",
                                  "arguments": {"command": "/bin/echo", "args": ["hi"]}})
        check("exec.blocked-cmd", r.get("error", {}).get("code") == 44001, str(r)[:120])

        r = m.call("tools/call", {"name": "bridge.nope", "arguments": {}})
        check("unknown-tool", r.get("error", {}).get("code") == -32602, str(r)[:120])

        r = m.call("does/not-exist")
        check("unknown-method", r.get("error", {}).get("code") == -32601, str(r)[:120])

        # notification: no id -> server must stay silent
        m.s.sendall(b'{"jsonrpc":"2.0","method":"notifications/ping"}\n')
        m.s.settimeout(1.0)
        try:
            extra = m.s.recv(4096)
            check("notification.silent", extra == b"", f"got {extra[:60]!r}")
        except socket.timeout:
            check("notification.silent", True)
        m.s.settimeout(5)
        m.close()

        # ---------------- torch: classify live server responses ----------------
        import torch
        import torch.nn as nn
        torch.manual_seed(0)

        def feats(texts):
            X = []
            for t in texts:
                h = [0.0] * 256
                b = t.encode("utf-8", "replace")
                for x in b:
                    h[x] += 1.0
                n = float(len(b)) or 1.0
                X.append([v / n for v in h])
            return torch.tensor(X, dtype=torch.float32)

        def mutate(t):
            b = bytearray(t.encode("utf-8", "replace"))
            for _ in range(max(1, len(b) // 8)):
                b[random.randrange(len(b))] = random.randrange(256)
            return bytes(b).decode("utf-8", "replace")

        live = m.live_texts
        assert len(live) >= 10, f"only {len(live)} live responses captured"
        bad = [mutate(t) for t in live for _ in range(2)]
        X = feats(live + bad)
        y = torch.tensor([0] * len(live) + [1] * len(bad))

        model = nn.Sequential(nn.Linear(256, 64), nn.ReLU(), nn.Linear(64, 2))
        opt = torch.optim.Adam(model.parameters(), lr=0.02)
        loss_fn = nn.CrossEntropyLoss()
        for step in range(400):
            opt.zero_grad()
            loss = loss_fn(model(X), y)
            loss.backward()
            opt.step()
        with torch.no_grad():
            pred_live = model(feats(live)).argmax(1).tolist()
            pred_bad = model(feats(bad)).argmax(1).tolist()
        acc_bad = sum(pred_bad) / len(pred_bad)
        print(f"[torch] final loss={loss.item():.4f} live-ok={sum(p == 0 for p in pred_live)}/{len(pred_live)} "
              f"mutated-caught={acc_bad:.2f}")
        check("torch.live-classified-ok", all(p == 0 for p in pred_live),
              str(pred_live))
        check("torch.mutations-mostly-caught", acc_bad >= 0.80, f"{acc_bad:.2f}")

        failed = [n for n, ok, _ in CHECKS if not ok]
        print(f"\n{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed (torch {torch.__version__})")
        return 1 if failed else 0
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
        if os.path.exists(staged):
            os.remove(staged)

if __name__ == "__main__":
    sys.exit(main())
