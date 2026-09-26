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

"""
ws_bridge.py — WebSocket ↔ TCP bridge for the mcpd-asm MCP server.

Browsers can't speak raw TCP, so this bridge:
  1. Accepts WebSocket connections from the web frontend
  2. Proxies JSON-RPC 2.0 messages to the assembly MCP server (127.0.0.1:7341)
  3. Adds bridge-local tools the asm server doesn't implement:
     - bridge.web_fetch  — HTTP GET via Python (URL allowlist)
     - bridge.generate   — GLM evoke generation (if EVOKE_URL is set)

Run:
    python3 bridge/ws_bridge.py [--mcp-host 127.0.0.1 --mcp-port 7341 --ws-port 8765]
"""
import argparse
import asyncio
import json
import os
import socket
import urllib.request
import urllib.parse

try:
    import websockets
except ImportError:
    raise SystemExit("pip install websockets")

MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.environ.get("MCP_PORT", "7341"))
WS_PORT = int(os.environ.get("WS_PORT", "8765"))
EVOKE_URL = os.environ.get("EVOKE_URL", "")  # e.g. http://127.0.0.1:8080/generate

# Extra tools served by the bridge itself (not the asm server)
BRIDGE_TOOLS = [
    {"name": "bridge.web_fetch",
     "description": "Fetch a URL over HTTP(S) and return status + first 8KB of body",
     "inputSchema": {"type": "object", "required": ["url"],
                     "properties": {"url": {"type": "string"}}}},
    {"name": "bridge.generate",
     "description": "Generate tokens via the GLM evoke backend (if configured)",
     "inputSchema": {"type": "object", "required": ["prompt"],
                     "properties": {"prompt": {"type": "string"},
                                    "max_tokens": {"type": "integer"}}}},
]

# Simple allowlist for web_fetch (avoid SSRF to internal services)
BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
BLOCKED_SUFFIXES = (".internal", ".local")


def mcp_roundtrip(message: dict, timeout: float = 10.0) -> dict:
    """Send one JSON-RPC message to the asm MCP server, return the parsed reply."""
    s = socket.create_connection((MCP_HOST, MCP_PORT), timeout=timeout)
    try:
        s.sendall((json.dumps(message) + "\n").encode())
        f = s.makefile("r")
        line = f.readline()
        if not line:
            return {"jsonrpc": "2.0", "id": message.get("id"),
                    "error": {"code": -32603, "message": "empty reply from mcpd"}}
        return json.loads(line)
    finally:
        s.close()


def tool_web_fetch(args: dict, msg_id) -> dict:
    url = args.get("url", "")
    try:
        parts = urllib.parse.urlparse(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError("only http/https allowed")
        host = (parts.hostname or "").lower()
        if host in BLOCKED_HOSTS or host.endswith(BLOCKED_SUFFIXES):
            raise ValueError("host not allowed")
        req = urllib.request.Request(url, headers={"User-Agent": "mcpd-asm-bridge/0.1"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
            result = {"status": resp.status, "url": url,
                      "content_type": resp.headers.get("Content-Type", ""),
                      "body": body}
    except Exception as e:
        return {"jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32603, "message": f"fetch failed: {e}"}}
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def tool_generate(args: dict, msg_id) -> dict:
    prompt = args.get("prompt", "")
    max_tokens = int(args.get("max_tokens", 32))
    if not EVOKE_URL:
        return {"jsonrpc": "2.0", "id": msg_id, "result": {
            "status": "unavailable",
            "backend": "glm-evoke",
            "hint": "Set EVOKE_URL to a running evoke generate endpoint, "
                    "e.g. EVOKE_URL=http://127.0.0.1:8080/generate",
            "echo_prompt": prompt[:200],
        }}
    try:
        payload = json.dumps({"prompt": prompt, "max_tokens": max_tokens}).encode()
        req = urllib.request.Request(EVOKE_URL, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode())
        return {"jsonrpc": "2.0", "id": msg_id,
                "result": {"status": "ok", "backend": "glm-evoke", **data}}
    except Exception as e:
        return {"jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32603, "message": f"evoke backend error: {e}"}}


BRIDGE_HANDLERS = {
    "bridge.web_fetch": tool_web_fetch,
    "bridge.generate": tool_generate,
}


async def handle_ws(ws):
    peer = ws.remote_address
    print(f"[ws] client {peer}")
    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except Exception:
                await ws.send(json.dumps({"jsonrpc": "2.0", "id": None,
                                          "error": {"code": -32700, "message": "parse error"}}))
                continue
            method = msg.get("method")
            msg_id = msg.get("id")

            # tools/list: merge asm tools + bridge tools
            if method == "tools/list":
                reply = mcp_roundtrip(msg)
                if "result" in reply:
                    reply["result"].setdefault("tools", []).extend(BRIDGE_TOOLS)
                await ws.send(json.dumps(reply))
                continue

            # tools/call: route bridge.* local tools here, rest to asm
            if method == "tools/call":
                params = msg.get("params", {})
                name = params.get("name", "")
                if name in BRIDGE_HANDLERS:
                    args = params.get("arguments", {})
                    reply = BRIDGE_HANDLERS[name](args, msg_id)
                    await ws.send(json.dumps(reply))
                    continue
                # fall through to asm

            # default: proxy to asm MCP server
            try:
                reply = await asyncio.to_thread(mcp_roundtrip, msg)
            except Exception as e:
                reply = {"jsonrpc": "2.0", "id": msg_id,
                         "error": {"code": -32603, "message": f"mcpd unreachable: {e}"}}
            await ws.send(json.dumps(reply))
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        print(f"[ws] bye {peer}")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mcp-host", default=MCP_HOST)
    ap.add_argument("--mcp-port", type=int, default=MCP_PORT)
    ap.add_argument("--ws-port", type=int, default=WS_PORT)
    a = ap.parse_args()
    # rebind module globals for the chosen MCP endpoint
    globals()["MCP_HOST"], globals()["MCP_PORT"] = a.mcp_host, a.mcp_port
    print(f"[ws] listening on 0.0.0.0:{a.ws_port} -> mcp {a.mcp_host}:{a.mcp_port}")
    if EVOKE_URL:
        print(f"[ws] evoke backend configured")
    else:
        print("[ws] evoke backend: not configured")
    async with websockets.serve(handle_ws, "0.0.0.0", a.ws_port):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
