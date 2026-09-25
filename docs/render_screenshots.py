#!/usr/bin/env python3
"""Render terminal-style demo screenshots from captured MCP session."""
import json
import os
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "screenshots")
os.makedirs(OUT, exist_ok=True)

# Colors (GitHub dark terminal theme)
BG = (13, 17, 23)
TITLE_BG = (22, 27, 34)
GREEN = (63, 185, 80)      # $
WHITE = (230, 237, 243)    # command text
DIM = (139, 148, 158)      # request JSON
KEY = (121, 192, 255)      # JSON keys
STR = (165, 214, 255)      # JSON strings
NUM = (255, 166, 87)       # numbers
BOOL = (255, 123, 114)     # booleans
PUNCT = (139, 148, 158)    # punctuation

def get_font(size=16):
    for p in [
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    ]:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()

FONT = get_font(15)
TITLE_FONT = get_font(13)
PAD = 24
LINE_H = 24

def tokenize_json(s):
    """Simple JSON tokenizer yielding (text, color)."""
    tokens = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while j < n and s[j] != '"':
                if s[j] == '\\':
                    j += 1
                j += 1
            j += 1
            txt = s[i:j]
            # peek: is it a key? (followed by :)
            k = j
            while k < n and s[k] in ' \t':
                k += 1
            color = KEY if (k < n and s[k] == ':') else STR
            tokens.append((txt, color))
            i = j
        elif c.isdigit() or (c == '-' and i + 1 < n and s[i+1].isdigit()):
            j = i + 1
            while j < n and (s[j].isdigit() or s[j] in '.eE+-'):
                j += 1
            tokens.append((s[i:j], NUM))
            i = j
        elif s.startswith("true", i) or s.startswith("false", i) or s.startswith("null", i):
            for w in ("true", "false", "null"):
                if s.startswith(w, i):
                    tokens.append((w, BOOL))
                    i += len(w)
                    break
        else:
            tokens.append((c, PUNCT))
            i += 1
    return tokens

def wrap_tokens(tokens, draw, max_w):
    """Wrap tokens into lines that fit max_w."""
    lines = []
    cur = []
    cur_w = 0
    for txt, color in tokens:
        # split long tokens if needed
        while txt:
            # try to fit as much as possible
            w = draw.textlength(txt, font=FONT)
            if cur_w + w <= max_w or not cur:
                # check if it fits, else split
                if cur_w + w <= max_w:
                    cur.append((txt, color))
                    cur_w += w
                    txt = ""
                else:
                    # binary split
                    lo, hi = 1, len(txt)
                    while lo < hi:
                        mid = (lo + hi + 1) // 2
                        if cur_w + draw.textlength(txt[:mid], font=FONT) <= max_w:
                            lo = mid
                        else:
                            hi = mid - 1
                    part = txt[:lo] or txt[:1]
                    cur.append((part, color))
                    cur_w += draw.textlength(part, font=FONT)
                    txt = txt[len(part):]
                    lines.append(cur)
                    cur, cur_w = [], 0
            else:
                lines.append(cur)
                cur, cur_w = [], 0
    if cur:
        lines.append(cur)
    return lines

def render(lines_spec, title, outpath, width=980):
    """lines_spec: list of (kind, text) where kind in 'cmd','req','resp'."""
    tmp = Image.new("RGB", (width, 100))
    d = ImageDraw.Draw(tmp)
    max_w = width - PAD * 2

    rendered = []  # list of (kind, token_lines)
    for kind, text in lines_spec:
        if kind == "cmd":
            rendered.append(("cmd", [[(text, WHITE)]]))
        else:
            if kind == "resp":
                try:
                    text = json.dumps(json.loads(text), indent=1)
                except Exception:
                    pass
                # split into physical lines first, tokenize each
                wrapped = []
                for phys in text.split("\n"):
                    toks = tokenize_json(phys)
                    wrapped.extend(wrap_tokens(toks, d, max_w - 20))
            else:
                # compact req to one line, truncate if too long
                if len(text) > 120:
                    text = text[:117] + "..."
                toks = [(text, DIM)]
                wrapped = wrap_tokens(toks, d, max_w)
            # indent resp lines
            rendered.append((kind, wrapped))

    # compute height
    h = 44  # title bar
    h += PAD
    for kind, wlines in rendered:
        h += len(wlines) * LINE_H
        h += 8  # gap between blocks
    h += PAD

    img = Image.new("RGB", (width, h), BG)
    d = ImageDraw.Draw(img)
    # title bar
    d.rectangle([0, 0, width, 36], fill=TITLE_BG)
    d.ellipse([14, 12, 26, 24], fill=(255, 95, 86))
    d.ellipse([32, 12, 44, 24], fill=(255, 189, 46))
    d.ellipse([50, 12, 62, 24], fill=(39, 201, 63))
    tw = d.textlength(title, font=TITLE_FONT)
    d.text(((width - tw) / 2, 9), title, font=TITLE_FONT, fill=DIM)

    y = 44 + PAD
    for kind, wlines in rendered:
        x0 = PAD
        for li, line in enumerate(wlines):
            x = x0
            if kind == "cmd" and li == 0:
                # green $ prompt
                d.text((x, y), "$ ", font=FONT, fill=GREEN)
                x += d.textlength("$ ", font=FONT)
            elif kind == "resp":
                if li == 0:
                    d.text((x, y), "← ", font=FONT, fill=GREEN)
                    x += d.textlength("← ", font=FONT)
                else:
                    x += d.textlength("← ", font=FONT)
            elif kind == "req" and li == 0:
                d.text((x, y), "→ ", font=FONT, fill=DIM)
                x += d.textlength("→ ", font=FONT)
            for txt, color in line:
                # for cmd, first token includes "$ "? no, we handled prompt
                if kind == "cmd" and li == 0 and txt.startswith("$"):
                    txt = txt[1:].lstrip()
                    if not txt:
                        continue
                d.text((x, y), txt, font=FONT, fill=color)
                x += d.textlength(txt, font=FONT)
            y += LINE_H
        y += 8

    img.save(outpath)
    print(f"wrote {outpath} ({width}x{h})")

def main():
    session = json.load(open("/tmp/demo_capture.json"))
    # group by id
    by_id = {}
    order = []
    cur_cmd = ""
    for typ, text in session:
        if typ == "cmd":
            cur_cmd = text.lstrip("$ ")
        elif typ == "req":
            d = json.loads(text)
            by_id[d["id"]] = {"cmd": cur_cmd, "req": text, "resp": None}
            order.append(d["id"])
        elif typ == "resp":
            d = json.loads(text)
            by_id[d["id"]]["resp"] = text

    # Screenshot 1: handshake + tools/list
    spec1 = []
    for i in [1, 2]:
        e = by_id[i]
        spec1.append(("cmd", e["cmd"]))
        spec1.append(("req", e["req"]))
        spec1.append(("resp", e["resp"]))
    render(spec1, "mcpd-asm — MCP handshake & tool registry", os.path.join(OUT, "01-handshake.png"))

    # Screenshot 2: policy gate
    spec2 = []
    for i in [3, 4]:
        e = by_id[i]
        spec2.append(("cmd", e["cmd"]))
        spec2.append(("req", e["req"]))
        spec2.append(("resp", e["resp"]))
    render(spec2, "mcpd-asm — permission gate: rewrite & block", os.path.join(OUT, "02-policy-gate.png"))

    # Screenshot 3: exec
    spec3 = []
    for i in [5, 6]:
        e = by_id[i]
        spec3.append(("cmd", e["cmd"]))
        spec3.append(("req", e["req"]))
        spec3.append(("resp", e["resp"]))
    render(spec3, "mcpd-asm — policy-gated exec", os.path.join(OUT, "03-exec.png"))

if __name__ == "__main__":
    main()
