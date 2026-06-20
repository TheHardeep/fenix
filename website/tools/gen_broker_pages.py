#!/usr/bin/env python3
"""Generate per-broker documentation pages for fenix and fenixpro by static
AST inspection (no imports, so optional broker deps aren't required).

Outputs:
  content/broker-<mod>.md          one page per fenix broker
  content/pro-broker-<mod>.md      one page per fenixpro adapter
  tools/_nav_brokers.json          nav entries to wire into assets/js/nav.js

Run from the DocsSite folder:  python tools/gen_broker_pages.py
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SITE = HERE.parent
CONTENT = SITE / "content"
FENIX = Path(r"D:/Work/Fenix/fenix/fenix")
FENIXPRO = Path(r"D:/Work/Fenix/fenixpro/fenixpro")

FENIX_BROKERS = [
    "aliceblue", "angelone", "anandrathi", "dhan", "finvasia", "fivepaisa",
    "fyers", "groww", "iifl", "kotakneo", "mastertrust", "motilaloswal",
    "symphony", "upstox", "zerodha",
]
PRO_BROKERS = [
    "aliceblue", "angelone", "finvasia", "fivepaisa", "fyers", "iifl",
    "kotak", "kotakneo", "kunjee", "mastertrust", "motilaloswal", "symphony",
    "upstox", "vpc", "zerodha",
]

DISPLAY = {
    "aliceblue": "AliceBlue", "angelone": "Angel One", "anandrathi": "Anand Rathi",
    "dhan": "Dhan", "finvasia": "Finvasia", "fivepaisa": "5paisa", "fyers": "Fyers",
    "groww": "Groww", "iifl": "IIFL", "kotak": "Kotak", "kotakneo": "Kotak Neo",
    "kunjee": "Kunjee", "mastertrust": "Master Trust", "motilaloswal": "Motilal Oswal",
    "symphony": "Symphony", "upstox": "Upstox", "vpc": "VPC", "zerodha": "Zerodha",
}


def first_line(doc: str | None) -> str:
    if not doc:
        return ""
    for line in doc.strip().splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def find_class(tree: ast.Module) -> ast.ClassDef | None:
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            return node
    return None


def get_assign(cls: ast.ClassDef, name: str):
    for node in cls.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return node.value
    return None


def describe_dict(cls: ast.ClassDef) -> dict[str, ast.AST]:
    for node in cls.body:
        if isinstance(node, ast.FunctionDef) and node.name == "describe":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Dict):
                    out = {}
                    for k, v in zip(sub.value.keys, sub.value.values):
                        if isinstance(k, ast.Constant):
                            out[k.value] = v
                    return out
    return {}


def const_list(node: ast.AST | None) -> list:
    if isinstance(node, ast.List):
        return [e.value for e in node.elts if isinstance(e, ast.Constant)]
    return []


def signature(fn: ast.FunctionDef) -> str:
    a = fn.args
    parts: list[str] = []
    allpos = a.posonlyargs + a.args
    ndef = len(a.defaults)
    nno = len(allpos) - ndef
    for i, arg in enumerate(allpos):
        if arg.arg == "self":
            continue
        if i >= nno:
            d = a.defaults[i - nno]
            parts.append(f"{arg.arg}={ast.unparse(d)}")
        else:
            parts.append(arg.arg)
    if a.vararg:
        parts.append("*" + a.vararg.arg)
    for i, arg in enumerate(a.kwonlyargs):
        d = a.kw_defaults[i]
        parts.append(f"{arg.arg}={ast.unparse(d)}" if d is not None else arg.arg)
    if a.kwarg:
        parts.append("**" + a.kwarg.arg)
    return f"{fn.name}(" + ", ".join(parts) + ")"


def public_methods(cls: ast.ClassDef):
    out = []
    for node in cls.body:
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
            out.append((node.name, signature(node), first_line(ast.get_docstring(node))))
    return out


def md_escape(s: str) -> str:
    return s.replace("|", "\\|")


# ── fenix broker pages ────────────────────────────────────────────────────
def gen_fenix(mod: str) -> tuple[str, str]:
    tree = ast.parse((FENIX / f"{mod}.py").read_text(encoding="utf-8"))
    cls = find_class(tree)
    assert cls is not None
    cls_name = cls.name
    cls_doc = first_line(ast.get_docstring(cls))
    desc = describe_dict(cls)

    bid = desc.get("id")
    bid = bid.value if isinstance(bid, ast.Constant) else cls_name
    token_params = const_list(desc.get("tokenParams"))
    sens = const_list(desc.get("sensitiveLogKeys"))

    api = get_assign(cls, "_API")
    servers, paths, doc_link = {}, {}, None
    if isinstance(api, ast.Dict):
        for k, v in zip(api.keys, api.values):
            if not isinstance(k, ast.Constant):
                continue
            if k.value == "doc" and isinstance(v, ast.Constant):
                doc_link = v.value
            elif k.value == "servers" and isinstance(v, ast.Dict):
                for sk, sv in zip(v.keys, v.values):
                    if isinstance(sk, ast.Constant) and isinstance(sv, ast.Constant):
                        servers[sk.value] = sv.value
            elif k.value == "paths" and isinstance(v, ast.Dict):
                for pk, pv in zip(v.keys, v.values):
                    if not isinstance(pk, ast.Constant):
                        continue
                    if isinstance(pv, ast.Constant):
                        paths[pk.value] = ("", pv.value)
                    elif isinstance(pv, ast.Dict):
                        d = {a.value: b.value for a, b in zip(pv.keys, pv.values)
                             if isinstance(a, ast.Constant) and isinstance(b, ast.Constant)}
                        paths[pk.value] = (d.get("server", ""), d.get("path", ""))

    rate = desc.get("rateLimits")
    rate_src = ast.unparse(rate) if rate is not None else ""

    methods = public_methods(cls)
    load_methods = [m for m in methods if m[0].startswith("load_")]

    L = []
    L.append(f"# {DISPLAY.get(mod, cls_name)}")
    L.append("")
    if cls_doc:
        L.append(f"> {cls_doc}")
        L.append("")
    L.append("| | |")
    L.append("|---|---|")
    L.append(f"| **Class** | `fenix.{cls_name}` |")
    L.append(f"| **`id`** | `{bid}` |")
    L.append(f"| **Module** | `fenix/{mod}.py` |")
    if doc_link:
        L.append(f"| **Broker API docs** | [{doc_link}]({doc_link}) |")
    if token_params:
        L.append(f"| **Auth params** | {', '.join(f'`{p}`' for p in token_params)} |")
    L.append(f"| **Endpoints** | {len(paths)} |")
    L.append(f"| **Methods** | {len(methods)} public |")
    L.append("")
    L.append("This adapter implements the [unified Fenix API](#/orders). Every method below "
             "returns the standardized [JSON schemas](#/unified-json) and is throttled, logged, "
             "and error-mapped by the [`Broker`](#/architecture) base class.")
    L.append("")

    if token_params:
        L.append("## Authentication")
        L.append("")
        L.append(f"`{cls_name}.authenticate()` requires these credentials (its `tokenParams`):")
        L.append("")
        for p in token_params:
            L.append(f"- `{p}`")
        L.append("")
        L.append("```python")
        L.append(f"from fenix import {cls_name}")
        L.append(f"broker = {cls_name}()")
        L.append("broker.authenticate(params={")
        for p in token_params:
            L.append(f'    "{p}": "...",')
        L.append("})")
        L.append("```")
        L.append("")
        L.append("See [Authentication](#/authentication) for session reuse and paper-mode login.")
        L.append("")

    if load_methods:
        L.append("## Instrument tokens")
        L.append("")
        L.append("Token loaders available on this adapter (see [Instrument Tokens](#/tokens)):")
        L.append("")
        L.append("| Method | Loads |")
        L.append("|--------|-------|")
        for name, sig, fl in load_methods:
            L.append(f"| `{name}()` | {md_escape(fl) or '—'} |")
        L.append("")

    if servers or paths:
        L.append("## Endpoints (`_API`)")
        L.append("")
        if servers:
            L.append("**Servers**")
            L.append("")
            L.append("| Name | Base URL |")
            L.append("|------|----------|")
            for n, u in servers.items():
                L.append(f"| `{n}` | `{u}` |")
            L.append("")
        if paths:
            L.append("**Paths** — resolved by `get_url(\"name\")` (see [API Endpoints](#/api-endpoints)).")
            L.append("")
            L.append("| Endpoint | Server | Path |")
            L.append("|----------|--------|------|")
            for n, (srv, pth) in paths.items():
                L.append(f"| `{n}` | {('`'+srv+'`') if srv else '—'} | `{md_escape(pth)}` |")
            L.append("")

    if rate_src:
        L.append("## Rate limits")
        L.append("")
        L.append("Token-bucket limits per [endpoint group](#/rate-limiting):")
        L.append("")
        L.append("```python")
        L.append("rateLimits = " + rate_src)
        L.append("```")
        L.append("")

    L.append("## Methods")
    L.append("")
    L.append(f"The `{cls_name}` adapter defines {len(methods)} public methods. In addition, it "
             "inherits the [order convenience wrappers](#/orders) "
             "(`market_buy_order`, `limit_order`, `sl_sell_order`, …) generated by the base class.")
    L.append("")
    for name, sig, fl in methods:
        L.append(f"### {name}")
        L.append("")
        L.append("```python")
        L.append(f"{cls_name}.{sig}")
        L.append("```")
        L.append("")
        if fl:
            L.append(md_escape(fl) if False else fl)
            L.append("")

    L.append("---")
    L.append("")
    L.append("_This page is generated from the adapter source. See the "
             "[unified method guides](#/orders) for full request/response details that apply to every broker._")
    L.append("")
    return f"broker-{mod}", "\n".join(L)


# ── fenixpro adapter pages ────────────────────────────────────────────────
def gen_pro(mod: str) -> tuple[str, str]:
    tree = ast.parse((FENIXPRO / f"{mod}.py").read_text(encoding="utf-8"))
    cls = find_class(tree)
    assert cls is not None
    cls_name = cls.name
    cls_doc = first_line(ast.get_docstring(cls))
    bases = [ast.unparse(b) for b in cls.bases]
    methods = public_methods(cls)
    sub = [m for m in methods if "subscribe" in m[0] or m[0] in ("start_websocket", "close_websocket")]

    L = []
    L.append(f"# {DISPLAY.get(mod, cls_name)} — Live Feed")
    L.append("")
    if cls_doc:
        L.append(f"> {cls_doc}")
        L.append("")
    L.append("| | |")
    L.append("|---|---|")
    L.append(f"| **Class** | `fenixpro.{cls_name}` |")
    L.append(f"| **Module** | `fenixpro/{mod}.py` |")
    if bases:
        L.append(f"| **Extends** | {', '.join(f'`{b}`' for b in bases)} |")
    L.append(f"| **Methods** | {len(methods)} public |")
    L.append("")
    L.append("Live market-data adapter. Construct it with broker headers/params, register "
             "callbacks via `start_websocket(...)`, then subscribe. Ticks are normalized to the "
             "[TickData contract](#/pro-contracts).")
    L.append("")
    L.append("```python")
    L.append(f"from fenixpro import {cls_name}, FeedType")
    L.append(f"broker = {cls_name}(headers=headers)")
    L.append("broker.start_websocket(on_ltp=lambda tick: print(tick))")
    L.append('broker.subscribe("256265", FeedType.LTP)')
    L.append("```")
    L.append("")
    if sub:
        L.append("## Subscription methods")
        L.append("")
        L.append("| Method | Purpose |")
        L.append("|--------|---------|")
        for name, sig, fl in sub:
            L.append(f"| `{name}()` | {md_escape(fl) or '—'} |")
        L.append("")
    L.append("## Methods")
    L.append("")
    for name, sig, fl in methods:
        L.append(f"### {name}")
        L.append("")
        L.append("```python")
        L.append(f"{cls_name}.{sig}")
        L.append("```")
        L.append("")
        if fl:
            L.append(fl)
            L.append("")
    L.append("---")
    L.append("")
    L.append("_Generated from the adapter source. See [Callback Interface](#/pro-callbacks) and "
             "[Data Contracts](#/pro-contracts) for the shared feed model._")
    L.append("")
    return f"pro-broker-{mod}", "\n".join(L)


def main() -> None:
    nav = {"fenix": [], "pro": []}
    for mod in FENIX_BROKERS:
        pid, md = gen_fenix(mod)
        (CONTENT / f"{pid}.md").write_text(md, encoding="utf-8")
        nav["fenix"].append({"id": pid, "title": DISPLAY.get(mod, mod)})
    for mod in PRO_BROKERS:
        pid, md = gen_pro(mod)
        (CONTENT / f"{pid}.md").write_text(md, encoding="utf-8")
        nav["pro"].append({"id": pid, "title": DISPLAY.get(mod, mod)})
    (HERE / "_nav_brokers.json").write_text(json.dumps(nav, indent=2), encoding="utf-8")
    print(f"fenix broker pages: {len(nav['fenix'])}")
    print(f"fenixpro adapter pages: {len(nav['pro'])}")
    print("nav written to tools/_nav_brokers.json")


if __name__ == "__main__":
    main()
