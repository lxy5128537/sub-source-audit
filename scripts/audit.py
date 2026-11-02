#!/usr/bin/env python3
"""单源审计：mihomo 测活（delay）→ 真连接测试（经固定代理的独立入口）→ 输出 JSON。

稳健性设计：mihomo 只要有一个 proxy 字段非法就整份配置拒绝加载，所以节点按块启动
（默认 30 个一块），某块起不来就二分定位，把零星坏节点剔除而保住整批。

用法：
  python audit.py --source-url <订阅地址> --mihomo ./mihomo --out out/001.json \
      [--limit 120] [--chunk 30] [--delay-timeout 3000] [--real-timeout 8]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nodes as N  # noqa: E402

DELAY_URL = "http://cp.cloudflare.com/generate_204"
REAL_URL = "https://www.cloudflare.com/cdn-cgi/trace"


def free_port(start: int) -> int:
    p = start
    while p < start + 4000:
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                p += 1
    raise RuntimeError("no free port")


class Instance:
    """一个 mihomo 进程 + 一组入口。"""

    def __init__(self, mihomo: str, chunk: list[dict], port_base: int):
        self.mihomo = mihomo
        self.chunk = chunk
        self.dir = tempfile.mkdtemp(prefix="audit-")
        self.ports = [free_port(port_base + i * 7) for i in range(len(chunk))]
        self.ctl = free_port(port_base + 2000)
        self.proc: subprocess.Popen | None = None
        self.err = ""
        self.log_path = os.path.join(self.dir, "mihomo.log")

    def start(self, timeout=25) -> bool:
        listeners = [{"name": f"pin{i}", "type": "mixed", "port": port, "proxy": p["name"]}
                     for i, (p, port) in enumerate(zip(self.chunk, self.ports))]
        proxies = [{k: v for k, v in p.items() if not k.startswith("_")} for p in self.chunk]
        cfg = {
            "mixed-port": free_port(self.ctl + 3),
            "external-controller": f"127.0.0.1:{self.ctl}",
            "log-level": "warning",
            "mode": "rule",
            "udp": False,
            "proxies": proxies,
            "listeners": listeners,
        }
        cfg_path = os.path.join(self.dir, "config.json")
        json.dump(cfg, open(cfg_path, "w"), ensure_ascii=False)  # JSON 是合法 YAML
        log = open(self.log_path, "wb")
        self.proc = subprocess.Popen([self.mihomo, "-d", self.dir, "-f", cfg_path],
                                     stdout=log, stderr=log)
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.proc.poll() is not None:
                break
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.ctl}/version", timeout=2) as r:
                    r.read()
                return True
            except Exception:
                time.sleep(0.3)
        self.stop()
        self.err = self._logtail()
        return False

    def _logtail(self) -> str:
        try:
            txt = open(self.log_path, "rb").read().decode("utf-8", "ignore")
        except Exception:
            return ""
        lines = [l for l in txt.splitlines() if re.search(r"(?i)error|fatal|reject|invalid|unsupport", l)]
        return " | ".join(lines[-3:])[:300]

    def delay(self, name: str, timeout_ms: int) -> int | None:
        q = urllib.parse.urlencode({"url": DELAY_URL, "timeout": timeout_ms})
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{self.ctl}/proxies/{urllib.parse.quote(name)}/delay?{q}",
                    timeout=int(timeout_ms / 1000) + 8) as r:
                d = json.loads(r.read())
            v = d.get("delay")
            return int(v) if v else None
        except Exception:
            return None

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.SIGTERM)
                self.proc.wait(timeout=8)
            except Exception:
                self.proc.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


def real_test(port: int, timeout_s: int) -> dict:
    proxy = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    t0 = time.time()
    try:
        req = urllib.request.Request(REAL_URL, headers={"User-Agent": N.UA["User-Agent"]})
        with opener.open(req, timeout=timeout_s) as r:
            body = r.read(4096).decode("utf-8", "ignore")
        ms = int((time.time() - t0) * 1000)
        m = re.search(r"(?m)^ip=(.+)$", body)
        if not m:
            return {"ok": False, "ms": ms, "error": "no-trace"}
        loc = re.search(r"(?m)^loc=(.+)$", body)
        warp = re.search(r"(?m)^warp=(.+)$", body)
        return {"ok": True, "ms": ms, "egress_ip": m.group(1).strip(),
                "country": loc.group(1).strip() if loc else "",
                "warp": warp.group(1).strip() if warp else ""}
    except urllib.error.HTTPError as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000), "error": f"http-{e.code}"}
    except Exception as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000), "error": type(e).__name__}


def audit_chunk(mihomo: str, chunk: list[dict], port_base: int, args) -> list[dict]:
    """返回每个节点的结果；配置被拒时二分定位坏节点。"""
    if not chunk:
        return []
    inst = Instance(mihomo, chunk, port_base)
    if not inst.start():
        err = inst.err
        inst.stop()
        if len(chunk) == 1:
            p = chunk[0]
            return [{"name": p["name"], "type": p["type"], "server": p.get("server"),
                     "port": p.get("port"), "delay_ms": None, "real_ok": False,
                     "real_ms": None, "egress_ip": "", "country": "",
                     "error": f"config-rejected: {err}", "uri": p.get("_uri", "")}]
        mid = len(chunk) // 2
        return (audit_chunk(mihomo, chunk[:mid], port_base, args)
                + audit_chunk(mihomo, chunk[mid:], port_base + 1500, args))

    out = [None] * len(chunk)
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        delays = list(ex.map(lambda i: inst.delay(chunk[i]["name"], args.delay_timeout),
                             range(len(chunk))))
    alive = [(i, port) for i, port in enumerate(inst.ports) if delays[i]]
    reals = {}
    if alive:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            got = list(ex.map(lambda t: real_test(t[1], args.real_timeout), alive))
        reals = {i: r for (i, _), r in zip(alive, got)}
    inst.stop()

    for i, p in enumerate(chunk):
        r = reals.get(i, {})
        out[i] = {"name": p["name"], "type": p["type"], "server": p.get("server"),
                  "port": p.get("port"), "delay_ms": delays[i],
                  "real_ok": bool(r.get("ok")), "real_ms": r.get("ms"),
                  "egress_ip": r.get("egress_ip", ""), "country": r.get("country", ""),
                  "error": r.get("error", ""), "uri": p.get("_uri", "")}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-url", required=True)
    ap.add_argument("--mihomo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=120)
    ap.add_argument("--chunk", type=int, default=30)
    ap.add_argument("--delay-timeout", type=int, default=3000)
    ap.add_argument("--real-timeout", type=int, default=8)
    ap.add_argument("--workers", type=int, default=24)
    args = ap.parse_args()

    result = {"source": args.source_url,
              "tested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "sampled": 0, "delay_ok": 0, "real_ok": 0, "usable_rate": 0.0, "nodes": []}
    try:
        picked, stats = N.load_source(args.source_url, args.limit)
    except Exception as e:
        result["error"] = f"fetch/parse: {type(e).__name__}: {e}"
        json.dump(result, open(args.out, "w"), ensure_ascii=False, indent=1)
        print(json.dumps({k: v for k, v in result.items() if k != "nodes"}, ensure_ascii=False))
        return 0

    result.update(stats)
    result["sampled"] = len(picked)
    if not picked:
        result["error"] = "no parseable nodes"
        json.dump(result, open(args.out, "w"), ensure_ascii=False, indent=1)
        print(json.dumps({k: v for k, v in result.items() if k != "nodes"}, ensure_ascii=False))
        return 0

    base = random.randint(24000, 40000)
    rows: list[dict] = []
    for i in range(0, len(picked), args.chunk):
        part = picked[i:i + args.chunk]
        rows += audit_chunk(args.mihomo, part, base + (i % 900) * 2, args)

    result["nodes"] = rows
    result["delay_ok"] = sum(1 for r in rows if r["delay_ms"])
    result["real_ok"] = sum(1 for r in rows if r["real_ok"])
    result["usable_rate"] = round(result["real_ok"] / max(1, result["sampled"]), 4)
    rejected = sum(1 for r in rows if str(r.get("error", "")).startswith("config-rejected"))
    if rejected:
        result["config_rejected"] = rejected
        sample = next(r["error"] for r in rows if str(r.get("error", "")).startswith("config-rejected"))
        result["config_error_sample"] = sample[:200]
    json.dump(result, open(args.out, "w"), ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in result.items() if k != "nodes"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
