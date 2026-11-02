#!/usr/bin/env python3
"""单源审计：mihomo 测活（delay）→ 真连接测试（经固定代理的独立入口）→ 输出 JSON。

用法：
  python audit.py --source-url <订阅地址> --mihomo /usr/local/bin/mihomo \
      --out result.json [--limit 120] [--delay-timeout 3000] [--real-timeout 8]
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

CONTROLLER = "127.0.0.1:19091"
PORT_BASE = 22000
TEST_URL_DELAY = "http://cp.cloudflare.com/generate_204"
TEST_URL_REAL = "https://www.cloudflare.com/cdn-cgi/trace"


def free_port(start: int, count: int) -> list[int]:
    """从 start 起找可用的连续端口区（够 count 个即可，允许不连续）。"""
    ports, p = [], start
    while len(ports) < count and p < start + count * 4 + 500:
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                ports.append(p)
            except OSError:
                pass
        p += 1
    return ports


def api(path: str, method="GET", body=None, timeout=10):
    url = f"http://{CONTROLLER}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    return json.loads(raw) if raw else {}


def wait_ready(proc: subprocess.Popen, deadline=45) -> bool:
    t0 = time.time()
    while time.time() - t0 < deadline:
        if proc.poll() is not None:
            return False
        try:
            api("/version", timeout=3)
            return True
        except Exception:
            time.sleep(0.5)
    return False


def delay_test(name: str, url: str, timeout_ms: int) -> int | None:
    q = urllib.parse.urlencode({"url": url, "timeout": timeout_ms})
    try:
        d = api(f"/proxies/{urllib.parse.quote(name)}/delay?{q}", timeout=timeout_ms / 1000 + 8)
        v = d.get("delay")
        return int(v) if v else None
    except Exception:
        return None


def real_test(port: int, timeout_s: int) -> dict:
    """经该节点专属入口做一次真实 HTTPS 请求，取回真实出口 IP。"""
    proxy = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    t0 = time.time()
    try:
        req = urllib.request.Request(TEST_URL_REAL, headers={"User-Agent": N.UA["User-Agent"]})
        with opener.open(req, timeout=timeout_s) as r:
            body = r.read(4096).decode("utf-8", "ignore")
        ms = int((time.time() - t0) * 1000)
        ip = re.search(r"(?m)^ip=(.+)$", body)
        loc = re.search(r"(?m)^loc=(.+)$", body)
        warp = re.search(r"(?m)^warp=(.+)$", body)
        if not ip:
            return {"ok": False, "ms": ms, "error": "no-trace-body"}
        return {"ok": True, "ms": ms, "egress_ip": ip.group(1).strip(),
                "country": (loc.group(1).strip() if loc else ""),
                "warp": (warp.group(1).strip() if warp else "")}
    except urllib.error.HTTPError as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000), "error": f"http-{e.code}"}
    except Exception as e:
        return {"ok": False, "ms": int((time.time() - t0) * 1000), "error": type(e).__name__}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-url", required=True)
    ap.add_argument("--mihomo", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=120, help="每源最多抽多少个节点来测")
    ap.add_argument("--delay-timeout", type=int, default=3000)
    ap.add_argument("--real-timeout", type=int, default=8)
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--keep-config", action="store_true")
    args = ap.parse_args()

    result = {"source": args.source_url, "tested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "sampled": 0, "delay_ok": 0, "real_ok": 0, "usable_rate": 0.0, "nodes": []}
    try:
        picked, stats = N.load_source(args.source_url, args.limit)
    except Exception as e:
        result["error"] = f"fetch/parse failed: {type(e).__name__}: {e}"
        json.dump(result, open(args.out, "w"), ensure_ascii=False, indent=1)
        print(json.dumps(result, ensure_ascii=False))
        return 0

    result.update(stats)
    if not picked:
        result["error"] = "no parseable nodes"
        json.dump(result, open(args.out, "w"), ensure_ascii=False, indent=1)
        print(json.dumps({k: v for k, v in result.items() if k != "nodes"}, ensure_ascii=False))
        return 0

    workdir = tempfile.mkdtemp(prefix="audit-")
    ports = free_port(PORT_BASE + random.randint(0, 3000), len(picked))
    if len(ports) < len(picked):
        picked, ports = picked[:len(ports)], ports
        result["sampled"] = len(picked)

    listeners = [{"name": f"pin{i}", "type": "mixed", "port": port, "proxy": p["name"]}
                 for i, (p, port) in enumerate(zip(picked, ports))]
    proxies = [{k: v for k, v in p.items() if not k.startswith("_")} for p in picked]
    cfg = {
        "mixed-port": 0,
        "external-controller": CONTROLLER,
        "log-level": "warning",
        "udp": False,
        "proxies": proxies,
        "listeners": listeners,
    }
    cfg_path = os.path.join(workdir, "config.yaml")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)  # JSON 是合法的 YAML 子集，省掉 yaml 依赖

    proc = subprocess.Popen([args.mihomo, "-d", workdir, "-f", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready(proc):
            result["error"] = "mihomo failed to start (config rejected?)"
        else:
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                delays = list(ex.map(lambda p: delay_test(p["name"], TEST_URL_DELAY, args.delay_timeout), picked))
            alive = [(p, port, d) for p, port, d in zip(picked, ports, delays) if d]
            result["delay_ok"] = len(alive)
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                reals = list(ex.map(lambda t: real_test(t[1], args.real_timeout), alive))
            ok = 0
            for (p, port, d), r in zip(alive, reals):
                if r.get("ok"):
                    ok += 1
                result["nodes"].append({
                    "name": p["name"], "type": p["type"], "server": p.get("server"),
                    "port": p.get("port"), "delay_ms": d,
                    "real_ok": bool(r.get("ok")), "real_ms": r.get("ms"),
                    "egress_ip": r.get("egress_ip", ""), "country": r.get("country", ""),
                    "error": r.get("error", ""),
                    "uri": p.get("_uri", ""),
                })
            result["real_ok"] = ok
            result["usable_rate"] = round(ok / max(1, result["sampled"]), 4)
    finally:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=8)
        except Exception:
            proc.kill()
        if not args.keep_config:
            shutil.rmtree(workdir, ignore_errors=True)

    json.dump(result, open(args.out, "w"), ensure_ascii=False, indent=1)
    print(json.dumps({k: v for k, v in result.items() if k != "nodes"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
